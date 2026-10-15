// clrjit_hook.cpp v4 — universal NecroBit JIT dump + US heap capture
// ICorJitCompiler::compileMethod VMT hook. Captures the CIL body BEFORE
// the original call (NecroBit wipes it after), plus resolves ldstr
// tokens via the ICorJitInfo vtable (getUserString literal content) so
// merge-time can rebind runtime tokens to disk-module tokens.
// Proven: 7.5.9.1 T4Y (238 bodies), T-MAX Fx4.8 x64 (251 bodies).
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

struct CORINFO_METHOD_INFO {
    void* ftn;
    void* scope;
    std::uint8_t* ILCode;
    unsigned ILCodeSize;
    unsigned maxStack;
    unsigned EHcount;
    unsigned options;
    unsigned regionKind;
    void* args;
    void* locals;
};

// CORINFO_EH_CLAUSE — corinfo.h layout, 28 bytes, identical on Framework
// and CoreCLR. Clause tables are NOT captured via a vtable hook: the section
// sits in memory right after the IL bytes and the snapshot grabs it whole
// (header dword 4 = extra length past the IL). Clause field order matches
// this struct: Flags(0=catch 1=filter 2=finally 3=fault), TryOffset,
// TryLen, HandlerOffset, HandlerLen, ClassToken, FilterOffset.
typedef int(__stdcall* CompileFn)(void*, void*, CORINFO_METHOD_INFO*, unsigned, std::uint8_t**, std::uint32_t*);
typedef void* (__stdcall* GetJitFn)();

static GetJitFn g_getJit = nullptr;
static void* g_origCompile = nullptr;
static std::mutex g_mtx;
static std::map<int, std::set<std::uint64_t>> g_seen;   // per-scope dedup
static std::set<std::uint32_t> g_ldstrSeen;
static char g_outDir[MAX_PATH] = "";
static std::vector<std::string> g_lines;
static std::mutex g_lines_mtx;
static std::uint32_t g_tokCounter = 0;

// Scope grouping (NB_SCOPE_DIRS=1): every distinct info->scope (one CLR
// module each) gets its own subdirectory, so ONLY the target module's
// bodies land in the dir the merge consumes. Foreign JIT (mscorlib, the
// companion itself) is physically separated — its MethodDef rids would
// otherwise collide with the target's. Grouping is pure pointer bookkeeping:
// no vtable probing, nothing foreign is ever called.
typedef const char* (__stdcall* ModNameFn)(void* scope);
static bool g_scopeDirs = false;
static std::mutex g_scope_mtx;
static std::map<void*, int> g_scopeIdx;
static int g_scopeCount = 0;

static int ScopeIndexFor(void* scope) {
    std::lock_guard<std::mutex> lk(g_scope_mtx);
    auto it = g_scopeIdx.find(scope);
    if (it != g_scopeIdx.end()) return it->second;
    int idx = g_scopeCount++;
    g_scopeIdx[scope] = idx;
    char mp[MAX_PATH]; char msg[96];
    std::snprintf(msg, sizeof(msg), "scope%d = %p", idx, scope);
    std::snprintf(mp, sizeof(mp), "%s\\scopes.log", g_outDir);
    FILE* f = nullptr;
    if (fopen_s(&f, mp, "ab") == 0) { fputs(msg, f); fputc('\n', f); fclose(f); }
    return idx;
}

// getMethodDefFromMethod vtable index: Framework 4.x x86 offset-read is
// proven; x64 uses vtable (NB_TOKENMODE=vt) or chunk-derived synthetic.
static std::uint32_t resolveRealToken(void* comp, void* ftn) {
    if (!ftn) return 0;
    std::uint32_t tok = 0;
    const char* mode = getenv("NB_TOKENMODE");
#ifdef _WIN64
    bool useVt = (mode && strcmp(mode, "vt") == 0);
#else
    bool useVt = (mode && strcmp(mode, "vt") == 0);
#endif
    if (useVt && comp) {
        int slot = 112;
        const char* vts = getenv("NB_VTSLOT");
        if (vts) slot = atoi(vts);
        __try {
            void** vt = *(void***)comp;
            std::uint32_t(__stdcall * pGet)(void*) =
                (std::uint32_t(__stdcall*)(void*))vt[slot];
            if (pGet) {
                std::uint32_t r = pGet(ftn);
                if (r > 0 && r < 0x00FFFFFF) tok = 0x06000000 | r;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { tok = 0; }
        if (tok) return tok;
    }
#ifndef _WIN64
    __try {
        std::uint32_t rid = *(std::uint32_t*)((std::uint8_t*)ftn + 0x0C) & 0x00FFFFFF;
        if (rid > 0 && rid < 0x00FFFFFF) tok = 0x06000000 | rid;
    } __except (EXCEPTION_EXECUTE_HANDLER) { tok = 0; }
#else
    __try {
        std::uint32_t rid = *(std::uint32_t*)((std::uint8_t*)ftn + 0x14) & 0x00FFFFFF;
        if (rid > 0 && rid < 0x00FFFFFF) tok = 0x06000000 | rid;
    } __except (EXCEPTION_EXECUTE_HANDLER) { tok = 0; }
#endif
    return tok;
}

// getStringLiteral vtable index: ICorStaticInfo::getStringLiteral comes
// AFTER getMethodDefFromMethod family in corinfo.h order. Framework 4.x:
// index varies — env-driven NB_STRSLOT (default 118, CoreCLR .NET 8
// count). Returns length via out-param; literal bytes UTF-16.
// SEH-guarded: wrong slot = silent skip (never crashes the target).
static bool dumpLdstrLiterals(void* comp, const std::uint8_t* il, unsigned ilSize) {
    if (!comp || !il || !ilSize) return false;
    // scan ldstr (0x72) opcodes in the body
    std::vector<std::uint32_t> toks;
    unsigned i = 0;
    while (i + 4 < ilSize) {
        if (il[i] == 0x72) {
            std::uint32_t t = *(std::uint32_t*)(il + i + 1);
            if ((t & 0xFF000000) == 0x70000000) toks.push_back(t & 0x00FFFFFF);
            i += 5;
        } else if (il[i] == 0xFE) i += 2;
        else if (il[i] >= 0x28 && il[i] <= 0x2F) i += 5; // call family? keep simple
        else i += 1;
    }
    if (toks.empty()) return false;
    const char* ss = getenv("NB_STRSLOT");
    int slot = ss ? atoi(ss) : 118;
    void** vt = *(void***)comp;
    // typedef: HRESULT getStringLiteral(void* scope, mdToken token,
    //          const wchar_t** literal, int* pLen) — CoreCLR ABI-ish.
    // Framework ABI: int(__stdcall*)(void*, unsigned, wchar_t const**, int*)
    typedef int(__stdcall * StrFn)(void*, std::uint32_t, const wchar_t**, int*);
    StrFn pStr = (StrFn)vt[slot];
    if (!pStr) return false;
    bool any = false;
    for (std::uint32_t off : toks) {
        if (!g_ldstrSeen.insert(off).second) continue;
        __try {
            const wchar_t* lit = nullptr; int len = 0;
            if (pStr(nullptr, 0x70000000 | off, &lit, &len) >= 0 && lit && len > 0 && len < 1024) {
                char path[MAX_PATH];
                std::snprintf(path, sizeof(path), "%s\\us_%06X.txt", g_outDir, off);
                FILE* f = nullptr;
                if (fopen_s(&f, path, "wb") == 0 && f) {
                    fwrite(lit, 2, len, f);
                    fclose(f);
                    any = true;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    return any;
}

static bool installHook();



static void markerLine(const char* msg);

static int __stdcall HookedCompileMethod(
    void* self, void* comp, CORINFO_METHOD_INFO* info, unsigned flags,
    std::uint8_t** nativeEntry, std::uint32_t* nativeSize)
{
    {
        static volatile long seen = 0;
        if (_InterlockedIncrement(&seen) == 1) markerLine("compile-seen #1");
    }
    // ENTRY SNAPSHOT: NecroBit fills the IL buffer right before entry and
    // wipes it after — copy on the FIRST line, before the original call.
    std::vector<std::uint8_t> pre;
    std::uint32_t preIl = 0, preMaxStack = 0, preEh = 0, preExtra = 0;
    void* preFtn = nullptr;
    if (info && info->ILCode && info->ILCodeSize > 0 && info->ILCodeSize < (4u << 20)) {
        preIl = info->ILCodeSize;
        preMaxStack = info->maxStack;
        preEh = info->EHcount;
        preFtn = info->ftn;
        pre.assign(info->ILCode, info->ILCode + info->ILCodeSize);
        if (info->EHcount > 0) {
            // The EH clause section sits in memory right after the IL bytes
            // (4-aligned) — getEHinfo reads it from exactly there. Snapshot
            // the tail too and nbilmerge rebuilds handlers from it: no
            // vtable slot, no per-runtime probing. SEH-guarded: ILCode may
            // end at a page boundary.
            __try {
                // The section is 4-aligned FROM THE BODY START (header
                // included), so its offset relative to ILCode depends on the
                // header size we don't know here (tiny 1 / fat 12). Probe the
                // candidate offsets and take the one carrying an EH-table
                // section (kind 0x66; 0x40 flag = fat clauses).
                const std::uint32_t cand[3] = {
                    (preIl + 3u) & ~3u,                       // tiny-header alignment
                    ((preIl + 12u + 3u) & ~3u) - 12u,         // fat-header alignment
                    ((preIl + 8u + 3u) & ~3u) - 8u,           // defensive middle
                };
                for (int ci = 0; ci < 3 && preExtra == 0; ci++) {
                    std::uint32_t sec_off = cand[ci];
                    if (sec_off < preIl) continue;
                    std::uint32_t kind = *(std::uint32_t*)(info->ILCode + sec_off);
                    if ((kind & 0xFF) != 0x66) continue;
                    std::uint32_t dsize = *(std::uint32_t*)(info->ILCode + sec_off + 4);
                    if (dsize == 0 || dsize > 65536) continue;
                    std::uint32_t total = sec_off + 8 + dsize;
                    if (total <= preIl || total > (4u << 20)) continue;
                    pre.resize(total);
                    memcpy(pre.data() + preIl, info->ILCode + preIl, total - preIl);
                    preExtra = total - preIl;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                if (pre.size() > preIl) pre.resize(preIl);
                preExtra = 0;
            }
        }
        // v4: capture ldstr literal contents — SEH-guarded inside; a wrong
        // vtable slot can still destabilize the JIT under some hosts, so
        // default OFF; NB_STRDUMP=1 enables.
        const char* sd = getenv("NB_STRDUMP");
        if (sd && strcmp(sd, "1") == 0)
            dumpLdstrLiterals(comp, pre.data(), preIl);
    }

    int r = ((CompileFn)g_origCompile)(self, comp, info, flags, nativeEntry, nativeSize);

    if (!pre.empty()) {
        std::uint32_t real = resolveRealToken(comp, preFtn);
        std::uint32_t tok = real ? real : ++g_tokCounter;
        int scopeIdx = g_scopeDirs ? ScopeIndexFor(info->scope) : -1;
        char dir[MAX_PATH];
        if (scopeIdx >= 0) {
            std::snprintf(dir, sizeof(dir), "%s\\scope%d", g_outDir, scopeIdx);
            CreateDirectoryA(dir, NULL);   // NO_ERROR / ALREADY_EXISTS both fine
        } else {
            strcpy_s(dir, sizeof(dir), g_outDir);
        }
        std::lock_guard<std::mutex> lk(g_mtx);
        std::uint64_t key = (std::uint64_t)tok << 32 | preIl;
        if (g_seen[scopeIdx].insert(key).second) {
            char path[MAX_PATH];
            std::snprintf(path, sizeof(path), "%s\\m_%08X.bin", dir, tok);
            FILE* f = nullptr;
            if (fopen_s(&f, path, "wb") == 0 && f) {
                std::uint32_t hdr[5] = { tok, preIl, preMaxStack, preEh, preExtra };
                fwrite(hdr, 1, sizeof(hdr), f);
                fwrite(pre.data(), 1, pre.size(), f);
                fclose(f);
                std::lock_guard<std::mutex> lk2(g_lines_mtx);
                char line[180];
                std::snprintf(line, sizeof(line), "scope=%d token=0x%08X il=%u maxStack=%u eh=%u extra=%u PRE",
                               scopeIdx, tok, preIl, preMaxStack, preEh, preExtra);
                g_lines.push_back(line);
            }
        }
    }
    return r;
}

static void markerLine(const char* msg) {
    char mp[MAX_PATH];
    std::snprintf(mp, sizeof(mp), "%s\\marker.txt", g_outDir);
    FILE* f = nullptr;
    if (fopen_s(&f, mp, "ab") == 0) { fputs(msg, f); fputc('\n', f); fclose(f); }
}

static bool installHook() {
    HMODULE h = GetModuleHandleW(L"clrjit.dll");
    if (!h) h = GetModuleHandleW(L"mscorjit.dll");
    if (!h) {
        // bare-name search misses the Framework JIT: it lives under
        // \Microsoft.NET\Framework[64]\v4.0.30319, outside the DLL search
        // path. Only fall back to the full path inside a FRAMEWORK process —
        // the discriminator is clr.dll (the Framework engine; CoreCLR never
        // loads it). Without the gate a .NET Core process would get the
        // wrong JIT hooked and compile invisibly.
        if (GetModuleHandleW(L"clr.dll")) {
            h = LoadLibraryW(
#ifdef _WIN64
                L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clrjit.dll"
#else
                L"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\clrjit.dll"
#endif
            );
        }
        if (!h) h = LoadLibraryW(L"clrjit.dll");
        if (!h) h = LoadLibraryW(L"mscorjit.dll");
    }
    if (!h) {
        static long attempts = 0;
        if (++attempts == 30) markerLine("install: no JIT library found");
        return false;
    }
    g_getJit = (GetJitFn)GetProcAddress(h, "getJit");
    if (!g_getJit) { markerLine("install: getJit export missing"); return false; }
    void* jit = g_getJit();
    if (!jit) return false;
    void** vt = *(void***)jit;
    DWORD op;
    if (!VirtualProtect(&vt[0], sizeof(void*), PAGE_EXECUTE_READWRITE, &op)) return false;
    g_origCompile = vt[0];
    vt[0] = (void*)&HookedCompileMethod;
    VirtualProtect(&vt[0], sizeof(void*), op, &op);
    {
        char mp[MAX_PATH]; char msg[128];
        std::snprintf(msg, sizeof(msg), "HOOK-OK pid=%lu clrjit=%p orig=%p",
            GetCurrentProcessId(), (void*)h, g_origCompile);
        std::snprintf(mp, sizeof(mp), "%s\\marker.txt", g_outDir);
        FILE* f = nullptr;
        if (fopen_s(&f, mp, "ab") == 0) { fputs(msg, f); fputc('\n', f); fclose(f); }
    }
    return true;
}


static void flushLog() {
    char path[MAX_PATH];
    std::snprintf(path, sizeof(path), "%s\\jitdump.log", g_outDir);
    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") == 0) {
        std::lock_guard<std::mutex> lk(g_lines_mtx);
        for (auto& s : g_lines) { fwrite(s.data(), 1, s.size(), f); fputc('\n', f); }
        fclose(f);
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        if (!GetEnvironmentVariableA("JITDUMP_DIR", g_outDir, sizeof(g_outDir)))
            strcpy_s(g_outDir, ".");
        {
            char sd[8];
            if (GetEnvironmentVariableA("NB_SCOPE_DIRS", sd, sizeof(sd)) &&
                strcmp(sd, "1") == 0)
                g_scopeDirs = true;
        }
        // v5 race fix: x86 Framework targets finish their startup JIT burst
        // before the 100ms deferred loop lands (dotqw proof: HOOK-OK but
        // 0 bodies, GUI alive — every method compiled pre-hook). Try a
        // synchronous install FIRST — this DllMain runs inside the
        // LoadLibraryA APC, which executes during mscoree's alertable
        // startup waits, BEFORE managed Main. Force-load clrjit if needed.
        installHook();
        // then keep the retry loop, but 10ms instead of 100ms.
        CreateThread(0, 0, [](void*) -> DWORD {
            // 1 ms poll: short-lived console targets JIT within their first
            // seconds; a 10 ms poll can lose that race entirely (0 bodies)
            for (int i = 0; i < 60000; i++) {
                if (g_origCompile) break;
                if (installHook()) break;
                Sleep(1);
            }
            return 0;
            }, 0, 0, 0);
        {
            char mp[MAX_PATH]; char msg[96];
            std::snprintf(msg, sizeof(msg), "attach pid=%lu deferred-hook-thread", GetCurrentProcessId());
            std::snprintf(mp, sizeof(mp), "%s\\marker.txt", g_outDir);
            FILE* f = nullptr;
            if (fopen_s(&f, mp, "ab") == 0) { fputs(msg, f); fputc('\n', f); fclose(f); }
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        flushLog();
    }
    return TRUE;
}