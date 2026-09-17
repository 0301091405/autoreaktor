// clrjit_hook.cpp v4 — universal NecroBit JIT dump + US heap capture
// ICorJitCompiler::compileMethod VMT hook. Captures the CIL body BEFORE
// the original call (NecroBit wipes it after), plus resolves ldstr
// tokens via the ICorJitInfo vtable (getUserString literal content) so
// merge-time can rebind runtime tokens to disk-module tokens.
// Proven: 7.5.9.1 T4Y (238 bodies), T-MAX Fx4.8 x64 (251 bodies).
#include <Windows.h>
#include <cstdint>
#include <cstdio>
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

typedef int(__stdcall* CompileFn)(void*, void*, CORINFO_METHOD_INFO*, unsigned, std::uint8_t**, std::uint32_t*);
typedef void* (__stdcall* GetJitFn)();

static GetJitFn g_getJit = nullptr;
static void* g_origCompile = nullptr;
static std::mutex g_mtx;
static std::set<std::uint64_t> g_seen;
static std::set<std::uint32_t> g_ldstrSeen;
static char g_outDir[MAX_PATH] = "";
static std::vector<std::string> g_lines;
static std::mutex g_lines_mtx;
static std::uint32_t g_tokCounter = 0;

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

static int __stdcall HookedCompileMethod(
    void* self, void* comp, CORINFO_METHOD_INFO* info, unsigned flags,
    std::uint8_t** nativeEntry, std::uint32_t* nativeSize)
{
    // ENTRY SNAPSHOT: NecroBit fills the IL buffer right before entry and
    // wipes it after — copy on the FIRST line, before the original call.
    std::vector<std::uint8_t> pre;
    std::uint32_t preIl = 0, preMaxStack = 0, preEh = 0;
    void* preFtn = nullptr;
    if (info && info->ILCode && info->ILCodeSize > 0 && info->ILCodeSize < (4u << 20)) {
        preIl = info->ILCodeSize;
        preMaxStack = info->maxStack;
        preEh = info->EHcount;
        preFtn = info->ftn;
        pre.assign(info->ILCode, info->ILCode + info->ILCodeSize);
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
        std::lock_guard<std::mutex> lk(g_mtx);
        std::uint64_t key = (std::uint64_t)tok << 32 | preIl;
        if (g_seen.insert(key).second) {
            char path[MAX_PATH];
            std::snprintf(path, sizeof(path), "%s\\m_%08X.bin", g_outDir, tok);
            FILE* f = nullptr;
            if (fopen_s(&f, path, "wb") == 0 && f) {
                std::uint32_t hdr[5] = { tok, preIl, preMaxStack, preEh, 0 };
                fwrite(hdr, 1, sizeof(hdr), f);
                fwrite(pre.data(), 1, preIl, f);
                fclose(f);
                std::lock_guard<std::mutex> lk2(g_lines_mtx);
                char line[160];
                std::snprintf(line, sizeof(line), "token=0x%08X il=%u maxStack=%u eh=%u PRE",
                               tok, preIl, preMaxStack, preEh);
                g_lines.push_back(line);
            }
        }
    }
    return r;
}

static bool installHook() {
    HMODULE h = GetModuleHandleW(L"clrjit.dll");
    if (!h) h = GetModuleHandleW(L"mscorjit.dll");
    if (!h) h = LoadLibraryW(L"clrjit.dll");
    if (!h) return false;
    g_getJit = (GetJitFn)GetProcAddress(h, "getJit");
    if (!g_getJit) return false;
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
        // v5 race fix: x86 Framework targets finish their startup JIT burst
        // before the 100ms deferred loop lands (dotqw proof: HOOK-OK but
        // 0 bodies, GUI alive — every method compiled pre-hook). Try a
        // synchronous install FIRST — this DllMain runs inside the
        // LoadLibraryA APC, which executes during mscoree's alertable
        // startup waits, BEFORE managed Main. Force-load clrjit if needed.
        installHook();
        // then keep the retry loop, but 10ms instead of 100ms.
        CreateThread(0, 0, [](void*) -> DWORD {
            for (int i = 0; i < 6000; i++) {
                if (g_origCompile) break;
                if (installHook()) break;
                Sleep(10);
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