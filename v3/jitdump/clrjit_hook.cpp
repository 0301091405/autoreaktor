// clrjit_hook.cpp — NecroBit evrensel JIT dump rota v3
// ICorJitCompiler::compileMethod VMT hook; NecroBit'in JIT
// oncesi cozup sonra sildigi CIL govdesini ILCode pointer'indan
// yakalar. Kanitli: 7.5.9.1 T4Y hedefi, 238 govde / 7060 IL bayt.
// x86, .NET Framework 4.x clrjit.dll ABI.
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
static char g_outDir[MAX_PATH] = "";
static std::vector<std::string> g_lines;
static std::mutex g_lines_mtx;
static std::uint32_t g_tokCounter = 0;
static char g_envBuf[8] = {0};

static void writeDump(std::uint32_t token, const CORINFO_METHOD_INFO* info) {
    std::lock_guard<std::mutex> lk(g_mtx);
    std::uint64_t key = (std::uint64_t)token << 32 | info->ILCodeSize;
    if (!g_seen.insert(key).second) return;
    char path[MAX_PATH];
    std::snprintf(path, sizeof(path), "%s\\m_%08X.bin", g_outDir, token);
    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") == 0 && f) {
        std::uint32_t hdr[5] = { token, info->ILCodeSize, info->maxStack, info->EHcount, info->options };
        fwrite(hdr, 1, sizeof(hdr), f);
        fwrite(info->ILCode, 1, info->ILCodeSize, f);
        fclose(f);
    }
    char line[160];
    std::snprintf(line, sizeof(line), "token=0x%08X il=%u maxStack=%u eh=%u ilptr=%p",
                   token, info->ILCodeSize, info->maxStack, info->EHcount, (void*)info->ILCode);
    std::lock_guard<std::mutex> lk2(g_lines_mtx);
    g_lines.push_back(line);
}

// token cozumu — MethodDesc trick: CORINFO_METHOD_HANDLE aslinda
// MethodDesc*; x86 .NET Framework'te metodun token rid'si offset
// 0x0C'de (m_Token alani). Vtable cagrisi GEREKMEZ, salt okuma —
// SEH korumali. Geçersizse JIT sirasiyla devam.
// token cozumu — iki rota:
// 1) NB_TOKENMODE=vt (default x64): ICorJitInfo::getMethodDefFromMethod
//    vtable cagrisi. x64 vtable slot 0xB0 (8 byte/entry * 22).
//    SEH korumali — yanlis slot AV'yi yutar, sentetige duser.
// 2) NB_TOKENMODE=off (default x86): MethodDesc salt-offset
//    okumasi (x86 +0x0C kanitli dogru; x64'te chunk yapisindan
//    dolayi offset okumasi guvenilmez).
static std::uint32_t resolveRealToken(void* comp, void* ftn) {
    if (!ftn) return 0;
    std::uint32_t tok = 0;
    // ICorJitInfo::getMethodDefFromMethod vtable index = 105
    // (kanit: xoofx/ManagedJit — .NET Framework 4.7.2 / CoreCLR
    // corinfo.h sirasi, IntPtr.Size * 105). x86'da offset 420,
    // x64'te 840. x86 +0x0C offset okumasi da zaten dogruydu;
    // vtable rotasi x64'te guvenilir olan TEK yol.
    const char* mode = getenv("NB_TOKENMODE");
#ifdef _WIN64
    // x64: slot 105 Framework 4.x clrjit'te dogrulanMADI —
    // t1 hedefinde 0xC0000005 cokusu yaratti. DEFAULT KAPALI;
    // NB_TOKENMODE=vt ile deneysel acilir.
    bool useVt = (mode && strcmp(mode, "vt") == 0);
#else
    // x86: offset okumasi (ftn+0x0C) kanitli; vtable opsiyonel
    bool useVt = (mode && strcmp(mode, "vt") == 0);
#endif
    if (useVt && comp) {
        // slot: NB_VTSLOT (default 112 — coreclr .NET 8 corinfo.h
        // sayimi: ICorStaticInfo icinde getMethodDefFromMethod
        // oncesi 112 pure-virtual). Framework 4.x icin dogru
        // slot BILINMIYOR (105 crash kanitli) — ENV ile ver.
        int slot = 112;
        const char* vts = getenv("NB_VTSLOT");
        if (vts) slot = atoi(vts);
        __try {
            void** vt = *(void***)comp;
            std::uint32_t (__stdcall *pGet)(void*) =
                (std::uint32_t (__stdcall*)(void*))vt[slot];
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

static int __stdcall HookedCompileMethod(
    void* self, void* comp, CORINFO_METHOD_INFO* info, unsigned flags,
    std::uint8_t** nativeEntry, std::uint32_t* nativeSize)
{
    // GIRIS SNAPSHOT: NecroBit, compileMethod'a girmeden hemen once
    // ILCode buffer'ini doldurur ve JIT bitiminde silip gercekle
    // temizler (kaba wipe de olabilir). Cikista okunan buffer bos/
    // bozuk olabilir — 0-instr govde bunun kaniti. Bu yuzden ILK
    // SATIRDA, original cagrilmadan kopya al.
    std::vector<std::uint8_t> pre;
    std::uint32_t preIl = 0, preMaxStack = 0, preEh = 0;
    void* preFtn = nullptr;
    if (info && info->ILCode && info->ILCodeSize > 0 && info->ILCodeSize < (4u << 20)) {
        preIl = info->ILCodeSize;
        preMaxStack = info->maxStack;
        preEh = info->EHcount;
        preFtn = info->ftn;
        pre.assign(info->ILCode, info->ILCode + info->ILCodeSize);
    }
    int r = ((CompileFn)g_origCompile)(self, comp, info, flags, nativeEntry, nativeSize);
    if (!pre.empty()) {
        std::uint32_t real = resolveRealToken(comp, preFtn);
        std::uint32_t tok = real ? real : ++g_tokCounter;
        // gecici CORINFO kopyasi: writeDump info->ILCode okur —
        // pre-dumped buffer'i geri yazmak yerine dogrudan yaz:
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
    if (fopen_s(&f, path, "wb") == 0 && f) {
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
        // clrjit.dll henuz yuklenmemis olabilir (APC erken injection):
        // kurulumu arka thread'e birak (60s boyunca dene).
        CreateThread(0, 0, [](void*) -> DWORD {
            for (int i = 0; i < 600; i++) {
                if (installHook()) break;
                Sleep(100);
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
    } else if (reason == DLL_PROCESS_DETACH) {
        flushLog();
    }
    return TRUE;
}