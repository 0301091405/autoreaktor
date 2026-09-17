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

static int __stdcall HookedCompileMethod(
    void* self, void* comp, CORINFO_METHOD_INFO* info, unsigned flags,
    std::uint8_t** nativeEntry, std::uint32_t* nativeSize)
{
    // NecroBit hook'u (zincirlendiyse) veya gercek JIT calisir;
    // ILCode bu noktada NecroBit tarafindan COZULMUS halde.
    int r = ((CompileFn)g_origCompile)(self, comp, info, flags, nativeEntry, nativeSize);
    if (info && info->ILCode && info->ILCodeSize > 0 && info->ILCodeSize < (4u << 20)) {
        std::uint32_t tok = ++g_tokCounter; // JIT sirasi; token eslemesi
        // write-back katmaninda IL-pattern matching ile yapilir (nbilmerge)
        writeDump(tok, info);
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