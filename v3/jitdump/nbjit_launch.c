// nbjit_launch.c — suspended CreateProcess + APC injection launcher.
// Kullanim: nbjit_launch.exe "target.exe [args]"
// Env: NB_DLL (DLL to inject), JITDUMP_DIR (dump output dir)
// The launcher's bitness must MATCH the target (the kernel32
// LoadLibraryA address is in the target's bitness; x86 processes
// need the x86 build).
#include <Windows.h>
#include <stdio.h>

int main(int argc, char** argv) {
    char dllPath[MAX_PATH];
    if (!GetEnvironmentVariableA("NB_DLL", dllPath, MAX_PATH)) {
        printf("NB_DLL not set\n"); return 1;
    }
    if (argc < 2) { printf("usage: nbjit_launch \"target.exe [args]\"\n"); return 1; }

    STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    char cmd[2048];
    strncpy_s(cmd, sizeof(cmd), argv[1], _TRUNCATE);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("CreateProcess fail %lu\n", GetLastError()); return 1;
    }
    // APC injection: target clrjit.dll yuklemeden DLL otursun.
    SIZE_T n = strlen(dllPath) + 1;
    void* rem = VirtualAllocEx(pi.hProcess, NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { TerminateProcess(pi.hProcess, 1); return 1; }
    WriteProcessMemory(pi.hProcess, rem, dllPath, n, NULL);
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC ll = GetProcAddress(k32, "LoadLibraryA");
    QueueUserAPC((PAPCFUNC)ll, pi.hThread, (ULONG_PTR)rem);
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, 60000);
    DWORD rc = 0; GetExitCodeProcess(pi.hProcess, &rc);
    printf("target rc=%lu\n", rc);
    return 0;
}