@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cl /nologo /LD /EHsc /O2 /std:c++17 clrjit_hook.cpp /Fe:clrjit_dump.dll
echo BUILD_RC=%ERRORLEVEL%