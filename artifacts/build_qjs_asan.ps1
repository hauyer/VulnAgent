# Build QuickJS vulnerable revision (CVE-2023-48183, parent of c4cdd61a3ed) 
# with MSVCRT LLVM-MinGW clang + AddressSanitizer, using the in-tree libbf
# (the 2026 tree includes bf_get_uint64 which the old standalone libbf lacks).
# Output: qjs_asan.exe in the quickjs-git root.
$ErrorActionPreference = "Stop"
$mgw = "C:\Users\17875\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.MSVCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-msvcrt-x86_64\bin"
$env:Path = "$mgw;" + $env:Path
Set-Location "D:\课程设计小学期\VulnAgent\third_party\quickjs-git"

$cc = "x86_64-w64-mingw32-clang"
$asan = @("-O0", "-g", "-fsanitize=address", "-fno-omit-frame-pointer")
$common = $asan + @(
  "-D_GNU_SOURCE",
  '-DCONFIG_VERSION=\"2023-12-09\"',
  "-D__USE_MINGW_ANSI_STDIO",
  "-I.", "-Ilibbf"
)

Remove-Item *.o, qjs_asan.exe, qjsc_asan.exe, repl.c -ErrorAction SilentlyContinue

# 1) engine lib objects (incl. in-tree libbf)
& $cc @common -c libbf/libbf.c -o libbf.o
& $cc @common -c quickjs.c -o quickjs.o
& $cc @common -c libregexp.c -o libregexp.o
& $cc @common -c libunicode.c -o libunicode.o
& $cc @common -c cutils.c -o cutils.o
& $cc @common -c quickjs-libc.c -o quickjs-libc.o
if (-not (Test-Path quickjs.o)) { throw "FAIL: quickjs.o" }

# 2) qjsc (compiler) -> generates repl.c from repl.js
& $cc @common -c qjsc.c -o qjsc.o
& $cc @common -o qjsc_asan.exe qjsc.o quickjs.o quickjs-libc.o libregexp.o libunicode.o cutils.o libbf.o -lwinpthread
if (-not (Test-Path qjsc_asan.exe)) { throw "FAIL: qjsc build" }

# 3) repl.c from repl.js via qjsc
& .\qjsc_asan.exe -c -o repl.c -m repl.js
if (-not (Test-Path repl.c)) { throw "FAIL: repl.c generation" }

# 4) remaining objects + link qjs
& $cc @common -c repl.c -o repl.o
& $cc @common -c qjs.c -o qjs.o
& $cc @common -o qjs_asan.exe qjs.o repl.o quickjs.o quickjs-libc.o libregexp.o libunicode.o cutils.o libbf.o -lwinpthread
if (-not (Test-Path qjs_asan.exe)) { throw "FAIL: qjs link" }
Write-Output "BUILD OK: qjs_asan.exe $((Get-Item qjs_asan.exe).Length) bytes"
