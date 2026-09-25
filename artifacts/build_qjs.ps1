$mgw = "C:\Users\17875\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.MSVCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-msvcrt-x86_64\bin"
$env:Path = "$mgw;" + $env:Path
$root = (Get-Location).Path
Set-Location "$root\third_party\quickjs-git"

$cc = "x86_64-w64-mingw32-clang"
$common = @(
  "-g", "-O2",
  "-D_GNU_SOURCE",
  '-DCONFIG_VERSION=\"2023-12-09\"',
  "-D__USE_MINGW_ANSI_STDIO",
  "-I.", "-Ilibbf"
)
Remove-Item *.o, qjs.exe, qjsc.exe, repl.c -ErrorAction SilentlyContinue

# 1) engine lib objects (incl. libbf from libbf/)
& $cc @common -c libbf/libbf.c -o libbf.o 2>$null
& $cc @common -c quickjs.c -o quickjs.o 2>$null
& $cc @common -c libregexp.c -o libregexp.o 2>$null
& $cc @common -c libunicode.c -o libunicode.o 2>$null
& $cc @common -c cutils.c -o cutils.o 2>$null

# 2) qjsc (compiler) -> used to generate repl.c (needs quickjs-libc for js_load_file)
& $cc @common -c quickjs-libc.c -o quickjs-libc.o 2>$null
& $cc @common -c qjsc.c -o qjsc.o 2>$null
& $cc @common -o qjsc.exe qjsc.o quickjs.o quickjs-libc.o libregexp.o libunicode.o cutils.o libbf.o -lwinpthread 2>$null
if (-not (Test-Path qjsc.exe)) { Write-Output "FAIL: qjsc build"; exit 1 }

# 3) repl.c from repl.js via qjsc
& .\qjsc.exe -c -o repl.c -m repl.js 2>$null
if (-not (Test-Path repl.c)) { Write-Output "FAIL: repl.c generation"; exit 1 }

# 4) remaining objects + link qjs
& $cc @common -c repl.c -o repl.o 2>$null
& $cc @common -c qjs.c -o qjs.o 2>$null
& $cc @common -o qjs.exe qjs.o repl.o quickjs.o quickjs-libc.o libregexp.o libunicode.o cutils.o libbf.o -lwinpthread 2>$null
if (-not (Test-Path qjs.exe)) { Write-Output "FAIL: qjs link"; exit 1 }
Write-Output "BUILD OK: qjs.exe $((Get-Item qjs.exe).Length) bytes"
