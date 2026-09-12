$ErrorActionPreference = "Stop"

$bundleRoot = $PSScriptRoot
$repositoryRoot = (Resolve-Path (Join-Path $bundleRoot "..\..")).Path
$outputDirectory = Join-Path $bundleRoot "bin"
$upx = Join-Path $repositoryRoot "tools\upx\upx-5.2.1-win64\upx.exe"

if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    throw "gcc is required to build the AFL training adapter"
}
if (-not (Get-Command g++ -ErrorAction SilentlyContinue)) {
    throw "g++ is required to build the google/fuzzing adapter"
}
if (-not (Test-Path -LiteralPath $upx -PathType Leaf)) {
    throw "UPX was not found at $upx"
}

New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$aflSource = Join-Path $bundleRoot "afl_training\vulnagent_stdin_driver.c"
$googleSource = Join-Path $bundleRoot "google_fuzzing\vulnagent_stdin_driver.cc"
$aflRaw = Join-Path $outputDirectory "afl-training-vulnagent.exe"
$googleRaw = Join-Path $outputDirectory "google-fuzzing-vulnagent.exe"
$aflPacked = Join-Path $outputDirectory "afl-training-vulnagent-upx.exe"
$googlePacked = Join-Path $outputDirectory "google-fuzzing-vulnagent-upx.exe"

& gcc -O0 -g -fno-builtin $aflSource -o $aflRaw
if ($LASTEXITCODE -ne 0) { throw "gcc failed" }

& g++ -O0 -g -fno-builtin $googleSource -o $googleRaw
if ($LASTEXITCODE -ne 0) { throw "g++ failed" }

foreach ($packed in @($aflPacked, $googlePacked)) {
    if (Test-Path -LiteralPath $packed -PathType Leaf) {
        Remove-Item -LiteralPath $packed -Force
    }
}

& $upx -9 -q -o $aflPacked $aflRaw
if ($LASTEXITCODE -ne 0) { throw "UPX failed for AFL training adapter" }

& $upx -9 -q -o $googlePacked $googleRaw
if ($LASTEXITCODE -ne 0) { throw "UPX failed for google/fuzzing adapter" }

Get-FileHash -Algorithm SHA256 $aflPacked, $googlePacked |
    Select-Object Path, Hash
