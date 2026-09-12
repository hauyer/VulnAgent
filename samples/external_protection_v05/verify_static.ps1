$ErrorActionPreference = "Stop"

$bundleRoot = $PSScriptRoot
$manifestPath = Join-Path $bundleRoot "manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$failed = $false
$rows = foreach ($sample in $manifest.samples) {
    $path = Join-Path $bundleRoot ($sample.path -replace "/", "\")
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $failed = $true
        [pscustomobject]@{
            Sample = $sample.sample_id
            Format = "missing"
            Hash = "MISSING"
            Status = "FAIL"
        }
        continue
    }

    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $bytes = [IO.File]::ReadAllBytes($path)
    $magic = ($bytes[0..3] | ForEach-Object { $_.ToString("X2") }) -join ""
    $actualFormat = if ($magic.StartsWith("4D5A")) {
        "PE"
    } elseif ($magic -eq "7F454C46") {
        "ELF"
    } elseif ($magic.StartsWith("504B")) {
        "APK/ZIP"
    } else {
        "unknown:$magic"
    }

    $ok = $actualHash -eq $sample.sha256 -and $actualFormat -eq $sample.format
    if (-not $ok) { $failed = $true }
    [pscustomobject]@{
        Sample = $sample.sample_id
        Format = $actualFormat
        Hash = if ($actualHash -eq $sample.sha256) { "OK" } else { "MISMATCH" }
        Status = if ($ok) { "OK" } else { "FAIL" }
    }
}

$rows | Format-Table -AutoSize
if ($failed) { exit 1 }
exit 0
