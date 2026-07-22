param(
    [switch]$Sign,
    [string]$Thumbprint = "9AC4E22205AF0E71506DFABC56DEA41BBEF3C38C"
)

$ErrorActionPreference = "Stop"
$src = "$PSScriptRoot\rust_loader\src\main.rs"
$out = "$PSScriptRoot\build\mtool.exe"

if (!(Test-Path "$PSScriptRoot\build")) { New-Item -ItemType Directory "$PSScriptRoot\build" | Out-Null }

Write-Host "[*] Building with rustc -O ..." -ForegroundColor Cyan
rustc $src -O --edition 2021 -o $out -l oleaut32
if ($LASTEXITCODE -ne 0) { Write-Host "[-] Build failed" -ForegroundColor Red; exit 1 }

$size = (Get-Item $out).Length
Write-Host "[+] Built: $out ($size bytes)" -ForegroundColor Green

if ($Sign) {
    Write-Host "[*] Signing with cert $Thumbprint ..." -ForegroundColor Cyan
    $cert = Get-ChildItem Cert:\CurrentUser\My\$Thumbprint -ErrorAction SilentlyContinue
    if ($cert) {
        Set-AuthenticodeSignature -FilePath $out -Certificate $cert -TimestampServer "http://timestamp.digicert.com" | Out-Null
        Write-Host "[+] Signed" -ForegroundColor Green
    } else {
        Write-Host "[!] Cert not found, skipping signature" -ForegroundColor Yellow
    }
}

Write-Host "[+] Done" -ForegroundColor Green
