# gitleaks と osv-scanner を公式GitHubリリースから bin\ に取得し、SHA256 を検証する（Windows 用）。
# 既に winget / scoop 等で入っていれば不要（PATH 上のものを使う）。
# 使い方: powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GitleaksVersion = '8.30.1'
$OsvVersion = '2.7.0'

$Root = Split-Path -Parent $PSScriptRoot
$Bin = Join-Path $Root 'bin'
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ('sscan-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null

switch ($env:PROCESSOR_ARCHITECTURE) {
    'ARM64' { $glArch = 'arm64'; $osvArch = 'arm64' }
    'AMD64' { $glArch = 'x64'; $osvArch = 'amd64' }
    default { throw "未対応のCPU: $($env:PROCESSOR_ARCHITECTURE)" }
}

function Get-File([string]$url, [string]$dest) {
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
}

function Test-Checksum([string]$file, [string]$sumsFile) {
    $name = Split-Path -Leaf $file
    $expected = $null
    foreach ($line in Get-Content -LiteralPath $sumsFile) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -ge 2 -and ($parts[1] -eq $name -or $parts[1] -eq ('*' + $name))) { $expected = $parts[0].ToLower() }
    }
    $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
    if (-not $expected -or $expected -ne $actual) { throw "チェックサム不一致: $name" }
    Write-Host "  OK $name の SHA256 を確認"
}

try {
    Write-Host "gitleaks v$GitleaksVersion (windows/$glArch)"
    $gl = "gitleaks_${GitleaksVersion}_windows_${glArch}.zip"
    $base = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion"
    Get-File "$base/$gl" (Join-Path $Tmp $gl)
    Get-File "$base/gitleaks_${GitleaksVersion}_checksums.txt" (Join-Path $Tmp 'gl_sums.txt')
    Test-Checksum (Join-Path $Tmp $gl) (Join-Path $Tmp 'gl_sums.txt')
    Expand-Archive -LiteralPath (Join-Path $Tmp $gl) -DestinationPath (Join-Path $Tmp 'gl') -Force
    Copy-Item -LiteralPath (Join-Path $Tmp 'gl\gitleaks.exe') -Destination (Join-Path $Bin 'gitleaks.exe') -Force

    Write-Host "osv-scanner v$OsvVersion (windows/$osvArch)"
    $osv = "osv-scanner_windows_${osvArch}.exe"
    $base = "https://github.com/google/osv-scanner/releases/download/v$OsvVersion"
    Get-File "$base/$osv" (Join-Path $Tmp $osv)
    Get-File "$base/osv-scanner_SHA256SUMS" (Join-Path $Tmp 'osv_sums.txt')
    Test-Checksum (Join-Path $Tmp $osv) (Join-Path $Tmp 'osv_sums.txt')
    Copy-Item -LiteralPath (Join-Path $Tmp $osv) -Destination (Join-Path $Bin 'osv-scanner.exe') -Force

    # インターネットから来た印（Zone.Identifier）を外して SmartScreen の確認を出さない（SHA256 は検証済み）
    Unblock-File -LiteralPath (Join-Path $Bin 'gitleaks.exe'), (Join-Path $Bin 'osv-scanner.exe')
    & (Join-Path $Bin 'gitleaks.exe') version
    & (Join-Path $Bin 'osv-scanner.exe') --version | Select-Object -First 1
    Write-Host "完了: $Bin"
} finally {
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
