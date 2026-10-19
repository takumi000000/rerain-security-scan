# 毎週のスキャンをタスクスケジューラに登録する（Windows 用。既定: 月曜 8:00）。
# 使い方: powershell -ExecutionPolicy Bypass -File scripts\install-schedule.ps1 [曜日 0-6(日=0)] [時] [分]
# 解除:   powershell -ExecutionPolicy Bypass -File scripts\install-schedule.ps1 -Remove
# ログオン中だけ動く（パスワードを保存しない・通知を出せる）。新しい緊急・高があれば通知する。
param(
    [ValidateRange(0, 6)][int]$Weekday = 1,
    [ValidateRange(0, 23)][int]$Hour = 8,
    [ValidateRange(0, 59)][int]$Minute = 0,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$TaskName = 'rerain-security-scan'
$Root = Split-Path -Parent $PSScriptRoot
$Scan = Join-Path $Root 'scan.py'
$Reports = Join-Path $Root 'reports'
$Log = Join-Path $Reports 'task.log'

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host '解除しました'
    exit 0
}

# 窓を出さない pyw / pythonw を優先する。3.11 以上（tomllib）が必要
$exe = $null; $prefix = @()
$pyw = Get-Command pyw.exe -ErrorAction SilentlyContinue
if ($pyw) {
    $ErrorActionPreference = 'Continue'   # 5.1 ではネイティブの stderr が例外になるので判定の間だけ緩める
    & py.exe -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $exe = $pyw.Source; $prefix = @('-3') }
    $ErrorActionPreference = 'Stop'
}
if (-not $exe) {
    $py = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $py) { throw 'Python 3.11 以上が見つかりません（https://www.python.org/ から入れてください）' }
    & $py.Source -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 以上が必要です' }
    $w = Join-Path (Split-Path -Parent $py.Source) 'pythonw.exe'
    if (Test-Path -LiteralPath $w) { $exe = $w } else { $exe = $py.Source }
}

New-Item -ItemType Directory -Force -Path $Reports | Out-Null
# レポートには弱点の一覧が入るので、継承を切って本人とSYSTEMだけが読めるようにする
& icacls.exe $Reports /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null

$argList = ($prefix + @("`"$Scan`"", '--notify', '--log', "`"$Log`"")) -join ' '
$action = New-ScheduledTaskAction -Execute $exe -Argument $argList -WorkingDirectory $Root
$day = [System.DayOfWeek]$Weekday
$at = (Get-Date).Date.AddHours($Hour).AddMinutes($Minute)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $day -At $at
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
    -Description 'ReRain セキュリティ点検: 読み取り専用のセキュリティ点検（毎週）' -Force | Out-Null

Write-Host ("登録しました: 毎週 {0} {1}:{2:D2}（タスク名 {3}）" -f $day, $Hour, $Minute, $TaskName)
Write-Host "今すぐ1回: Start-ScheduledTask -TaskName $TaskName"
Write-Host "ログ: $Log"
