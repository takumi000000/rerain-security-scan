# ReRain セキュリティ点検: Windows本体の設定を読み取り専用で集めて JSON で出す（win.py から呼ばれる）。
# 管理者権限は不要。設定の変更・送信は一切しない。
# 常駐・タスクのコマンド引数には秘密が入りうるので、出力するのは「起動するプログラムのパス」と判定結果だけ。
# Windows PowerShell 5.1 で動く書き方に限定している（?? や三項演算子は使わない）。

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

$out = [ordered]@{}

function Add-Section([string]$name, [scriptblock]$sb) {
    try {
        $script:out[$name] = & $sb
    } catch {
        $script:out[$name] = @{ __error = [string]$_.Exception.Message }
    }
}

function Get-RegValue([string]$path, [string]$name) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $p = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    $prop = $p.PSObject.Properties[$name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

# 起動コマンド文字列から実行ファイルのパスだけを取り出す（引数は捨てる）
function Get-ExePath([string]$cmd) {
    if ([string]::IsNullOrWhiteSpace($cmd)) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
        return $c.Trim('"')
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|scr|dll|msi))(\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

$LOLBINS = @('mshta.exe', 'wscript.exe', 'cscript.exe', 'rundll32.exe', 'regsvr32.exe', 'powershell.exe', 'pwsh.exe', 'cmd.exe', 'bitsadmin.exe', 'certutil.exe', 'msiexec.exe')
$SUSPICIOUS = '(?i)(\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Downloads\\|\\Users\\Public\\|%TEMP%|%TMP%)'

# 起動項目1件ぶんの判定材料を作る。cmd 全体は返さない
function New-StartItem([string]$kind, [string]$where, [string]$name, [string]$cmd) {
    $exe = Get-ExePath $cmd
    $expanded = [Environment]::ExpandEnvironmentVariables([string]$cmd)
    $exists = $false
    $sig = ''
    if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf -ErrorAction SilentlyContinue)) {
        $exists = $true
        try { $sig = [string](Get-AuthenticodeSignature -LiteralPath $exe).Status } catch { $sig = 'Unknown' }
    } elseif ($exe -and -not ($exe -match '[\\/]')) {
        # パス無しのコマンド名（rundll32.exe 等）は PATH から探す
        $found = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            $exists = $true
            $exe = $found.Source
            try { $sig = [string](Get-AuthenticodeSignature -LiteralPath $exe).Status } catch { $sig = 'Unknown' }
        }
    }
    $leaf = ''
    if ($exe) { try { $leaf = [System.IO.Path]::GetFileName($exe).ToLower() } catch { $leaf = '' } }
    return [ordered]@{
        kind      = $kind
        where     = $where
        name      = $name
        exe       = $exe
        exists    = $exists
        signature = $sig
        lolbin    = ($LOLBINS -contains $leaf)
        suspicious_dir = ($expanded -match $SUSPICIOUS)
    }
}

Add-Section 'os' {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [ordered]@{
        product = [string]$cv.ProductName
        edition = [string]$cv.EditionID
        build   = [int]$cv.CurrentBuildNumber
        ubr     = $cv.UBR
        display = [string]$cv.DisplayVersion
        release = [string]$cv.ReleaseId
        computer = [string]$env:COMPUTERNAME
    }
}

Add-Section 'bitlocker' {
    # 管理者権限なしで読める方法（エクスプローラーと同じ値）。
    # 0=非対応 1=オン 2=オフ 3=暗号化中 4=復号中 5=一時停止 6=オン(ロック中) 8=有効化待ち
    $sh = New-Object -ComObject Shell.Application
    $drive = $env:SystemDrive + '\'
    $v = $sh.NameSpace($drive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
    [ordered]@{ drive = $env:SystemDrive; protection = $v }
}

Add-Section 'defender' {
    $s = Get-MpComputerStatus
    [ordered]@{
        av_enabled   = [bool]$s.AntivirusEnabled
        realtime     = [bool]$s.RealTimeProtectionEnabled
        signature_age = [int]$s.AntivirusSignatureAge
        tamper       = [bool]$s.IsTamperProtected
        mode         = [string]$s.AMRunningMode
    }
}

Add-Section 'av_products' {
    $items = @()
    foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct)) {
        $items += [ordered]@{ name = [string]$p.displayName; state = [int]$p.productState }
    }
    , $items
}

Add-Section 'firewall' {
    $items = @()
    foreach ($p in @(Get-NetFirewallProfile)) {
        $items += [ordered]@{ name = [string]$p.Name; enabled = [string]$p.Enabled; inbound = [string]$p.DefaultInboundAction }
    }
    , $items
}

Add-Section 'network_category' {
    $items = @()
    foreach ($p in @(Get-NetConnectionProfile)) {
        $items += [ordered]@{ name = [string]$p.Name; category = [string]$p.NetworkCategory }
    }
    , $items
}

Add-Section 'uac' {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    [ordered]@{
        lua            = Get-RegValue $k 'EnableLUA'
        consent_admin  = Get-RegValue $k 'ConsentPromptBehaviorAdmin'
        secure_desktop = Get-RegValue $k 'PromptOnSecureDesktop'
    }
}

Add-Section 'autologin' {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    [ordered]@{
        auto         = [string](Get-RegValue $k 'AutoAdminLogon')
        user         = [string](Get-RegValue $k 'DefaultUserName')
        has_password = ($null -ne (Get-RegValue $k 'DefaultPassword'))   # 値そのものは読まない
    }
}

Add-Section 'screenlock' {
    $d = 'HKCU:\Control Panel\Desktop'
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $hex = { param($args2)
        # Windows PowerShell 5.1 は Stop のままだとネイティブコマンドの stderr で例外になるので、ここだけ緩める
        $ErrorActionPreference = 'Continue'
        $text = ''
        try { $text = (& powercfg.exe @args2 2>$null) -join "`n" } catch { $text = '' }
        $m = [regex]::Matches($text, '0x[0-9a-fA-F]{8}')
        $vals = @()
        foreach ($x in $m) { $vals += [Convert]::ToInt64($x.Value, 16) }
        if ($vals.Count -ge 2) { return @($vals[$vals.Count - 2], $vals[$vals.Count - 1]) }   # AC, DC
        return @()
    }
    [ordered]@{
        ss_active   = [string](Get-RegValue $d 'ScreenSaveActive')
        ss_secure   = [string](Get-RegValue $d 'ScreenSaveIsSecure')
        ss_timeout  = [string](Get-RegValue $d 'ScreenSaveTimeOut')
        inactivity  = Get-RegValue $pol 'InactivityTimeoutSecs'
        console_lock = & $hex @('/q', 'SCHEME_CURRENT', 'SUB_NONE', 'CONSOLELOCK')
        sleep_idle   = & $hex @('/q', 'SCHEME_CURRENT', 'SUB_SLEEP', 'STANDBYIDLE')
        dynamic_lock = Get-RegValue 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'EnableGoodbye'
    }
}

Add-Section 'updates' {
    $last = $null
    $lastId = ''
    foreach ($h in @(Get-HotFix -ErrorAction SilentlyContinue)) {
        $when = $null
        try { $when = $h.InstalledOn } catch { $when = $null }
        if ($when -and (($null -eq $last) -or ($when -gt $last))) { $last = $when; $lastId = [string]$h.HotFixID }
    }
    $lastText = $null
    if ($last) { $lastText = $last.ToString('yyyy-MM-dd') }
    [ordered]@{
        last_hotfix    = $lastText
        last_hotfix_id = $lastId
        reboot_pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    }
}

Add-Section 'listening' {
    # 待ち受けポートごとに「何が動いているか」（プロセス・実行ファイル・発行元・署名・中で動くサービス）を集める。
    # 127.0.0.1 / ::1 だけのものも一覧のために集める（外からは届かない印 local=true を付ける）
    $svcByPid = @{}
    try {
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter 'ProcessId > 0')) {
            $k = [int]$s.ProcessId
            if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = @() }
            $svcByPid[$k] += ([string]$s.Name + ' (' + [string]$s.DisplayName + ')')
        }
    } catch { }
    $procInfo = @{}
    $items = @()
    foreach ($c in @(Get-NetTCPConnection -State Listen)) {
        $procId = [int]$c.OwningProcess
        if (-not $procInfo.ContainsKey($procId)) {
            $info = [ordered]@{ proc = ''; path = ''; company = ''; description = ''; signature = ''; signer = ''; services = @() }
            $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($p) {
                $info.proc = [string]$p.ProcessName
                $path = $null
                try { $path = $p.Path } catch { $path = $null }
                if (-not $path) {
                    try { $path = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $procId").ExecutablePath } catch { $path = $null }
                }
                if ($path) {
                    $info.path = [string]$path
                    try {
                        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
                        $info.company = [string]$vi.CompanyName
                        $info.description = [string]$vi.FileDescription
                    } catch { }
                    try {
                        $sig = Get-AuthenticodeSignature -LiteralPath $path
                        $info.signature = [string]$sig.Status
                        if ($sig.SignerCertificate) { $info.signer = [string]$sig.SignerCertificate.GetNameInfo('SimpleName', $false) }
                    } catch { $info.signature = 'Unknown' }
                }
            }
            if ($procId -eq 4) { $info.proc = 'System'; $info.description = 'Windows カーネル（System）' }
            if ($svcByPid.ContainsKey($procId)) { $info.services = @($svcByPid[$procId]) }
            $procInfo[$procId] = $info
        }
        $a = [string]$c.LocalAddress
        $i = $procInfo[$procId]
        $items += [ordered]@{
            port = [int]$c.LocalPort; addr = $a; pid = $procId
            local = ($a -eq '::1' -or $a.StartsWith('127.'))
            proc = $i.proc; path = $i.path; company = $i.company; description = $i.description
            signature = $i.signature; signer = $i.signer; services = $i.services
        }
    }
    , $items
}

Add-Section 'rdp' {
    [ordered]@{
        deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        nla  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    }
}

Add-Section 'smb1' {
    [ordered]@{
        client_start = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
        server_start = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\srv' 'Start'
        server_param = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    }
}

Add-Section 'accounts' {
    $guest = $null
    $admin = $null
    foreach ($u in @(Get-LocalUser)) {
        if ($u.SID.Value -like '*-501') { $guest = [bool]$u.Enabled }
        if ($u.SID.Value -like '*-500') { $admin = [bool]$u.Enabled }
    }
    [ordered]@{ guest_enabled = $guest; builtin_admin_enabled = $admin }
}

Add-Section 'hardening' {
    [ordered]@{
        smartscreen       = [string](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')
        smartscreen_policy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
        hvci              = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled'
        secure_boot       = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
    }
}

Add-Section 'sshd' {
    $s = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
    if ($null -eq $s) { [ordered]@{ installed = $false } }
    else { [ordered]@{ installed = $true; status = [string]$s.Status; start = [string]$s.StartType } }
}

Add-Section 'startup' {
    $items = @()
    $runKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($k in $runKeys) {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $p = Get-ItemProperty -LiteralPath $k
        foreach ($prop in $p.PSObject.Properties) {
            if ($prop.Name -like 'PS*') { continue }
            $items += New-StartItem 'run' $k $prop.Name ([string]$prop.Value)
        }
    }
    $folders = @(
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
    )
    $wsh = New-Object -ComObject WScript.Shell
    foreach ($f in $folders) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $f -File -Force)) {
            if ($file.Name -ieq 'desktop.ini') { continue }
            $target = $file.FullName
            if ($file.Extension -ieq '.lnk') {
                try { $target = '"' + $wsh.CreateShortcut($file.FullName).TargetPath + '"' } catch { }
            }
            $items += New-StartItem 'startup_folder' $f $file.Name $target
        }
    }
    , $items
}

Add-Section 'tasks' {
    $items = @()
    foreach ($t in @(Get-ScheduledTask)) {
        if ($t.TaskPath -like '\Microsoft\*') { continue }
        if ([string]$t.State -eq 'Disabled') { continue }
        foreach ($a in @($t.Actions)) {
            $exec = [string]$a.Execute
            if (-not $exec) { continue }
            $cmd = $exec
            if ($exec -notmatch '^\s*"') { $cmd = '"' + $exec.Trim() + '"' }
            $item = New-StartItem 'task' ([string]$t.TaskPath) ([string]$t.TaskName) ($cmd + ' ' + [string]$a.Arguments)
            $items += $item
        }
    }
    , $items
}

Add-Section 'services' {
    # 自動起動で SYSTEM 等として動くサービスのうち、ユーザーが書き換えられる場所のもの・引用符のない空白入りパスだけ返す
    $items = @()
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service)) {
        if ($s.StartMode -ne 'Auto') { continue }
        $path = [string]$s.PathName
        if (-not $path) { continue }
        $exe = Get-ExePath $path
        $userWritable = ($exe -match '(?i)^[a-z]:\\Users\\') -or ($exe -match '(?i)\\Temp\\')
        $unquoted = (-not $path.Trim().StartsWith('"')) -and ($exe -match ' ') -and ($exe -notmatch '(?i)^[a-z]:\\Windows\\')
        if ($userWritable -or $unquoted) {
            $items += [ordered]@{ name = [string]$s.Name; display = [string]$s.DisplayName; exe = $exe; account = [string]$s.StartName; user_writable = $userWritable; unquoted = $unquoted }
        }
    }
    , $items
}

ConvertTo-Json -InputObject $out -Depth 6 -Compress
