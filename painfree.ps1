<#
.SYNOPSIS
    Painfree - read-only Windows troubleshooter.

.DESCRIPTION
    Scans event logs, program logs, services, disks, registry, security settings,
    installed programs and any detected server roles (IIS, SQL Server, AD DS, DNS,
    DHCP, Hyper-V, Exchange, WSUS), then writes a self-contained HTML report with
    a proposed fix for every finding.

    Painfree NEVER changes anything. Every fix is shown for you to review and run.

    Supported: Windows 10/11, Windows Server 2016/2019/2022/2025 (Windows PowerShell 5.1+).
    Must be run from an elevated (Run as Administrator) PowerShell.

.EXAMPLE
    irm https://raw.githubusercontent.com/kconsulting786/painfree/main/painfree.ps1 | iex

.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kconsulting786/painfree/main/painfree.ps1))) -Days 14 -NoOpen
#>
[CmdletBinding()]
param(
    # How many days of event logs and program logs to look back over.
    [int]$Days = 7,
    # Where to write the report. Defaults to the Desktop (or TEMP if there is no Desktop).
    [string]$OutputPath,
    # Do not open the report in a browser when finished.
    [switch]$NoOpen,
    # Skip the slower checks (program log scan, folder sizes, dcdiag).
    [switch]$Quick
)

$PainfreeVersion = '0.1.0'

function Start-Painfree {
    param([int]$Days, [string]$OutputPath, [switch]$NoOpen, [switch]$Quick)

    $ErrorActionPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    #region ---------- Framework ----------

    $PF = @{
        Findings = New-Object System.Collections.Generic.List[object]
        Errors   = New-Object System.Collections.Generic.List[object]
        Checks   = New-Object System.Collections.Generic.List[object]
        Roles    = New-Object System.Collections.Generic.List[string]
        Info     = [ordered]@{}
        Start    = (Get-Date).AddDays(-$Days)
    }

    function Add-Finding {
        param(
            [Parameter(Mandatory)][string]$Category,
            [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
            [Parameter(Mandatory)][string]$Title,
            [string]$Description = '',
            [object]$Evidence,
            [string]$Fix = '',
            [string]$Command = '',
            [string]$Reference = ''
        )
        $ev = ''
        if ($null -ne $Evidence) {
            $lines = @($Evidence | ForEach-Object { "$_" })
            if ($lines.Count -gt 40) { $lines = $lines[0..39] + "... ($($lines.Count - 40) more)" }
            $ev = $lines -join "`n"
        }
        $PF.Findings.Add([pscustomobject]@{
                Category    = $Category
                Severity    = $Severity
                Title       = $Title
                Description = $Description
                Evidence    = $ev
                Fix         = $Fix
                Command     = $Command
                Reference   = $Reference
            })
    }

    function Invoke-Check {
        param([string]$Name, [scriptblock]$Script)
        Write-Host ('  {0,-48}' -f $Name) -NoNewline
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $before = $PF.Findings.Count
        try {
            . $Script
            $n = $PF.Findings.Count - $before
            if ($n -gt 0) { Write-Host ("{0} finding(s)" -f $n) -ForegroundColor Yellow } else { Write-Host 'OK' -ForegroundColor Green }
        }
        catch {
            Write-Host 'check failed' -ForegroundColor DarkGray
            $PF.Errors.Add([pscustomobject]@{ Check = $Name; Error = ($_.Exception.Message -split "`r?`n")[0] })
        }
        $PF.Checks.Add([pscustomobject]@{ Name = $Name; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
    }

    function Get-RegValue {
        param([string]$Path, [string]$Name)
        try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
    }

    function Format-Size {
        param([double]$Bytes)
        if ($Bytes -ge 1TB) { return '{0:N1} TB' -f ($Bytes / 1TB) }
        if ($Bytes -ge 1GB) { return '{0:N1} GB' -f ($Bytes / 1GB) }
        if ($Bytes -ge 1MB) { return '{0:N0} MB' -f ($Bytes / 1MB) }
        return '{0:N0} KB' -f ($Bytes / 1KB)
    }

    function Get-FolderSize {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { return 0 }
        $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($sum) { return [double]$sum } else { return 0 }
    }

    # Reads the last $Bytes of a file even when another process has it open. Handles UTF-16 logs (e.g. SQL ERRORLOG).
    function Read-FileTail {
        param([string]$Path, [int]$Bytes = 262144)
        $fs = $null
        try {
            $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
            $len = $fs.Length
            $start = [math]::Max(0, $len - $Bytes)
            if ($start % 2 -ne 0) { $start++ }
            [void]$fs.Seek($start, [IO.SeekOrigin]::Begin)
            $buf = New-Object byte[] ([int]($len - $start))
            $n = $fs.Read($buf, 0, $buf.Length)
            $zeros = 0
            $probe = [math]::Min($n, 2000)
            for ($i = 0; $i -lt $probe; $i++) { if ($buf[$i] -eq 0) { $zeros++ } }
            if ($probe -gt 0 -and $zeros / $probe -gt 0.2) { $text = [Text.Encoding]::Unicode.GetString($buf, 0, $n) }
            else { $text = [Text.Encoding]::UTF8.GetString($buf, 0, $n) }
            return ($text -split "`r?`n")
        }
        catch { return @() }
        finally { if ($fs) { $fs.Close() } }
    }

    # Runs a native command with a timeout and returns its output text.
    function Invoke-Native {
        param([string]$File, [string]$Arguments, [int]$TimeoutSec = 60)
        $out = [IO.Path]::GetTempFileName()
        $err = [IO.Path]::GetTempFileName()
        try {
            $p = Start-Process -FilePath $File -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
            if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch {}; return $null }
            return (Get-Content -LiteralPath $out -Raw)
        }
        finally { Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue }
    }

    # Pulls the executable path out of a command line. Returns $null when it cannot be determined reliably.
    function Get-CommandPath {
        param([string]$CommandLine)
        if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
        $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
        $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:SystemRoot\"
        if ($c -match '^(?i)system32\\') { $c = Join-Path $env:SystemRoot $c }
        if ($c -match '^"([^"]+)"') { $p = $Matches[1] }
        elseif ($c -match '^(?i)([a-z]:\\.+?\.(exe|com|bat|cmd|dll|vbs|js|ps1|scr|msc|cpl|lnk))(?=\s|,|$)') { $p = $Matches[1] }
        else { return $null }
        if ($p -match '(?i)\\(rundll32|regsvr32)\.exe$' -and $c -match '(?i)(rundll32|regsvr32)(\.exe)?"?\s+"?(?:/s\s+)?"?([a-z]:\\[^",]+?\.(dll|ocx|cpl))') {
            $p = $Matches[3]
        }
        if ($p -notmatch '^(?i)[a-z]:\\') { return $null }
        return $p
    }

    function Get-MsiUninstallCommand {
        param($App)
        if ($App.QuietUninstallString) { return $App.QuietUninstallString }
        if ($App.UninstallString -match '(?i)msiexec(\.exe)?\s+/[ix]\s*(\{[0-9a-f-]+\})') { return "msiexec.exe /x $($Matches[2])" }
        return $App.UninstallString
    }

    #endregion

    #region ---------- Pre-flight ----------

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host ''
    Write-Host "  Painfree $PainfreeVersion - read-only Windows troubleshooter" -ForegroundColor Cyan
    Write-Host '  Nothing on this machine will be changed.' -ForegroundColor DarkGray
    Write-Host ''
    if (-not $isAdmin) {
        Write-Host '  Painfree needs to run as Administrator to read all logs and registry keys.' -ForegroundColor Red
        Write-Host '  Right-click PowerShell, choose "Run as administrator", and run the command again.' -ForegroundColor Red
        Write-Host ''
        return
    }

    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu = @(Get-CimInstance Win32_Processor)
    $isServer = $os.ProductType -ne 1
    $isDC = $os.ProductType -eq 2
    $build = [int]$os.BuildNumber
    $ubr = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
    $displayVersion = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion'
    if (-not $displayVersion) { $displayVersion = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'ReleaseId' }
    $uptime = (Get-Date) - $os.LastBootUpTime
    $services = @(Get-CimInstance Win32_Service)
    $svcNames = @{}
    foreach ($s in $services) { $svcNames[$s.Name] = $s }

    $PF.Info['Computer'] = $env:COMPUTERNAME
    $PF.Info['Domain / Workgroup'] = if ($cs.PartOfDomain) { "$($cs.Domain) (domain)" } else { "$($cs.Workgroup) (workgroup)" }
    $PF.Info['Operating system'] = "$($os.Caption) $displayVersion (build $build.$ubr)"
    $PF.Info['Role'] = if ($isDC) { 'Domain controller' } elseif ($isServer) { 'Member / standalone server' } else { 'Workstation' }
    $PF.Info['Manufacturer / model'] = "$($cs.Manufacturer) $($cs.Model)"
    $PF.Info['BIOS'] = "$($bios.SMBIOSBIOSVersion) ($(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') }))"
    $PF.Info['CPU'] = "$($cpu[0].Name.Trim()) x$($cpu.Count) ($(($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum) logical)"
    $PF.Info['Memory'] = Format-Size ($cs.TotalPhysicalMemory)
    $PF.Info['Last boot'] = "$($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')) (up $([int]$uptime.TotalDays) days)"
    $PF.Info['PowerShell'] = "$($PSVersionTable.PSVersion)"
    $PF.Info['Scan window'] = "Last $Days days"
    $PF.Info['Scanned by'] = "$env:USERDOMAIN\$env:USERNAME"

    # Role detection
    $roleMap = [ordered]@{
        'IIS (web server)'   = { $svcNames.ContainsKey('W3SVC') }
        'SQL Server'         = { @($services | Where-Object { $_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*' }).Count -gt 0 }
        'Active Directory'   = { $svcNames.ContainsKey('NTDS') }
        'DNS Server'         = { $svcNames.ContainsKey('DNS') }
        'DHCP Server'        = { $svcNames.ContainsKey('DHCPServer') }
        'Hyper-V'            = { $svcNames.ContainsKey('vmms') }
        'Exchange'           = { $svcNames.ContainsKey('MSExchangeTransport') -or $svcNames.ContainsKey('MSExchangeIS') }
        'WSUS'               = { $svcNames.ContainsKey('WsusService') }
        'Print Server'       = { $svcNames['Spooler'].State -eq 'Running' -and @(Get-CimInstance Win32_Printer | Where-Object Shared).Count -gt 0 }
        'File Server'        = { @(Get-CimInstance Win32_Share | Where-Object { $_.Type -eq 0 -and $_.Name -notmatch '^(ADMIN|IPC|print|[A-Z])\$$|^(SYSVOL|NETLOGON)$' }).Count -gt 0 }
    }
    foreach ($r in $roleMap.Keys) { if (& $roleMap[$r]) { $PF.Roles.Add($r) } }
    $PF.Info['Detected roles'] = if ($PF.Roles.Count) { $PF.Roles -join ', ' } else { 'None' }

    Write-Host "  $($PF.Info['Operating system'])" -ForegroundColor Gray
    Write-Host "  Roles: $($PF.Info['Detected roles'])" -ForegroundColor Gray
    Write-Host ''

    #endregion

    #region ---------- Operating system and updates ----------

    Invoke-Check 'Windows version support' {
        $caption = $os.Caption
        $ent = $caption -match 'Enterprise|Education'
        $ltsc = $caption -match 'LTSC|LTSB'
        $eos = $null
        if ($isServer) {
            $map = @{ 14393 = '2027-01-12'; 17763 = '2029-01-09'; 20348 = '2031-10-14'; 26100 = '2034-11-14' }
            if ($map.ContainsKey($build)) { $eos = $map[$build] }
        }
        else {
            # build = @(Home/Pro, Enterprise/Education, LTSC)
            $map = @{
                10240 = @('2017-05-09', '2017-05-09', '2025-10-14'); 10586 = @('2017-10-10', '2018-04-10', $null)
                14393 = @('2018-04-10', '2019-04-09', '2026-10-13'); 15063 = @('2018-10-09', '2019-10-08', $null)
                16299 = @('2019-04-09', '2020-10-13', $null); 17134 = @('2019-11-12', '2021-05-11', $null)
                17763 = @('2020-11-10', '2021-05-11', '2029-01-09'); 18362 = @('2020-12-08', '2020-12-08', $null)
                18363 = @('2021-05-11', '2022-05-10', $null); 19041 = @('2021-12-14', '2021-12-14', $null)
                19042 = @('2022-05-10', '2023-05-09', $null); 19043 = @('2022-12-13', '2022-12-13', $null)
                19044 = @('2023-06-13', '2024-06-11', '2027-01-12'); 19045 = @('2025-10-14', '2025-10-14', $null)
                22000 = @('2023-10-10', '2024-10-08', $null); 22621 = @('2024-10-08', '2025-10-14', $null)
                22631 = @('2025-11-11', '2026-11-10', $null); 26100 = @('2026-10-13', '2027-10-12', '2029-10-09')
                26200 = @('2027-10-12', '2028-10-10', $null)
            }
            if ($map.ContainsKey($build)) {
                $e = $map[$build]
                if ($ltsc -and $e[2]) { $eos = $e[2] } elseif ($ent) { $eos = $e[1] } else { $eos = $e[0] }
            }
        }
        if ($eos) {
            $eosDate = [datetime]::ParseExact($eos, 'yyyy-MM-dd', $null)
            $left = ($eosDate - (Get-Date)).Days
            $PF.Info['OS end of support'] = "$eos ($(if ($left -lt 0) { 'ENDED' } else { "$left days left" }))"
            if ($left -lt 0) {
                $esu = if ($build -eq 19045) { ' If this PC is enrolled in Extended Security Updates (ESU) it is still covered; otherwise it no longer gets security fixes.' } else { '' }
                Add-Finding -Category 'Updates' -Severity 'High' -Title "Windows version is out of support ($($caption) $displayVersion)" `
                    -Description "This Windows release stopped receiving security updates on $eos.$esu" `
                    -Evidence "Build $build.$ubr, end of servicing $eos" `
                    -Fix 'Upgrade to a supported release with Windows Update or the Installation Assistant (feature update), or enrol in ESU if available. Servers need an in-place upgrade or migration to a newer Windows Server.' `
                    -Reference 'https://learn.microsoft.com/lifecycle/products/'
            }
            elseif ($left -lt 180) {
                Add-Finding -Category 'Updates' -Severity 'Medium' -Title "Windows version reaches end of support in $left days" `
                    -Description "This release stops receiving security updates on $eos." -Evidence "Build $build.$ubr" `
                    -Fix 'Plan the feature update or server upgrade before the end-of-support date.' -Reference 'https://learn.microsoft.com/lifecycle/products/'
            }
        }
    }

    Invoke-Check 'Windows Update status' {
        $hf = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
        $last = $null
        # Prefer the Windows Update history (covers cumulative updates on newer builds better than Get-HotFix)
        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $count = $searcher.GetTotalHistoryCount()
            if ($count -gt 0) {
                $hist = $searcher.QueryHistory(0, [math]::Min($count, 50)) | Where-Object { $_.ResultCode -eq 2 -and $_.Title -notmatch 'Definition|Security Intelligence' } | Sort-Object Date -Descending
                if ($hist) { $last = @($hist)[0].Date.ToLocalTime() }
                $failed = @($searcher.QueryHistory(0, [math]::Min($count, 50)) | Where-Object { $_.ResultCode -in 4, 5 -and $_.Date -gt $PF.Start.AddDays(-23) })
                if ($failed.Count -gt 0) {
                    Add-Finding -Category 'Updates' -Severity 'Medium' -Title "$($failed.Count) Windows Update installation(s) failed recently" `
                        -Description 'Updates that fail repeatedly leave the machine unpatched and can block later updates.' `
                        -Evidence ($failed | ForEach-Object { '{0:yyyy-MM-dd}  0x{1:X8}  {2}' -f $_.Date, $_.HResult, $_.Title }) `
                        -Fix "1. Run the Windows Update troubleshooter.`n2. Repair the component store: DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow.`n3. If it still fails, reset Windows Update components (stop wuauserv/bits/cryptsvc, rename SoftwareDistribution and catroot2, start services) and retry.`n4. Look up the error code shown above." `
                        -Command "DISM /Online /Cleanup-Image /RestoreHealth`nsfc /scannow"
                }
            }
        }
        catch {}
        if (-not $last -and $hf.Count) { $last = $hf[0].InstalledOn }
        if ($last) {
            $PF.Info['Last update installed'] = $last.ToString('yyyy-MM-dd')
            $age = ((Get-Date) - $last).Days
            if ($age -gt 60) { $sev = 'High' } elseif ($age -gt 35) { $sev = 'Medium' } else { $sev = $null }
            if ($sev) {
                Add-Finding -Category 'Updates' -Severity $sev -Title "No Windows updates installed for $age days" `
                    -Description 'Microsoft releases security updates monthly (second Tuesday). A machine more than a month behind is missing security fixes.' `
                    -Evidence "Last successful update: $($last.ToString('yyyy-MM-dd'))" `
                    -Fix "Open Settings > Windows Update (or sconfig on Server Core) and install all available updates, then reboot. If updates are managed by WSUS/Intune/RMM, check that this machine is checking in and approved updates are being deployed." `
                    -Command 'UsoClient StartInteractiveScan'
            }
        }
        $wu = $svcNames['wuauserv']
        if ($wu -and $wu.StartMode -eq 'Disabled') {
            Add-Finding -Category 'Updates' -Severity 'High' -Title 'Windows Update service is disabled' `
                -Description 'With wuauserv disabled the machine cannot install security updates.' `
                -Evidence "wuauserv StartMode = Disabled" `
                -Fix 'Set the Windows Update service back to Manual (the default) unless updates are deliberately blocked by policy.' `
                -Command 'Set-Service -Name wuauserv -StartupType Manual'
        }
        $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        if ((Get-RegValue $au 'NoAutoUpdate') -eq 1) {
            Add-Finding -Category 'Updates' -Severity 'Medium' -Title 'Automatic updates are turned off by policy' `
                -Description 'The NoAutoUpdate policy is set, so updates only install when someone runs them manually.' `
                -Evidence "$au\NoAutoUpdate = 1" `
                -Fix 'If this was not intentional, remove the policy in Group Policy (Computer Configuration > Administrative Templates > Windows Components > Windows Update) or delete the registry value.' `
                -Command "Remove-ItemProperty -Path '$au' -Name NoAutoUpdate"
        }
        $wsus = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
        if ($wsus) { $PF.Info['Update source'] = "WSUS: $wsus" }
    }

    Invoke-Check 'Pending reboot' {
        $reasons = @()
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Component Based Servicing (updates/features)' }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
        $pfro = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
        if ($pfro -and @($pfro | Where-Object { $_ }).Count -gt 0) { $reasons += 'Pending file rename operations (installers)' }
        $a = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
        $p = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
        if ($a -and $p -and $a -ne $p) { $reasons += "Computer rename ($a -> $p)" }
        if ($reasons.Count) {
            Add-Finding -Category 'System' -Severity 'Medium' -Title 'A reboot is pending' `
                -Description 'Updates or installs are waiting for a restart. Until then fixes are not active and further updates may fail.' `
                -Evidence $reasons -Fix 'Restart the machine at a suitable time.' -Command 'Restart-Computer'
        }
    }

    Invoke-Check 'Uptime' {
        $d = [int]$uptime.TotalDays
        if ($d -gt 60) {
            Add-Finding -Category 'System' -Severity $(if ($d -gt 120) { 'Medium' } else { 'Low' }) -Title "Machine has not been restarted for $d days" `
                -Description 'Long uptimes usually mean monthly updates have not been applied, and memory leaks or stuck handles accumulate.' `
                -Evidence "Last boot: $($os.LastBootUpTime)" -Fix 'Schedule a restart, ideally after installing updates.'
        }
    }

    #endregion

    #region ---------- Event logs ----------

    # Known events: Log, provider regex, id, severity, title, fix. Warnings (level 3) are only reported when listed here.
    $kb = @(
        @{L = 'System'; P = 'Kernel-Power'; I = 41; S = 'High'; T = 'Unexpected restart or power loss (Kernel-Power 41)'; F = "The system restarted without shutting down cleanly. Check for blue screens (BugCheck events), power supply/UPS problems, overheating, or someone holding the power button. If the BugCheck code in the event is 0, suspect power or hardware. Update BIOS, chipset and storage drivers." }
        @{L = 'System'; P = 'EventLog'; I = 6008; S = 'Medium'; T = 'Previous shutdown was unexpected'; F = 'See the Kernel-Power 41 / BugCheck findings for the cause. Check UPS and power, and look for a crash dump in C:\Windows\Minidump.' }
        @{L = 'System'; P = 'WER-SystemErrorReporting|BugCheck'; I = 1001; S = 'High'; T = 'Blue screen crash (BugCheck)'; F = "Open the minidump in C:\Windows\Minidump with WinDbg (!analyze -v) or BlueScreenView to find the faulting driver. Update or roll back that driver, update BIOS/firmware, and test RAM (mdsched.exe) if crashes vary." }
        @{L = 'System'; P = 'Service Control Manager'; I = 7000; S = 'Medium'; T = 'A service failed to start'; F = 'Check the service account password, that the program files still exist, and the service dependencies. If the software was uninstalled, set the service to Disabled or remove it.' }
        @{L = 'System'; P = 'Service Control Manager'; I = 7001; S = 'Medium'; T = 'A service could not start because a dependency failed'; F = 'Fix the dependency service first (see the related 7000/7023 events).' }
        @{L = 'System'; P = 'Service Control Manager'; I = 7009; S = 'Medium'; T = 'A service timed out while starting'; F = 'The service took more than 30 seconds to start. Often caused by slow disks, AV scanning, or a hung dependency. Check the application, or set it to Automatic (Delayed Start).' }
        @{L = 'System'; P = 'Service Control Manager'; I = 7023; S = 'Medium'; T = 'A service stopped with an error'; F = 'Check the application log for the service at the same time, update or repair the application.' }
        @{L = 'System'; P = 'Service Control Manager'; I = 7024; S = 'Medium'; T = 'A service stopped with a service-specific error'; F = 'Check the vendor documentation for the error code and the application log.' }
        @{L = 'System'; P = 'Service Control Manager'; I = 7031; S = 'Medium'; T = 'A service crashed and was restarted'; F = 'The service terminated unexpectedly. Look for matching Application Error (1000) events, update the application, and check its own logs.' }
        @{L = 'System'; P = 'Service Control Manager'; I = 7034; S = 'Medium'; T = 'A service terminated unexpectedly'; F = 'Look for matching Application Error (1000) events, update or repair the application.' }
        @{L = 'System'; P = 'Service Control Manager'; I = 7026; S = 'Low'; T = 'Boot-start drivers failed to load'; F = 'Usually leftover drivers from removed software. Identify the driver named in the event and remove the software or the driver service.' }
        @{L = 'System'; P = 'DistributedCOM'; I = 10016; S = 'Info'; T = 'DCOM permission warnings (10016)'; F = 'Microsoft documents these as expected and safe to ignore unless a specific application is failing.' }
        @{L = 'System'; P = 'DistributedCOM'; I = 10010; S = 'Low'; T = 'DCOM server did not register in time (10010)'; F = 'Usually harmless. If a specific app is failing, update or repair it.' }
        @{L = 'System'; P = 'storahci|stornvme|storport|iaStor|LSI|megasas|disk'; I = 129; S = 'Medium'; T = 'Storage controller reset (event 129)'; F = 'The storage driver reset a device that stopped responding. Update storage controller drivers and firmware, check cables/backplane, and check disk health. On VMs, check host storage latency.' }
        @{L = 'System'; P = '^disk$|Microsoft-Windows-Disk'; I = 153; S = 'Medium'; T = 'Disk I/O was retried (event 153)'; F = 'The disk did not respond in time and the request was retried. Check disk health (SMART), cables, controller drivers and firmware.' }
        @{L = 'System'; P = '^disk$|Microsoft-Windows-Disk'; I = 51; S = 'High'; T = 'Disk error during paging (event 51)'; F = 'Data could not be written or read reliably. Back up now, check disk health and cables, and plan to replace the disk if it continues.' }
        @{L = 'System'; P = '^disk$|Microsoft-Windows-Disk'; I = 7; S = 'Critical'; T = 'Bad block on disk (event 7)'; F = 'The disk has bad sectors. Back up immediately and replace the disk.' }
        @{L = 'System'; P = '^disk$|Microsoft-Windows-Disk'; I = 11; S = 'High'; T = 'Disk controller error (event 11)'; F = 'Check cables, controller drivers/firmware and disk health. Back up the data.' }
        @{L = 'System'; P = 'Ntfs'; I = 55; S = 'High'; T = 'File system corruption detected (NTFS 55)'; F = 'Run chkdsk on the affected volume. A scan is safe online; repairs need a restart for the system drive.'; C = 'chkdsk C: /scan' }
        @{L = 'System'; P = 'Ntfs'; I = 98; S = 'High'; T = 'Volume needs repair (NTFS 98)'; F = 'Run chkdsk on the volume named in the event.'; C = 'chkdsk C: /scan' }
        @{L = 'System'; P = 'Ntfs'; I = 140; S = 'Medium'; T = 'Delayed write failed (NTFS 140)'; F = 'Data could not be flushed to disk. Check disk health, storage drivers and, on VMs, the host storage.' }
        @{L = 'System'; P = '^disk$|Microsoft-Windows-Disk'; I = 157; S = 'Medium'; T = 'Disk was surprise removed (event 157)'; F = 'A disk disconnected unexpectedly. Check USB/SAS cables, power management and controller drivers.' }
        @{L = 'System'; P = 'DNS Client'; I = 1014; S = 'Low'; T = 'DNS name resolution timeouts'; F = 'Configured DNS servers are slow or unreachable. Check the DNS servers set on the network adapter.' }
        @{L = 'System'; P = 'Tcpip'; I = 4199; S = 'High'; T = 'IP address conflict detected'; F = 'Another device is using the same IP address. Find it by the MAC address in the event and fix the static IP or DHCP reservation.' }
        @{L = 'System'; P = 'Tcpip'; I = 4227; S = 'Medium'; T = 'TCP port exhaustion warnings (4227)'; F = 'An application is opening outbound connections faster than they close. Find it with netstat -ano and fix the application, or increase the dynamic port range.'; C = 'netstat -ano | findstr TIME_WAIT' }
        @{L = 'System'; P = 'NETLOGON'; I = 5719; S = 'High'; T = 'No domain controller available (NETLOGON 5719)'; F = 'The machine could not reach a DC. Check DNS points only at domain DNS servers, network connectivity and time sync. If it only happens at boot, it may be the network starting late.' }
        @{L = 'System'; P = 'NETLOGON'; I = 3210; S = 'High'; T = 'Secure channel to the domain failed (NETLOGON 3210)'; F = 'The computer account trust is broken. Repair it with Test-ComputerSecureChannel -Repair (as a domain admin) or rejoin the domain.'; C = 'Test-ComputerSecureChannel -Repair -Credential (Get-Credential)' }
        @{L = 'System'; P = 'GroupPolicy'; I = 1129; S = 'Medium'; T = 'Group Policy failed: no network connection to a DC'; F = 'Check DNS settings and network at startup. Enable "Always wait for the network at computer startup and logon" if it happens only at boot.' }
        @{L = 'System'; P = 'GroupPolicy'; I = 1058; S = 'Medium'; T = 'Group Policy could not read gpt.ini from SYSVOL'; F = 'Check SYSVOL replication and access to \\domain\SYSVOL. Run gpupdate /force after fixing.'; C = 'gpupdate /force' }
        @{L = 'System'; P = 'GroupPolicy'; I = 1030; S = 'Medium'; T = 'Group Policy processing failed'; F = 'Run gpresult /h report.html and check DNS and DC connectivity.'; C = 'gpresult /h "$env:TEMP\gp.html"' }
        @{L = 'System'; P = 'GroupPolicy'; I = 1096; S = 'Medium'; T = 'Group Policy registry.pol is corrupt'; F = 'Delete C:\Windows\System32\GroupPolicy\Machine\Registry.pol and run gpupdate /force.'; C = "Remove-Item C:\Windows\System32\GroupPolicy\Machine\Registry.pol; gpupdate /force" }
        @{L = 'System'; P = 'WHEA-Logger'; I = 18; S = 'Critical'; T = 'Fatal hardware error (WHEA 18)'; F = 'A hardware component (usually CPU or memory) reported an uncorrectable error. Update BIOS, check cooling, run vendor diagnostics, and replace the faulty part.' }
        @{L = 'System'; P = 'WHEA-Logger'; I = 1; S = 'Critical'; T = 'Fatal hardware error (WHEA 1)'; F = 'Run hardware vendor diagnostics, update BIOS/firmware, check cooling.' }
        @{L = 'System'; P = 'WHEA-Logger'; I = 17; S = 'Medium'; T = 'Corrected hardware errors (WHEA 17, usually PCIe)'; F = 'Often PCIe link errors. Update chipset drivers and BIOS; disabling PCIe ASPM can help. Check the device named in the event.' }
        @{L = 'System'; P = 'WHEA-Logger'; I = 19; S = 'Medium'; T = 'Corrected CPU/cache errors (WHEA 19)'; F = 'Update BIOS, remove overclocking, check cooling. Repeated errors suggest a failing CPU.' }
        @{L = 'System'; P = 'WHEA-Logger'; I = 47; S = 'Medium'; T = 'Corrected memory errors (WHEA 47)'; F = 'Run memory diagnostics (mdsched.exe or vendor tools) and replace the faulty DIMM.' }
        @{L = 'System'; P = 'Resource-Exhaustion-Detector'; I = 2004; S = 'High'; T = 'Low virtual memory (Resource Exhaustion 2004)'; F = 'The event lists the processes using the most memory. Fix or restart the leaking process, add RAM, or enlarge the page file.' }
        @{L = 'System'; P = '^srv$|Srv'; I = 2019; S = 'High'; T = 'Non-paged pool exhausted (Srv 2019)'; F = 'A driver is leaking kernel memory. Use poolmon to find the tag, and update the driver (often AV, backup or NIC drivers).' }
        @{L = 'System'; P = '^srv$|Srv'; I = 2020; S = 'High'; T = 'Paged pool exhausted (Srv 2020)'; F = 'A driver is leaking kernel memory. Use poolmon to find the tag and update the driver.' }
        @{L = 'System'; P = 'Schannel'; I = 36887; S = 'Low'; T = 'TLS fatal alerts received (Schannel 36887)'; F = 'Usually a client or server refusing an old TLS version or cipher. Only investigate if an application is failing to connect.' }
        @{L = 'System'; P = 'Schannel'; I = 36874; S = 'Low'; T = 'TLS connection with unsupported protocol (Schannel 36874)'; F = 'A client tried an old TLS version. Find and update the client.' }
        @{L = 'System'; P = 'Schannel'; I = 36882; S = 'Medium'; T = 'Certificate problem with TLS (Schannel 36882)'; F = 'Check the certificate used by the service (expiry, private key, chain).' }
        @{L = 'System'; P = 'TPM-WMI'; I = 1801; S = 'Medium'; T = 'Secure Boot certificates need updating (TPM-WMI 1801)'; F = 'The Microsoft Secure Boot certificates from 2011 expire in 2026. Install the latest cumulative update and the OEM BIOS update so the 2023 certificates can be applied.'; R = 'https://support.microsoft.com/topic/windows-devices-for-businesses-and-organizations-with-it-managed-updates-e2b43f9f-b424-42df-bc6a-8476db65ab2f' }
        @{L = 'System'; P = 'TPM-WMI'; I = 1796; S = 'Medium'; T = 'Secure Boot certificate update failed (TPM-WMI 1796)'; F = 'Update the BIOS/UEFI firmware from the manufacturer and install the latest cumulative update, then reboot.' }
        @{L = 'System'; P = 'Kernel-PnP'; I = 219; S = 'Low'; T = 'Driver failed to load for a device (Kernel-PnP 219)'; F = 'Usually harmless at boot. If a device is not working, reinstall its driver.' }
        @{L = 'System'; P = 'EventLog'; I = 104; S = 'Low'; T = 'An event log was cleared'; F = 'Confirm who cleared the log and why. Unexpected clearing can indicate an attacker covering tracks.' }
        @{L = 'System'; P = 'User Profile'; I = 1511; S = 'High'; T = 'User logged on with a temporary profile'; F = 'The profile could not be loaded. Check HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList for a .bak duplicate SID key and fix the ProfileImagePath/State values.' }
        @{L = 'Application'; P = 'User Profile'; I = 1511; S = 'High'; T = 'User logged on with a temporary profile'; F = 'Check HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList for a duplicate .bak key and fix it.' }
        @{L = 'Application'; P = 'User Profile'; I = 1530; S = 'Info'; T = 'Registry handles left open at logoff (1530)'; F = 'Normal behaviour; Windows cleans these up. Ignore unless profiles fail to unload.' }
        @{L = 'Application'; P = 'VSS'; I = 8193; S = 'Medium'; T = 'Volume Shadow Copy error (VSS 8193)'; F = 'Backups and restore points may fail. Run vssadmin list writers to find failed writers and restart the related service.'; C = 'vssadmin list writers' }
        @{L = 'Application'; P = 'VSS'; I = 12289; S = 'Medium'; T = 'Volume Shadow Copy error (VSS 12289)'; F = 'Check vssadmin list writers and vssadmin list providers. Third-party VSS providers from old backup software are a common cause.'; C = 'vssadmin list writers' }
        @{L = 'Application'; P = 'VSS'; I = 13; S = 'Medium'; T = 'Volume Shadow Copy error (VSS 13)'; F = 'Check COM+ and the VSS service; run vssadmin list writers.'; C = 'vssadmin list writers' }
        @{L = 'Application'; P = 'MsiInstaller'; I = 11708; S = 'Low'; T = 'Software installation failed (MsiInstaller 11708)'; F = 'Retry the installation with logging (msiexec /i package.msi /l*v log.txt) and check the log.' }
        @{L = 'Application'; P = 'MSExchangeTransport'; I = 15004; S = 'High'; T = 'Exchange back pressure: resources low (15004)'; F = 'Exchange stopped accepting mail because disk space or memory is low on the transport server. Free disk space on the queue database drive.' }
        @{L = 'Application'; P = 'MSExchangeTransport'; I = 15006; S = 'High'; T = 'Exchange back pressure: disk space critical (15006)'; F = 'Free disk space on the transport queue drive immediately; mail flow is stopped.' }
        @{L = 'Application'; P = 'ESENT'; I = 455; S = 'Low'; T = 'ESENT database log file error (455)'; F = 'Often a missing folder for an app database (e.g. TileDataLayer). Usually harmless; recreate the folder named in the event if an app is failing.' }
        @{L = 'Security'; P = 'Eventlog'; I = 1102; S = 'Medium'; T = 'The Security log was cleared'; F = 'Confirm who cleared the Security log. Unexpected clearing can indicate an attacker covering tracks.' }
        @{L = 'Directory Service'; P = 'NTDS Replication'; I = 2042; S = 'Critical'; T = 'AD replication stopped longer than tombstone lifetime (2042)'; F = 'This DC has not replicated for longer than the tombstone lifetime. Do not force replication; follow Microsoft guidance (usually demote and rebuild the DC).'; R = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8614' }
        @{L = 'Directory Service'; P = 'NTDS Replication'; I = 1988; S = 'High'; T = 'Lingering objects detected (1988)'; F = 'Remove lingering objects with repadmin /removelingeringobjects or the Lingering Object Liquidator.' }
        @{L = 'Directory Service'; P = 'NTDS KCC'; I = 1311; S = 'High'; T = 'KCC cannot build a replication topology (1311)'; F = 'Check site links and that all DCs are reachable. Run repadmin /replsummary.'; C = 'repadmin /replsummary' }
        @{L = 'Directory Service'; P = 'NTDS (KCC|General)'; I = 1925; S = 'High'; T = 'Replication link could not be established (1925)'; F = 'Check DNS and network connectivity between DCs; run dcdiag /test:dns.'; C = 'dcdiag /test:dns' }
        @{L = 'Directory Service'; P = 'NTDS Replication'; I = 1864; S = 'High'; T = 'DC has not replicated with partners recently (1864)'; F = 'Run repadmin /showrepl to find failing partners and fix connectivity/DNS.'; C = 'repadmin /showrepl' }
        @{L = 'DFS Replication'; P = 'DFSR'; I = 2213; S = 'High'; T = 'DFSR stopped after a dirty shutdown (2213)'; F = 'Replication is paused on this volume. The event contains a wmic command with the volume GUID to resume replication; run it after confirming there is a good copy of the data.' }
        @{L = 'DFS Replication'; P = 'DFSR'; I = 4012; S = 'Critical'; T = 'DFSR stopped replicating: content is stale (4012)'; F = 'This member has not replicated for longer than MaxOfflineTimeInDays. SYSVOL/DFS data is out of date; perform an authoritative/non-authoritative sync as per Microsoft guidance.' }
        @{L = 'DFS Replication'; P = 'DFSR'; I = 5002; S = 'High'; T = 'DFSR cannot talk to a partner (5002)'; F = 'Check network, firewall and DNS between DFSR members.' }
        @{L = 'File Replication Service'; P = 'NtFrs'; I = 13568; S = 'High'; T = 'FRS journal wrap (13568)'; F = 'FRS is deprecated. Migrate SYSVOL replication to DFSR (dfsrmig).' }
        @{L = 'Microsoft-Windows-Windows Defender/Operational'; P = 'Defender'; I = 1116; S = 'High'; T = 'Microsoft Defender detected malware'; F = 'Review the threat in Windows Security > Protection history, confirm it was removed, and run a full scan.'; C = 'Start-MpScan -ScanType FullScan' }
        @{L = 'Microsoft-Windows-Windows Defender/Operational'; P = 'Defender'; I = 1118; S = 'High'; T = 'Defender failed to remediate malware'; F = 'Run an offline scan (Start-MpWDOScan) and investigate the file.'; C = 'Start-MpWDOScan' }
        @{L = 'Microsoft-Windows-Windows Defender/Operational'; P = 'Defender'; I = 2001; S = 'Medium'; T = 'Defender signature update failed'; F = 'Check internet/WSUS access and run Update-MpSignature.'; C = 'Update-MpSignature' }
        @{L = 'Microsoft-Windows-Windows Defender/Operational'; P = 'Defender'; I = 5001; S = 'High'; T = 'Defender real-time protection was disabled'; F = 'Turn real-time protection back on unless another antivirus is in use.' }
    )
    $kbIndex = @{}
    foreach ($k in $kb) { $kbIndex["$($k.L)|$($k.I)"] = @($kbIndex["$($k.L)|$($k.I)"]) + $k | Where-Object { $_ } }

    $logs = @('System', 'Application', 'Microsoft-Windows-Windows Defender/Operational')
    if ($isDC) { $logs += 'Directory Service', 'DFS Replication', 'File Replication Service' }
    if ($PF.Roles -contains 'DNS Server') { $logs += 'DNS Server' }

    Invoke-Check 'Event logs (errors and known issues)' {
        foreach ($log in $logs) {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 1, 2, 3; StartTime = $PF.Start } -MaxEvents 20000 -ErrorAction SilentlyContinue)
            if (-not $events.Count) { continue }
            $groups = @{}
            $crashes = @{}
            foreach ($e in $events) {
                $known = $null
                foreach ($k in @($kbIndex["$log|$($e.Id)"])) { if ($k -and $e.ProviderName -match $k.P) { $known = $k; break } }
                if (-not $known -and $e.Level -eq 3) { continue }
                # Application crashes and hangs are grouped by program instead
                if ($log -eq 'Application' -and $e.Id -in 1000, 1002 -and $e.ProviderName -match 'Application (Error|Hang)') {
                    $app = "$($e.Properties[0].Value)"
                    $key = "$($e.Id)|$app"
                    if (-not $crashes.ContainsKey($key)) { $crashes[$key] = @{ Count = 0; Last = $e.TimeCreated; Module = "$($e.Properties[3].Value)"; Id = $e.Id; App = $app } }
                    $crashes[$key].Count++
                    continue
                }
                $key = "$($e.ProviderName)|$($e.Id)"
                if (-not $groups.ContainsKey($key)) { $groups[$key] = @{ Count = 0; First = $e; Last = $e.TimeCreated; Known = $known; Samples = New-Object System.Collections.Generic.List[object] } }
                $g = $groups[$key]
                $g.Count++
                if ($g.Samples.Count -lt 3) { $g.Samples.Add($e) }
            }
            foreach ($key in $groups.Keys) {
                $g = $groups[$key]
                $e = $g.First
                $samples = foreach ($s in $g.Samples) {
                    $msg = "$($s.Message)" -replace '\s+', ' '
                    if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }
                    '{0:yyyy-MM-dd HH:mm}  {1}' -f $s.TimeCreated, $msg
                }
                $ev = @("Log: $log   Source: $($e.ProviderName)   Event ID: $($e.Id)   Occurrences: $($g.Count)   Last: $($g.Last.ToString('yyyy-MM-dd HH:mm'))") + $samples
                if ($g.Known) {
                    $k = $g.Known
                    Add-Finding -Category 'Event logs' -Severity $k.S -Title "$($k.T) - $($g.Count)x" -Description "Seen $($g.Count) time(s) in the $log log in the last $Days days." `
                        -Evidence $ev -Fix $k.F -Command $(if ($k.C) { $k.C } else { '' }) -Reference $(if ($k.R) { $k.R } else { "https://www.google.com/search?q=event+id+$($e.Id)+$([uri]::EscapeDataString($e.ProviderName))" })
                }
                elseif ($g.Count -ge 3 -or $e.Level -eq 1) {
                    $sev = if ($e.Level -eq 1) { 'High' } elseif ($g.Count -ge 50) { 'Medium' } else { 'Low' }
                    Add-Finding -Category 'Event logs' -Severity $sev -Title "Recurring error: $($e.ProviderName) event $($e.Id) - $($g.Count)x" `
                        -Description "This error is not in the Painfree knowledge base yet but repeats in the $log log." `
                        -Evidence $ev -Fix "Read the message above for the component involved. Search the event ID and source, check the related application's own logs, and update or repair the component. Recurring errors from removed software can be fixed by uninstalling leftovers." `
                        -Reference "https://www.google.com/search?q=event+id+$($e.Id)+$([uri]::EscapeDataString($e.ProviderName))"
                }
            }
            # Application crashes grouped by program
            foreach ($key in $crashes.Keys) {
                $c = $crashes[$key]
                if ($c.Count -lt 2) { continue }
                $what = if ($c.Id -eq 1000) { 'crashed' } else { 'stopped responding' }
                $sev = if ($c.Count -ge 10) { 'Medium' } else { 'Low' }
                Add-Finding -Category 'Applications' -Severity $sev -Title "$($c.App) $what $($c.Count) times" `
                    -Description "The program $what repeatedly in the last $Days days." `
                    -Evidence @("Program: $($c.App)", "Faulting module: $($c.Module)", "Last: $($c.Last.ToString('yyyy-MM-dd HH:mm'))") `
                    -Fix "Update the program to the latest version or repair/reinstall it. If the faulting module is a third-party DLL (shell extensions, AV, overlays), update or remove that software. If the module is ntdll.dll or KERNELBASE.dll the fault is in the program itself."
            }
        }
    }

    Invoke-Check 'Failed logons (Security log)' {
        $fails = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-[math]::Min($Days, 7)) } -MaxEvents 20000 -ErrorAction SilentlyContinue)
        if ($fails.Count -ge 50) {
            $byAcct = $fails | Group-Object { "$($_.Properties[6].Value)\$($_.Properties[5].Value)" } | Sort-Object Count -Descending | Select-Object -First 10
            $bySrc = $fails | Group-Object { "$($_.Properties[19].Value)" } | Sort-Object Count -Descending | Select-Object -First 10
            $sev = if ($fails.Count -ge 1000) { 'High' } else { 'Medium' }
            Add-Finding -Category 'Security' -Severity $sev -Title "$($fails.Count) failed logon attempts" `
                -Description 'Many failed logons can mean a password-guessing attack (often RDP or SMB exposed to the internet), or a service or mapped drive still using an old password.' `
                -Evidence (@('Top accounts:') + ($byAcct | ForEach-Object { "  $($_.Count)  $($_.Name)" }) + 'Top source addresses:' + ($bySrc | ForEach-Object { "  $($_.Count)  $(if ($_.Name -and $_.Name -ne '-') { $_.Name } else { '(local)' })" })) `
                -Fix "1. If source addresses are public IPs, do not expose RDP/SMB to the internet; use a VPN or RD Gateway and enable account lockout.`n2. If the source is internal, check that machine for services, scheduled tasks or mapped drives using an old password.`n3. Make sure an account lockout policy is in place."
        }
    }

    #endregion

    #region ---------- Hardware, disks and performance ----------

    Invoke-Check 'Disk space' {
        foreach ($d in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
            if (-not $d.Size) { continue }
            $pct = [math]::Round($d.FreeSpace / $d.Size * 100, 1)
            $sev = $null
            if ($pct -lt 5 -or $d.FreeSpace -lt 2GB) { $sev = 'Critical' } elseif ($pct -lt 10 -or $d.FreeSpace -lt 5GB) { $sev = 'High' } elseif ($pct -lt 15) { $sev = 'Medium' }
            if ($sev) {
                Add-Finding -Category 'Disk' -Severity $sev -Title "Drive $($d.DeviceID) is low on space ($pct% free)" `
                    -Description 'Low free space causes failed updates, crashes, database and backup failures, and poor performance.' `
                    -Evidence "$($d.DeviceID) $(Format-Size $d.FreeSpace) free of $(Format-Size $d.Size)" `
                    -Fix "1. Run Disk Cleanup (cleanmgr) including 'Clean up system files', or Storage Sense on Windows 10/11.`n2. Clean the component store: DISM /Online /Cleanup-Image /StartComponentCleanup.`n3. See the 'Disk clean-up opportunities' finding (if any) for large folders.`n4. Use a tool like WizTree or TreeSize to find large files; move or archive them, or extend the volume." `
                    -Command 'cleanmgr /sageset:1 ; cleanmgr /sagerun:1'
            }
        }
    }

    Invoke-Check 'Disk health (SMART / storage)' {
        $pd = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)
        foreach ($d in $pd) {
            if ($d.HealthStatus -and "$($d.HealthStatus)" -ne 'Healthy') {
                Add-Finding -Category 'Disk' -Severity 'Critical' -Title "Physical disk '$($d.FriendlyName)' health is $($d.HealthStatus)" `
                    -Description 'Windows reports this disk as unhealthy. It may fail soon.' `
                    -Evidence "Disk: $($d.FriendlyName)  Serial: $($d.SerialNumber)  Media: $($d.MediaType)  Status: $($d.OperationalStatus)" `
                    -Fix 'Back up the data now and replace the disk. On RAID, check the controller utility and replace the failed member.'
            }
            $rc = $d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
            if ($rc) {
                if ($rc.Wear -ge 90) {
                    Add-Finding -Category 'Disk' -Severity 'High' -Title "SSD '$($d.FriendlyName)' is $($rc.Wear)% worn" -Description 'The SSD is near the end of its rated write endurance.' `
                        -Evidence "Wear: $($rc.Wear)%" -Fix 'Plan to replace the SSD and make sure backups are current.'
                }
                if ($rc.ReadErrorsUncorrected -gt 0 -or $rc.WriteErrorsUncorrected -gt 0) {
                    Add-Finding -Category 'Disk' -Severity 'High' -Title "Disk '$($d.FriendlyName)' has uncorrected read/write errors" -Description 'The disk has failed to read or write data.' `
                        -Evidence "Uncorrected read errors: $($rc.ReadErrorsUncorrected)  write errors: $($rc.WriteErrorsUncorrected)" -Fix 'Back up the data and replace the disk.'
                }
                if ($rc.Temperature -ge 65) {
                    Add-Finding -Category 'Disk' -Severity 'Medium' -Title "Disk '$($d.FriendlyName)' is running hot ($($rc.Temperature) C)" -Description 'High temperatures shorten disk life and can cause throttling.' `
                        -Evidence "Temperature: $($rc.Temperature) C (max $($rc.TemperatureMax) C)" -Fix 'Check airflow, fans and dust in the case or server.'
                }
            }
        }
        $smart = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | Where-Object PredictFailure)
        foreach ($s in $smart) {
            Add-Finding -Category 'Disk' -Severity 'Critical' -Title 'SMART predicts a disk failure' -Description 'The drive firmware is reporting that failure is imminent.' `
                -Evidence $s.InstanceName -Fix 'Back up immediately and replace the disk.'
        }
        foreach ($v in @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' | Where-Object { $_.DriveLetter })) {
            $q = & fsutil dirty query $v.DriveLetter 2>$null
            if ("$q" -match 'is Dirty|is dirty') {
                Add-Finding -Category 'Disk' -Severity 'High' -Title "Volume $($v.DriveLetter) is marked dirty" -Description 'NTFS has flagged the volume as possibly corrupt; chkdsk will run at next boot.' `
                    -Evidence "$q" -Fix 'Run chkdsk on the volume and restart when convenient.' -Command "chkdsk $($v.DriveLetter) /scan"
            }
        }
    }

    Invoke-Check 'Memory, CPU and page file' {
        $total = [double]$os.TotalVisibleMemorySize * 1KB
        $free = [double]$os.FreePhysicalMemory * 1KB
        $usedPct = [math]::Round((1 - $free / $total) * 100)
        $top = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 8 | ForEach-Object { '{0,-30} {1,10}' -f $_.ProcessName, (Format-Size $_.WorkingSet64) }
        if ($usedPct -ge 90) {
            Add-Finding -Category 'Performance' -Severity 'Medium' -Title "Memory is $usedPct% used" -Description 'The system is close to running out of physical memory, which causes heavy paging and slowness.' `
                -Evidence (@("$(Format-Size ($total - $free)) used of $(Format-Size $total)", 'Top processes by memory:') + $top) `
                -Fix 'Close or fix the processes using the most memory, check for memory leaks (memory growing over days), or add RAM. On SQL/Exchange servers, high usage can be normal; set max server memory instead.'
        }
        $minRam = if ($isServer) { 4GB } else { 8GB }
        if ($total -lt ($minRam * 0.95)) {
            Add-Finding -Category 'Performance' -Severity 'Low' -Title "Only $(Format-Size $total) of RAM installed" -Description "Under $(Format-Size $minRam) is tight for current Windows versions and typical workloads." `
                -Evidence "Installed: $(Format-Size $total)" -Fix 'Add more memory if the machine feels slow or pages heavily.'
        }
        $loads = @()
        for ($i = 0; $i -lt 3; $i++) { $loads += (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average; Start-Sleep -Milliseconds 700 }
        $avg = [math]::Round(($loads | Measure-Object -Average).Average)
        if ($avg -ge 90) {
            $cpuTop = Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 | ForEach-Object { '{0,-30} {1,10:N0}s CPU' -f $_.ProcessName, $_.CPU }
            Add-Finding -Category 'Performance' -Severity 'Medium' -Title "CPU is busy ($avg% during the scan)" -Description 'Sustained high CPU makes the machine slow.' `
                -Evidence (@('Processes with most CPU time since start:') + $cpuTop) -Fix 'Check Task Manager / Resource Monitor for the busy process. Common causes: AV scans, Windows Update, search indexing, runaway applications.'
        }
        $pf = @(Get-CimInstance Win32_PageFileUsage)
        if (-not $pf.Count -and -not $cs.AutomaticManagedPagefile) {
            Add-Finding -Category 'Performance' -Severity 'Medium' -Title 'No page file configured' -Description 'Without a page file Windows cannot write crash dumps and applications can fail with out-of-memory errors even when RAM is free.' `
                -Evidence 'Win32_PageFileUsage returned nothing' -Fix 'Enable "Automatically manage paging file size" in System Properties > Advanced > Performance > Virtual memory.'
        }
        foreach ($p in $pf) {
            if ($p.AllocatedBaseSize -gt 0 -and $p.PeakUsage / $p.AllocatedBaseSize -ge 0.85) {
                Add-Finding -Category 'Performance' -Severity 'Medium' -Title 'Page file has been nearly full' -Description 'Peak page file use reached its limit, which leads to out-of-memory errors.' `
                    -Evidence "$($p.Name): peak $($p.PeakUsage) MB of $($p.AllocatedBaseSize) MB" -Fix 'Let Windows manage the page file size, increase it, or add RAM.'
            }
        }
        if ($isServer) {
            $scheme = & powercfg /getactivescheme 2>$null
            if ("$scheme" -match 'Balanced|Power saver') {
                Add-Finding -Category 'Performance' -Severity 'Low' -Title 'Server is using the Balanced power plan' -Description 'Balanced can lower CPU clock speeds and add latency on servers. Microsoft recommends High performance for most server workloads.' `
                    -Evidence "$scheme" -Fix 'Switch to the High performance plan (and check the BIOS power profile is set to performance).' -Command 'powercfg /setactive SCHEME_MIN'
            }
        }
    }

    Invoke-Check 'Device problems (Device Manager)' {
        $codes = @{ 1 = 'Not configured correctly'; 3 = 'Driver may be corrupted'; 10 = 'Device cannot start'; 12 = 'Not enough resources'; 14 = 'Needs restart'; 18 = 'Reinstall drivers'; 19 = 'Registry configuration damaged'; 21 = 'Being removed'; 24 = 'Not present or not working'; 28 = 'Drivers not installed'; 31 = 'Not working properly'; 32 = 'Driver disabled'; 37 = 'Driver failed to initialise'; 39 = 'Driver missing or corrupt'; 41 = 'Driver loaded but device not found'; 43 = 'Device reported a problem'; 48 = 'Driver blocked (incompatible)'; 52 = 'Driver signature cannot be verified' }
        $bad = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -notin 22, 45 })
        if ($bad.Count) {
            Add-Finding -Category 'Hardware' -Severity 'Medium' -Title "$($bad.Count) device(s) with driver problems" -Description 'These devices show an error in Device Manager.' `
                -Evidence ($bad | ForEach-Object { "Code $($_.ConfigManagerErrorCode) ($($codes[[int]$_.ConfigManagerErrorCode])): $($_.Name)  [$($_.PNPDeviceID)]" }) `
                -Fix 'Install or update the driver from the hardware manufacturer (not just Windows Update), or uninstall the device in Device Manager and scan for hardware changes. Code 28 means no driver is installed.' `
                -Command 'pnputil /scan-devices'
        }
    }

    Invoke-Check 'Crash dumps' {
        $mini = @(Get-ChildItem "$env:SystemRoot\Minidump\*.dmp" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        $recent = @($mini | Where-Object { $_.LastWriteTime -gt $PF.Start.AddDays(-23) })
        $full = Get-Item "$env:SystemRoot\MEMORY.DMP" -ErrorAction SilentlyContinue
        if ($recent.Count) {
            Add-Finding -Category 'Crashes' -Severity 'High' -Title "$($recent.Count) blue screen crash dump(s) in the last 30 days" -Description 'Windows has crashed (BSOD) recently.' `
                -Evidence ($recent | Select-Object -First 15 | ForEach-Object { '{0:yyyy-MM-dd HH:mm}  {1}' -f $_.LastWriteTime, $_.FullName }) `
                -Fix "Analyse the dump with WinDbg (File > Open crash dump, then !analyze -v) or BlueScreenView to find the faulting driver. Update or remove that driver, update BIOS/firmware, and test memory with mdsched.exe."
        }
        if ($full) {
            Add-Finding -Category 'Crashes' -Severity 'Low' -Title "Full memory dump present ($(Format-Size $full.Length))" -Description 'A full crash dump from a previous blue screen is using disk space.' `
                -Evidence "$($full.FullName)  $($full.LastWriteTime)" -Fix 'Analyse it if the crash is not yet understood, then delete it to free space.' -Command "Remove-Item '$($full.FullName)'"
        }
        $dumpCfg = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' 'CrashDumpEnabled'
        if ($dumpCfg -eq 0) {
            Add-Finding -Category 'Crashes' -Severity 'Low' -Title 'Crash dumps are disabled' -Description 'If Windows blue-screens there will be no dump file to diagnose the cause.' `
                -Evidence 'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpEnabled = 0' -Fix 'Enable "Automatic memory dump" in System Properties > Advanced > Startup and Recovery.' `
                -Command "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -Value 7"
        }
        # Application crash reports collected by Windows Error Reporting
        $wer = @(Get-ChildItem "$env:ProgramData\Microsoft\Windows\WER\ReportArchive", "$env:ProgramData\Microsoft\Windows\WER\ReportQueue" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $PF.Start -and $_.Name -match '^(AppCrash|AppHang|Critical|Kernel)_' })
        if ($wer.Count -ge 5) {
            $byApp = $wer | Group-Object { ($_.Name -split '_')[0..1] -join ' ' } | Sort-Object Count -Descending | Select-Object -First 10
            Add-Finding -Category 'Crashes' -Severity 'Low' -Title "$($wer.Count) error reports collected by Windows Error Reporting" -Description 'Programs that crashed or hung recently, according to WER.' `
                -Evidence ($byApp | ForEach-Object { "$($_.Count)x  $($_.Name)" }) -Fix 'Update or reinstall the programs listed. See the Applications findings for details.'
        }
    }

    #endregion

    #region ---------- Services and scheduled tasks ----------

    Invoke-Check 'Automatic services not running' {
        # Services that are set to Automatic but stop by design
        $ignore = 'gupdate|gupdatem|edgeupdate|edgeupdatem|MicrosoftEdgeElevationService|GoogleUpdater|sppsvc|RemoteRegistry|MapsBroker|tiledatamodelsvc|CDPSvc|ShellHWDetection|WbioSrvc|TrustedInstaller|stisvc|BITS|wuauserv|UsoSvc|DoSvc|WaaSMedicSvc|clr_optimization|NetTcpPortSharing|sedsvc|AGMService|AGSService|OneSyncSvc|CDPUserSvc|WpnUserService|Intel\(R\) TPM|SysMain|Dnscache|IaasVmProvider|DPS|WinDefend|MsMpSvc|Sense|wscsvc|gpsvc|tzautoupdate|CertPropSvc|AdobeARMservice|ClickToRunSvc|VSStandardCollectorService|ssh-agent|osrss|SgrmBroker|WSearch|cbdhsvc|camsvc|InventorySvc|DcpSvc'
        $stopped = @($services | Where-Object {
                $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' -and $_.Name -notmatch "^($ignore)" -and -not $_.DelayedAutoStart -and
                -not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\TriggerInfo")
            })
        $critical = 'MSSQL|SQLAgent|MSExchange|W3SVC|WAS|NTDS|DNS|DHCPServer|Netlogon|LanmanServer|LanmanWorkstation|vmms|Spooler|EventLog|Winmgmt|DFSR|IsmServ|kdc|W32Time|WsusService|Veeam|BackupExec'
        foreach ($s in $stopped) {
            $sev = if ($s.Name -match "^($critical)") { 'High' } else { 'Medium' }
            $exe = Get-CommandPath $s.PathName
            $missing = $exe -and -not (Test-Path -LiteralPath $exe)
            $fix = if ($missing) { "The program file for this service no longer exists, so it is probably left over from uninstalled software. Disable it, or remove it with 'sc.exe delete $($s.Name)' after confirming it is not needed." }
            else { "Start the service and check the System log for 7000-series errors if it stops again. If it is not needed, set it to Manual or Disabled." }
            Add-Finding -Category 'Services' -Severity $sev -Title "Automatic service '$($s.DisplayName)' is not running" `
                -Description 'This service is set to start automatically but is currently stopped.' `
                -Evidence @("Name: $($s.Name)", "State: $($s.State)  Exit code: $($s.ExitCode)", "Account: $($s.StartName)", "Path: $($s.PathName)", $(if ($missing) { 'Program file is MISSING' })) `
                -Fix $fix -Command $(if ($missing) { "Set-Service -Name '$($s.Name)' -StartupType Disabled" } else { "Start-Service -Name '$($s.Name)'" })
        }
    }

    Invoke-Check 'Service configuration (registry)' {
        $unquoted = @(); $missing = @()
        foreach ($s in $services) {
            $path = "$($s.PathName)"
            if (-not $path) { continue }
            if ($path -notmatch '^"' -and $path -match '^(?i)[a-z]:\\[^"]*?\s[^"]*?\.exe' -and $path -notmatch '^(?i)[a-z]:\\windows\\') {
                $exePart = ($path -split '(?i)\.exe')[0]
                if ($exePart -match '\s') { $unquoted += "$($s.Name): $path" }
            }
            if ($s.StartMode -ne 'Disabled') {
                $exe = Get-CommandPath $path
                if ($exe -and -not (Test-Path -LiteralPath $exe)) { $missing += "$($s.Name) ($($s.StartMode)): $exe" }
            }
        }
        if ($unquoted.Count) {
            Add-Finding -Category 'Security' -Severity 'Medium' -Title "$($unquoted.Count) service(s) with an unquoted path containing spaces" `
                -Description 'An unquoted service path with spaces lets anyone who can write to a parent folder run code as the service account (often SYSTEM).' `
                -Evidence $unquoted -Fix 'Add quotes around the executable path in the service ImagePath (HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath), or update the software. Example for one service is shown below.' `
                -Command ('sc.exe config "<ServiceName>" binPath= "\"C:\Program Files\Vendor\app.exe\" <args>"')
        }
        if ($missing.Count) {
            Add-Finding -Category 'Registry' -Severity 'Low' -Title "$($missing.Count) service(s) point to missing program files" `
                -Description 'These services are left over from software that was removed or moved. They cause startup errors and clutter.' `
                -Evidence $missing -Fix "Confirm the software is no longer needed, then disable or delete each service." -Command 'sc.exe delete "<ServiceName>"'
        }
    }

    Invoke-Check 'Scheduled tasks' {
        $okCodes = 0, 267008, 267009, 267011, 267012, 267014, 267045, 1, 2147750687
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' })
        $failed = @(); $broken = @()
        foreach ($t in $tasks) {
            $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            if ($info -and $info.LastRunTime -gt $PF.Start -and $info.LastTaskResult -notin $okCodes) {
                $failed += '{0}{1}  last run {2:yyyy-MM-dd HH:mm}  result 0x{3:X8}' -f $t.TaskPath, $t.TaskName, $info.LastRunTime, $info.LastTaskResult
            }
            foreach ($a in @($t.Actions)) {
                if ($a.Execute) {
                    $exe = Get-CommandPath ('"' + [Environment]::ExpandEnvironmentVariables($a.Execute.Trim('"')) + '"')
                    if ($exe -and $exe -match '^(?i)[a-z]:\\' -and -not (Test-Path -LiteralPath $exe)) { $broken += "$($t.TaskPath)$($t.TaskName): $exe" }
                }
            }
        }
        if ($failed.Count) {
            Add-Finding -Category 'Scheduled tasks' -Severity 'Low' -Title "$($failed.Count) scheduled task(s) failed on their last run" `
                -Description 'Non-Microsoft scheduled tasks that returned an error. These are often backups, scripts or updaters.' `
                -Evidence $failed -Fix 'Open Task Scheduler, check the History tab and the account/password the task runs as. 0x1 often means the script itself failed; 0x80070005 is access denied; 0x8007052E is bad password.'
        }
        if ($broken.Count) {
            Add-Finding -Category 'Scheduled tasks' -Severity 'Low' -Title "$($broken.Count) scheduled task(s) point to missing programs" `
                -Description 'These tasks are left over from removed software and fail every time they run.' `
                -Evidence $broken -Fix 'Delete or disable the tasks in Task Scheduler if the software is gone.' -Command 'Unregister-ScheduledTask -TaskName "<TaskName>" -Confirm:$false'
        }
    }

    #endregion

    #region ---------- Registry and startup ----------

    Invoke-Check 'Startup entries' {
        $runKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        # Every loaded user hive
        foreach ($h in @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
            $runKeys += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
            $runKeys += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        }
        $all = @(); $broken = @(); $cmds = @()
        foreach ($k in $runKeys) {
            $item = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            foreach ($p in $item.PSObject.Properties) {
                if ($p.Name -like 'PS*') { continue }
                $all += "$($p.Name) = $($p.Value)"
                $exe = Get-CommandPath "$($p.Value)"
                if ($exe -and -not (Test-Path -LiteralPath $exe)) {
                    $broken += "$k\$($p.Name) -> $exe"
                    $cmds += "Remove-ItemProperty -LiteralPath '$k' -Name '$($p.Name)'"
                }
            }
        }
        foreach ($folder in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
            Get-ChildItem $folder -File -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini' | ForEach-Object { $all += "Startup folder: $($_.Name)" }
        }
        $PF.Info['Startup entries'] = "$($all.Count)"
        if ($broken.Count) {
            Add-Finding -Category 'Registry' -Severity 'Low' -Title "$($broken.Count) startup entr(y/ies) point to missing files" `
                -Description 'Run keys that launch programs that no longer exist. They are harmless but slow logon slightly and show errors.' `
                -Evidence $broken -Fix 'Remove the broken entries (Task Manager > Startup, Autoruns, or the commands below). Back up the key first with reg export.' -Command ($cmds -join "`n")
        }
        if ($all.Count -gt 15 -and -not $isServer) {
            Add-Finding -Category 'Performance' -Severity 'Low' -Title "$($all.Count) programs start automatically" -Description 'Many startup programs slow down logon and use memory in the background.' `
                -Evidence $all -Fix 'Disable the ones you do not need in Task Manager > Startup apps (or Settings > Apps > Startup). Use Sysinternals Autoruns for a full view.'
        }
    }

    Invoke-Check 'Registry hijacks and risky settings' {
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $shell = Get-RegValue $wl 'Shell'
        if ($shell -and $shell -notmatch '^(?i)explorer\.exe,?$') {
            Add-Finding -Category 'Registry' -Severity 'High' -Title 'Winlogon Shell has been changed' -Description 'The program that starts as the desktop has been replaced. This is a common malware persistence technique (unless this is a kiosk).' `
                -Evidence "$wl\Shell = $shell" -Fix 'If this is not a deliberate kiosk setup, scan for malware and set Shell back to explorer.exe.' -Command "Set-ItemProperty '$wl' -Name Shell -Value 'explorer.exe'"
        }
        $ui = Get-RegValue $wl 'Userinit'
        if ($ui -and $ui -notmatch '^(?i)[a-z]:\\windows\\system32\\userinit\.exe,?$') {
            Add-Finding -Category 'Registry' -Severity 'High' -Title 'Winlogon Userinit has been changed' -Description 'Extra programs are launched at every logon via Userinit. This is a common malware persistence technique.' `
                -Evidence "$wl\Userinit = $ui" -Fix 'Scan for malware and set Userinit back to the default.' -Command "Set-ItemProperty '$wl' -Name Userinit -Value 'C:\Windows\system32\userinit.exe,'"
        }
        if ((Get-RegValue $wl 'AutoAdminLogon') -eq '1' -and (Get-RegValue $wl 'DefaultPassword')) {
            Add-Finding -Category 'Security' -Severity 'High' -Title 'Automatic logon password stored in plain text' -Description 'AutoAdminLogon is on and the password is stored unencrypted in the registry, readable by any administrator or malware.' `
                -Evidence "$wl\AutoAdminLogon = 1, DefaultUserName = $(Get-RegValue $wl 'DefaultUserName'), DefaultPassword = (set)" `
                -Fix 'Turn off auto logon, or use Sysinternals Autologon which stores the password encrypted as an LSA secret.' -Command "Remove-ItemProperty '$wl' -Name DefaultPassword"
        }
        foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
            $dlls = Get-RegValue $k 'AppInit_DLLs'
            if ($dlls -and (Get-RegValue $k 'LoadAppInit_DLLs') -eq 1) {
                Add-Finding -Category 'Registry' -Severity 'Medium' -Title 'AppInit_DLLs are loaded into every program' -Description 'DLLs listed here are injected into every process that loads user32.dll. Legacy software and malware use this.' `
                    -Evidence "$k\AppInit_DLLs = $dlls" -Fix 'Identify the DLL; remove the value if it is not from trusted, required software.' -Command "Set-ItemProperty '$k' -Name LoadAppInit_DLLs -Value 0"
            }
        }
        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $hij = @(Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
                $dbg = Get-RegValue $_.PSPath 'Debugger'
                if ($dbg -and $dbg -notmatch '(?i)vsjitdebugger|drwtsn32|procexp|ntsd -d|systemsettings') { "$($_.PSChildName) -> $dbg" }
            })
        if ($hij.Count) {
            Add-Finding -Category 'Registry' -Severity 'High' -Title "$($hij.Count) program(s) redirected with an IFEO debugger" -Description 'Image File Execution Options can silently launch a different program instead of the one requested. Malware uses this to block security tools or hijack accessibility tools (e.g. sethc.exe, utilman.exe).' `
                -Evidence $hij -Fix 'Unless you set these deliberately (e.g. Process Explorer replacing Task Manager), delete the Debugger value and scan for malware.' -Command "Remove-ItemProperty -Path '$ifeo\<program.exe>' -Name Debugger"
        }
        $pol = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        foreach ($n in 'DisableTaskMgr', 'DisableRegistryTools', 'DisableCMD') {
            foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', $pol) {
                if ((Get-RegValue $root $n) -ge 1) {
                    Add-Finding -Category 'Registry' -Severity 'Medium' -Title "$n policy is set" -Description 'Admin tools are blocked by policy. This is sometimes deliberate in locked-down environments but is also a classic malware trick.' `
                        -Evidence "$root\$n = $(Get-RegValue $root $n)" -Fix 'If not set by your Group Policy, remove the value and scan for malware.' -Command "Remove-ItemProperty '$root' -Name $n"
                }
            }
        }
        $path = [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' | Where-Object { $_ }
        $deadPath = @($path | Where-Object { $_ -notmatch '%' -and -not (Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables($_))) })
        if ($deadPath.Count) {
            Add-Finding -Category 'Registry' -Severity 'Low' -Title "$($deadPath.Count) folder(s) in the system PATH no longer exist" -Description 'Leftover PATH entries from removed software slow down command lookup and can be a DLL-hijack risk if the folder is recreated by a user.' `
                -Evidence $deadPath -Fix 'Remove the missing folders in System Properties > Environment Variables > Path.'
        }
        $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
        $entries = @(Get-Content $hosts -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[0-9a-f:.]+\s+\S' -and $_ -notmatch '^\s*#' })
        if ($entries.Count) {
            $sus = @($entries | Where-Object { $_ -match '(?i)microsoft|windowsupdate|google|bank|paypal|apple|office|live\.com|defender' })
            Add-Finding -Category 'Network' -Severity $(if ($sus.Count) { 'High' } else { 'Info' }) -Title "Hosts file has $($entries.Count) custom entr(y/ies)" `
                -Description 'Entries in the hosts file override DNS. Stale entries break access to servers that moved; malicious entries redirect well-known sites or block updates.' `
                -Evidence $entries -Fix 'Remove entries that are no longer needed. Entries redirecting Microsoft, security vendor or banking sites are suspicious; scan for malware.' -Command "notepad $hosts"
        }
    }

    #endregion

    #region ---------- Security configuration ----------

    Invoke-Check 'Antivirus and Defender' {
        $thirdParty = @()
        if (-not $isServer) {
            $thirdParty = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' })
            if ($thirdParty.Count -ge 2) {
                Add-Finding -Category 'Security' -Severity 'High' -Title "$($thirdParty.Count) antivirus products installed" -Description 'Running more than one real-time antivirus causes conflicts, slowness and crashes, and can leave gaps.' `
                    -Evidence ($thirdParty | ForEach-Object { $_.displayName }) -Fix 'Keep one antivirus and uninstall the others with their vendor removal tool.'
            }
        }
        else {
            $avSvc = 'SentinelAgent|CSFalconService|SAVService|Sophos|ekrn|McAfee|mfemms|Symantec|SepMasterService|bdservicehost|EPSecurityService|WRSVC|CylanceSvc|TmCCSF|ds_agent|CarbonBlack|cbdefense|HuntressAgent|AvastSvc|AVP|klnagent'
            $thirdParty = @($services | Where-Object { $_.Name -match "^($avSvc)" -and $_.State -eq 'Running' })
        }
        $mp = if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { Get-MpComputerStatus -ErrorAction SilentlyContinue } else { $null }
        if ($mp) {
            $passive = "$($mp.AMRunningMode)" -match 'Passive|EDR'
            if (-not $thirdParty.Count -and -not $passive) {
                if (-not $mp.AntivirusEnabled -or -not $mp.RealTimeProtectionEnabled) {
                    Add-Finding -Category 'Security' -Severity 'High' -Title 'Microsoft Defender real-time protection is off' -Description 'No other antivirus was detected, so this machine has no real-time malware protection.' `
                        -Evidence "AntivirusEnabled=$($mp.AntivirusEnabled)  RealTimeProtectionEnabled=$($mp.RealTimeProtectionEnabled)  Mode=$($mp.AMRunningMode)" `
                        -Fix 'Turn on real-time protection in Windows Security, and check for a Group Policy that disables it.' -Command 'Set-MpPreference -DisableRealtimeMonitoring $false'
                }
                if ($mp.AntivirusSignatureAge -gt 3) {
                    Add-Finding -Category 'Security' -Severity 'Medium' -Title "Defender signatures are $($mp.AntivirusSignatureAge) days old" -Description 'Out-of-date signatures miss new malware.' `
                        -Evidence "Last updated: $($mp.AntivirusSignatureLastUpdated)" -Fix 'Update signatures and check this machine can reach Windows Update or your WSUS server.' -Command 'Update-MpSignature'
                }
            }
            if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware') -eq 1 -and -not $thirdParty.Count) {
                Add-Finding -Category 'Security' -Severity 'High' -Title 'Defender is disabled by policy' -Description 'DisableAntiSpyware is set and no other antivirus is running.' `
                    -Evidence 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1' -Fix 'Remove the policy unless another AV is deployed, then reboot.'
            }
            $PF.Info['Antivirus'] = if ($thirdParty.Count) { ($thirdParty | ForEach-Object { if ($_.displayName) { $_.displayName } else { $_.DisplayName } }) -join ', ' } else { "Microsoft Defender ($($mp.AMRunningMode))" }
        }
        elseif ($thirdParty.Count) { $PF.Info['Antivirus'] = ($thirdParty | ForEach-Object { if ($_.displayName) { $_.displayName } else { $_.DisplayName } }) -join ', ' }
        else {
            Add-Finding -Category 'Security' -Severity 'High' -Title 'No antivirus detected' -Description 'Neither Microsoft Defender nor a known third-party antivirus was found running.' `
                -Fix 'Install Microsoft Defender (Server: Install-WindowsFeature Windows-Defender) or your organisation''s antivirus.'
        }
    }

    Invoke-Check 'Firewall' {
        foreach ($p in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
            if (-not $p.Enabled) {
                $sev = if ($p.Name -eq 'Public') { 'High' } else { 'Medium' }
                Add-Finding -Category 'Security' -Severity $sev -Title "Windows Firewall is off for the $($p.Name) profile" -Description 'With the firewall off every listening service is reachable from the network.' `
                    -Evidence "$($p.Name): Enabled = False" -Fix 'Turn the firewall back on and add specific allow rules for what is needed, rather than disabling it.' -Command "Set-NetFirewallProfile -Profile $($p.Name) -Enabled True"
            }
        }
    }

    Invoke-Check 'Hardening settings' {
        $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if ((Get-RegValue $sys 'EnableLUA') -eq 0) {
            Add-Finding -Category 'Security' -Severity 'High' -Title 'User Account Control (UAC) is disabled' -Description 'With UAC off every program run by an administrator has full admin rights, and modern apps may not work.' `
                -Evidence "$sys\EnableLUA = 0" -Fix 'Turn UAC back on and reboot.' -Command "Set-ItemProperty '$sys' -Name EnableLUA -Value 1"
        }
        $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($smb -and $smb.EnableSMB1Protocol) {
            Add-Finding -Category 'Security' -Severity 'High' -Title 'SMBv1 is enabled' -Description 'SMBv1 is obsolete and was exploited by WannaCry and NotPetya. Very few devices still need it.' `
                -Evidence 'Get-SmbServerConfiguration: EnableSMB1Protocol = True' -Fix 'Disable SMBv1. If an old scanner/NAS needs it, update its firmware or replace it.' `
                -Command $(if ($isServer) { 'Uninstall-WindowsFeature FS-SMB1' } else { 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart' })
        }
        if ($smb -and -not $smb.RequireSecuritySignature -and $isDC) {
            Add-Finding -Category 'Security' -Severity 'Medium' -Title 'SMB signing is not required on this domain controller' -Description 'Without SMB signing, relay attacks against the DC are possible.' `
                -Fix 'Enable "Microsoft network server: Digitally sign communications (always)" in the Default Domain Controllers Policy.'
        }
        $rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        if ((Get-RegValue $rdp 'fDenyTSConnections') -eq 0) {
            $nla = Get-RegValue "$rdp\WinStations\RDP-Tcp" 'UserAuthentication'
            if ($nla -eq 0) {
                Add-Finding -Category 'Security' -Severity 'Medium' -Title 'Remote Desktop is on without Network Level Authentication' -Description 'Without NLA anyone can reach the logon screen before authenticating, which exposes the server to attacks and resource exhaustion.' `
                    -Evidence "$rdp\WinStations\RDP-Tcp\UserAuthentication = 0" -Fix 'Enable NLA in System Properties > Remote.' -Command "Set-ItemProperty '$rdp\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
            }
        }
        $wd = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        if ($wd -eq 1) {
            Add-Finding -Category 'Security' -Severity 'High' -Title 'WDigest stores passwords in memory in clear text' -Description 'UseLogonCredential=1 makes Windows keep plain-text passwords in LSASS, which tools like Mimikatz can read.' `
                -Evidence 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1' -Fix 'Set it to 0 and investigate why it was enabled (attackers often turn it on).' `
                -Command "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
        }
        $lm = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
        if ($null -ne $lm -and $lm -lt 3) {
            Add-Finding -Category 'Security' -Severity 'Medium' -Title "Old LM/NTLMv1 authentication allowed (level $lm)" -Description 'LM and NTLMv1 hashes are easy to crack.' `
                -Evidence "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel = $lm" -Fix 'Set "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" (5) after checking old devices.' `
                -Command "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5"
        }
        $sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $old = @()
        foreach ($proto in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
            if ((Get-RegValue "$sch\$proto\Server" 'Enabled') -ge 1) { $old += "$proto server explicitly enabled" }
        }
        if ($old.Count) {
            Add-Finding -Category 'Security' -Severity 'Medium' -Title 'Old SSL/TLS protocols explicitly enabled' -Description 'SSL and TLS 1.0/1.1 are deprecated and insecure.' `
                -Evidence $old -Fix 'Disable them (set Enabled=0, DisabledByDefault=1) after confirming no old clients need them, or use IIS Crypto. Reboot required.' `
                -Command "New-ItemProperty -Path '$sch\TLS 1.0\Server' -Name Enabled -Value 0 -PropertyType DWord -Force"
        }
        if (-not $isDC) {
            $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
            if (-not $guest) { $guest = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like '*-501' } }
            if ($guest -and $guest.Enabled) {
                Add-Finding -Category 'Security' -Severity 'Medium' -Title 'Guest account is enabled' -Description 'The Guest account allows access without a password.' `
                    -Evidence "$($guest.Name) Enabled = True" -Fix 'Disable the Guest account.' -Command "Disable-LocalUser -Name '$($guest.Name)'"
            }
            $admins = @()
            try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { "$($_.Name) ($($_.PrincipalSource))" }) }
            catch { $admins = @(& net localgroup administrators 2>$null | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' }) }
            if ($admins.Count) {
                Add-Finding -Category 'Security' -Severity $(if ($admins.Count -gt 5) { 'Low' } else { 'Info' }) -Title "$($admins.Count) member(s) of the local Administrators group" `
                    -Description 'Review that everyone listed really needs full admin rights on this machine.' -Evidence $admins -Fix 'Remove accounts that do not need admin rights; use LAPS for the built-in Administrator password.'
            }
        }
        if (-not $isServer) {
            $chassis = @((Get-CimInstance Win32_SystemEnclosure).ChassisTypes)
            $laptop = @($chassis | Where-Object { $_ -in 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32 }).Count -gt 0
            $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
            if ($bl -and "$($bl.ProtectionStatus)" -ne 'On') {
                Add-Finding -Category 'Security' -Severity $(if ($laptop) { 'Medium' } else { 'Low' }) -Title "System drive is not protected by BitLocker" -Description 'If the device is lost or stolen, the data on the disk can be read.' `
                    -Evidence "$env:SystemDrive ProtectionStatus = $($bl.ProtectionStatus), VolumeStatus = $($bl.VolumeStatus)" -Fix 'Turn on BitLocker (or Device Encryption) and save the recovery key to Entra ID/AD or a safe place.'
            }
        }
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            if (-not $sb) {
                Add-Finding -Category 'Security' -Severity 'Low' -Title 'Secure Boot is off' -Description 'Secure Boot protects against boot-level malware and is required for Windows 11.' `
                    -Fix 'Enable Secure Boot in the UEFI/BIOS settings (the disk must be GPT and the system booting in UEFI mode).'
            }
            else {
                $st = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' 'UEFICA2023Status'
                if ($st -and $st -ne 'Updated') {
                    Add-Finding -Category 'Security' -Severity 'Medium' -Title "Secure Boot 2023 certificates not yet applied ($st)" `
                        -Description 'The Microsoft Secure Boot certificates from 2011 expire during 2026. Devices that do not move to the 2023 certificates stop receiving boot security fixes.' `
                        -Evidence "UEFICA2023Status = $st" -Fix 'Install the latest cumulative update and the latest BIOS/UEFI firmware from the manufacturer, then reboot (twice). Check Microsoft''s Secure Boot certificate guidance for managed rollout.' `
                        -Reference 'https://support.microsoft.com/topic/windows-devices-for-businesses-and-organizations-with-it-managed-updates-e2b43f9f-b424-42df-bc6a-8476db65ab2f'
                }
            }
        }
        catch {}
        if (-not $isServer) {
            $ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
            if ($ps2 -and "$($ps2.State)" -eq 'Enabled') {
                Add-Finding -Category 'Security' -Severity 'Low' -Title 'PowerShell 2.0 engine is installed' -Description 'Attackers use the old PowerShell 2.0 engine to bypass logging and AMSI.' `
                    -Fix 'Remove the feature; nothing modern needs it.' -Command 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart'
            }
        }
    }

    Invoke-Check 'Shares and certificates' {
        foreach ($sh in @(Get-SmbShare -Special $false -ErrorAction SilentlyContinue)) {
            $acc = @(Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue | Where-Object { $_.AccountName -match '^(Everyone|NT AUTHORITY\\Authenticated Users|BUILTIN\\Users)$' -and "$($_.AccessRight)" -match 'Full|Change' -and "$($_.AccessControlType)" -eq 'Allow' })
            if ($acc.Count -and $sh.Name -notmatch '^(SYSVOL|NETLOGON|print\$)$') {
                Add-Finding -Category 'Security' -Severity 'Low' -Title "Share '$($sh.Name)' gives broad write access" -Description 'Everyone/Users have Change or Full Control at share level. NTFS permissions may still restrict access, but broad share rights make ransomware spread easier.' `
                    -Evidence ($acc | ForEach-Object { "$($sh.Name) ($($sh.Path)): $($_.AccountName) $($_.AccessRight)" }) -Fix 'Grant share access to specific groups and control detail with NTFS permissions.'
            }
        }
        $now = Get-Date
        $certs = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey })
        foreach ($c in $certs) {
            $newer = @($certs | Where-Object { $_.Subject -eq $c.Subject -and $_.NotAfter -gt $c.NotAfter -and $_.NotAfter -gt $now })
            if ($newer.Count) { continue }
            $left = ($c.NotAfter - $now).Days
            if ($left -lt 0 -and $left -gt -365) {
                Add-Finding -Category 'Certificates' -Severity 'Medium' -Title "Certificate expired: $($c.Subject)" -Description 'An expired certificate with a private key is still installed. If a service (IIS, RDP, Exchange, LDAPS) uses it, clients get errors.' `
                    -Evidence "Expired $($c.NotAfter.ToString('yyyy-MM-dd'))  Thumbprint $($c.Thumbprint)  Issuer $($c.Issuer)" -Fix 'Renew or replace the certificate and update the bindings that use it; delete it when no longer used.'
            }
            elseif ($left -ge 0 -and $left -le 30) {
                Add-Finding -Category 'Certificates' -Severity 'Low' -Title "Certificate expires in $left days: $($c.Subject)" -Description 'Renew it before it expires to avoid service interruptions.' `
                    -Evidence "Expires $($c.NotAfter.ToString('yyyy-MM-dd'))  Thumbprint $($c.Thumbprint)  Issuer $($c.Issuer)" -Fix 'Renew the certificate and update bindings (IIS, RDP, Exchange, etc.).'
            }
        }
    }

    #endregion

    #region ---------- Network ----------

    Invoke-Check 'Network configuration' {
        $public = '^(8\.8\.|8\.26\.|1\.1\.1\.|1\.0\.0\.|9\.9\.9\.|149\.112\.|208\.67\.|4\.2\.2\.|64\.6\.)'
        $upIdx = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object ifIndex)
        $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -in $upIdx -and $_.ServerAddresses })
        $PF.Info['DNS servers'] = (($dns | ForEach-Object { $_.ServerAddresses }) | Select-Object -Unique) -join ', '
        if ($cs.PartOfDomain) {
            $bad = @($dns | Where-Object { @($_.ServerAddresses | Where-Object { $_ -match $public -or ($_ -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)') }).Count })
            if ($bad.Count) {
                Add-Finding -Category 'Network' -Severity 'High' -Title 'Domain-joined machine uses non-domain DNS servers' -Description 'Domain members must use only domain DNS servers. Public DNS (e.g. 8.8.8.8) cannot resolve the domain and causes slow logons, Group Policy failures and authentication errors.' `
                    -Evidence ($bad | ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')" }) -Fix 'Set the adapter (or DHCP scope option 006) to the domain controllers'' DNS addresses only. Put public DNS as forwarders on the DC instead.' `
                    -Command 'Set-DnsClientServerAddress -InterfaceAlias "<adapter>" -ServerAddresses ("<DC1 IP>","<DC2 IP>")'
            }
        }
        $apipa = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '169.254.*' -and $_.InterfaceIndex -in $upIdx })
        if ($apipa.Count) {
            Add-Finding -Category 'Network' -Severity 'High' -Title 'Network adapter has a self-assigned (169.254) address' -Description 'The adapter could not get an address from DHCP, so it has no working network connection.' `
                -Evidence ($apipa | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)" }) -Fix 'Check the cable/Wi-Fi, switch port and that the DHCP server is reachable and has free addresses. Then renew.' -Command 'ipconfig /renew'
        }
        $resolved = Resolve-DnsName -Name 'www.microsoft.com' -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
        if (-not $resolved) {
            Add-Finding -Category 'Network' -Severity 'Medium' -Title 'Cannot resolve internet names' -Description 'DNS lookup of www.microsoft.com failed. Windows Update, activation and Defender updates will not work (expected only on deliberately isolated servers).' `
                -Evidence "DNS servers: $($PF.Info['DNS servers'])" -Fix 'Check DNS servers and forwarders, firewall/proxy rules and internet connectivity.' -Command 'Resolve-DnsName www.microsoft.com; Test-NetConnection www.microsoft.com -Port 443'
        }
        if ($cs.PartOfDomain -and -not $isDC) {
            $sc = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
            if ($sc -eq $false) {
                Add-Finding -Category 'Network' -Severity 'High' -Title 'Trust relationship with the domain is broken' -Description 'The computer account password does not match the domain. Domain logons and Group Policy will fail.' `
                    -Fix 'Repair the secure channel while logged on as a local administrator, using domain admin credentials.' -Command 'Test-ComputerSecureChannel -Repair -Credential (Get-Credential)'
            }
        }
        $w32 = (& w32tm /query /status 2>$null) -join "`n"
        if ($w32 -match 'Source:\s*(.+)') {
            $src = $Matches[1].Trim()
            $PF.Info['Time source'] = $src
            if ($src -match 'Local CMOS Clock|Free-running System Clock') {
                $sev = if ($isDC -or $cs.PartOfDomain) { 'Medium' } else { 'Low' }
                Add-Finding -Category 'Network' -Severity $sev -Title 'Clock is not synchronising with a time server' -Description 'Time drift over 5 minutes breaks Kerberos (domain logons) and causes certificate and log-correlation problems.' `
                    -Evidence $w32 -Fix $(if ($isDC) { 'On the PDC emulator, set an external NTP source; other DCs and members should use the domain hierarchy.' } elseif ($cs.PartOfDomain) { 'Domain members should sync from the domain hierarchy.' } else { 'Set an internet time server.' }) `
                    -Command $(if ($isDC) { 'w32tm /config /manualpeerlist:"time.windows.com,0x8 pool.ntp.org,0x8" /syncfromflags:manual /reliable:yes /update; w32tm /resync' } elseif ($cs.PartOfDomain) { 'w32tm /config /syncfromflags:domhier /update; w32tm /resync' } else { 'w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /update; w32tm /resync' })
            }
        }
        $winhttp = (& netsh winhttp show proxy 2>$null) -join ' '
        if ($winhttp -match 'Proxy Server\(s\)\s*:\s*(\S+)') {
            Add-Finding -Category 'Network' -Severity 'Info' -Title "System (WinHTTP) proxy is set: $($Matches[1])" -Description 'Windows services use this proxy. A stale proxy breaks Windows Update, activation and Defender updates.' `
                -Evidence $winhttp -Fix 'If the proxy is no longer used, reset it.' -Command 'netsh winhttp reset proxy'
        }
        foreach ($s in @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)) {
            $errs = [double]$s.ReceivedPacketErrors + [double]$s.OutboundPacketErrors
            if ($errs -gt 1000) {
                Add-Finding -Category 'Network' -Severity 'Low' -Title "Network adapter '$($s.Name)' has $errs packet errors" -Description 'Packet errors point to a bad cable, switch port, duplex mismatch or driver problem.' `
                    -Evidence "Received errors: $($s.ReceivedPacketErrors)  Outbound errors: $($s.OutboundPacketErrors)" -Fix 'Replace the cable, try another switch port, and update the NIC driver.'
            }
        }
    }

    #endregion

    #region ---------- Installed programs ----------

    Invoke-Check 'Installed programs (removable / outdated)' {
        $roots = @(
            @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; S = 'Machine' },
            @{ P = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; S = 'Machine (32-bit)' }
        )
        foreach ($h in @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
            $roots += @{ P = "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"; S = "User $($h.PSChildName)" }
        }
        $apps = foreach ($r in $roots) {
            foreach ($k in @(Get-ChildItem -LiteralPath $r.P -ErrorAction SilentlyContinue)) {
                $v = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                if (-not $v.DisplayName -or $v.SystemComponent -eq 1 -or $v.ParentKeyName -or $v.ReleaseType -match 'Update|Hotfix') { continue }
                [pscustomobject]@{
                    Name = "$($v.DisplayName)".Trim(); Version = "$($v.DisplayVersion)"; Publisher = "$($v.Publisher)"; InstallDate = "$($v.InstallDate)"
                    UninstallString = "$($v.UninstallString)"; QuietUninstallString = "$($v.QuietUninstallString)"; InstallLocation = "$($v.InstallLocation)"
                    SizeMB = if ($v.EstimatedSize) { [math]::Round($v.EstimatedSize / 1024) } else { $null }; Scope = $r.S; Key = $k.Name
                }
            }
        }
        $apps = @($apps | Sort-Object Name -Unique)
        $PF.Info['Installed programs'] = "$($apps.Count)"

        function Test-VersionBelow([string]$v, [string]$min) { try { return ([version]($v -replace '[^\d.].*$', '') -lt [version]$min) } catch { return $false } }

        $rules = @(
            @{ P = '^Adobe Flash Player'; S = 'High'; R = 'Adobe Flash is end-of-life (Dec 2020) and a known security risk.' }
            @{ P = '^Microsoft Silverlight'; S = 'Medium'; R = 'Silverlight is end-of-life (Oct 2021).' }
            @{ P = '^(Adobe )?Shockwave Player'; S = 'High'; R = 'Shockwave is end-of-life and unpatched.' }
            @{ P = '^QuickTime'; S = 'High'; R = 'QuickTime for Windows is unsupported and has unpatched vulnerabilities.' }
            @{ P = '^Python 2\.'; S = 'Medium'; R = 'Python 2 is end-of-life (Jan 2020).' }
            @{ P = '^Java( \d+)?( Update \d+)?( \(64-bit\))?$|^Java\(TM\) [67]'; S = 'Medium'; R = 'Java Runtime is a frequent attack target. Remove it unless an application needs it; otherwise keep it updated.' }
            @{ P = '^Adobe Reader (X|XI|9|8)\b|^Adobe Acrobat (X|XI|9|8|2015|2017)\b'; S = 'High'; R = 'This Adobe Reader/Acrobat version is out of support.' }
            @{ P = '^Microsoft Office.*\b(2007|2010|2013|2016|2019|2021)\b|^Microsoft (Visio|Project).*\b(2010|2013|2016|2019|2021)\b|^Office (16|15) Click-to-Run|Office LTSC.*2021'; S = 'High'; R = 'This Office version no longer receives security updates (Office 2016/2019 ended Oct 2025, Office 2021/LTSC 2021 ended Oct 2026).' }
            @{ P = '^Microsoft SQL Server (2005|2008|2012|2014)\b(?!.*(Native Client|ODBC|Driver|Compact|LocalDB|Management Objects|CLR|T-SQL|Setup Support|Policies|VSS Writer|Browser))'; S = 'High'; R = 'This SQL Server version is out of support.' }
            @{ P = '^Internet Explorer|^Microsoft Edge Legacy'; S = 'Low'; R = 'Retired browser.' }
            @{ P = 'Toolbar$|^Ask Toolbar|^Babylon|^Conduit|^Yahoo! (Toolbar|Search)|^Bing Bar'; S = 'Medium'; R = 'Browser toolbar / search hijacker (potentially unwanted program).' }
            @{ P = '^(Segurazo|SAntivirus|ByteFence|Reimage|Restoro|SlimCleaner|MyPC Backup|WebDiscover|OneLaunch|Wave Browser|Shift Browser|PC App Store|Hola|PC Optimizer|Driver Booster|Driver Easy|DriverPack|Advanced SystemCare|WinZip Driver Updater|Systweak|PC Accelerate|Total PC Cleaner|Search Protect|Web Companion|PDFreeConverter|PDF Pro|ShieldApps|WildTangent|Bonjour)'; S = 'Medium'; R = 'Potentially unwanted program, scareware or bundleware. Safe to remove.' }
            @{ P = '^(McAfee|Norton|Avast|AVG|Avira|Kaspersky|Bitdefender|ESET|Malwarebytes|Webroot|Trend Micro|Sophos Home|Total ?AV|Panda)\b.*(Trial|Security|Antivirus|Internet Security|LiveSafe|360|Free)'; S = 'Info'; R = 'Consumer antivirus. Keep only one AV; remove trial or duplicate products (Defender is built in).' }
            @{ P = '^(CCleaner|Glary Utilities|Wise (Care|Registry)|Auslogics|IObit|Registry (Mechanic|Cleaner|Booster)|Clean Master)'; S = 'Low'; R = 'Registry cleaners / "optimisers" provide no real benefit and can break Windows.' }
            @{ P = '^(Booking\.com|Candy Crush|Dropbox Promotion|ExpressVPN Promotion|Amazon Assistant|Coupon)'; S = 'Low'; R = 'Pre-installed promotional software (bloatware).' }
            @{ P = '^(HP|Dell|Lenovo|Acer|ASUS|Toshiba|MSI)\s.*(Jumpstart|Documentation|Registration|Welcome|Customer Experience|Product Improvement|Support Assist Recovery|Connection Optimizer|Sure Click|Wolf Security Console|Audio Switch)'; S = 'Low'; R = 'Manufacturer bloatware that is generally safe to remove.' }
        )
        $hits = @{}
        foreach ($a in $apps) {
            foreach ($r in $rules) {
                if ($a.Name -match $r.P) {
                    if (-not $hits.ContainsKey($r.R)) { $hits[$r.R] = @{ Sev = $r.S; Apps = New-Object System.Collections.Generic.List[object] } }
                    $hits[$r.R].Apps.Add($a); break
                }
            }
        }
        # Version-based checks for widely exploited tools
        foreach ($a in $apps) {
            $reason = $null
            if ($a.Name -match '^7-Zip' -and (Test-VersionBelow $a.Version '24.9')) { $reason = '7-Zip older than 24.09 has known vulnerabilities (e.g. CVE-2025-0411). Update it.' }
            elseif ($a.Name -match '^WinRAR' -and (Test-VersionBelow $a.Version '7.13')) { $reason = 'WinRAR older than 7.13 has actively exploited vulnerabilities (CVE-2025-8088, CVE-2023-38831). Update it.' }
            elseif ($a.Name -match '^Notepad\+\+' -and (Test-VersionBelow $a.Version '8.8.2')) { $reason = 'Outdated Notepad++ with known vulnerabilities. Update it.' }
            elseif ($a.Name -match '^(TeamViewer|AnyDesk|ScreenConnect|ConnectWise Control|Splashtop|RustDesk|UltraVNC|TightVNC|RealVNC|LogMeIn|Remote Utilities|Atera|NinjaRMM)' -and $isServer) { $reason = 'Remote access tools on servers are a common attacker entry point. Keep only the ones your organisation manages.' }
            if ($reason) {
                if (-not $hits.ContainsKey($reason)) { $hits[$reason] = @{ Sev = $(if ($reason -match 'Remote access') { 'Info' } else { 'Medium' }); Apps = New-Object System.Collections.Generic.List[object] } }
                $hits[$reason].Apps.Add($a)
            }
        }
        foreach ($reason in $hits.Keys) {
            $h = $hits[$reason]
            $cmds = @($h.Apps | ForEach-Object { $c = Get-MsiUninstallCommand $_; if ($c) { "# $($_.Name)`n$c" } })
            Add-Finding -Category 'Programs' -Severity $h.Sev -Title "Removable or outdated software: $(($h.Apps | Select-Object -First 3 | ForEach-Object Name) -join ', ')$(if ($h.Apps.Count -gt 3) { " (+$($h.Apps.Count - 3) more)" })" `
                -Description $reason -Evidence ($h.Apps | ForEach-Object { "$($_.Name)  $($_.Version)  [$($_.Publisher)]$(if ($_.SizeMB) { "  $($_.SizeMB) MB" })" }) `
                -Fix 'Uninstall from Settings > Apps (or Programs and Features), or run the uninstall command shown. Update instead of removing if the software is needed.' -Command ($cmds -join "`n")
        }
        # Duplicate versions of the same product
        $dupes = @($apps | Where-Object { $_.Name -match '^(Java|Adobe Acrobat|Adobe Reader|Python 3|Node\.js|Google Chrome|Mozilla Firefox|Zoom|Microsoft Teams)' } |
                Group-Object { ($_.Name -replace '\s*\(?(x64|x86|64-bit|32-bit)\)?', '' -replace '\s+[\d.]+.*$', '' -replace '\s+Update.*$', '').Trim() } | Where-Object Count -gt 1)
        foreach ($d in $dupes) {
            Add-Finding -Category 'Programs' -Severity 'Low' -Title "Multiple versions of $($d.Name) installed" -Description 'Old versions are usually left behind by upgrades and are not patched.' `
                -Evidence ($d.Group | ForEach-Object { "$($_.Name)  $($_.Version)" }) -Fix 'Uninstall the older versions unless an application specifically needs them.'
        }
        # Orphaned uninstall entries
        $orphans = @($apps | Where-Object {
                $exe = Get-CommandPath $_.UninstallString
                $exe -and $_.UninstallString -notmatch '(?i)msiexec' -and -not (Test-Path -LiteralPath $exe)
            })
        if ($orphans.Count) {
            Add-Finding -Category 'Registry' -Severity 'Low' -Title "$($orphans.Count) orphaned entries in Apps / Programs and Features" -Description 'These programs appear as installed but their uninstaller is missing, so they were probably deleted manually. The entries cannot be uninstalled normally.' `
                -Evidence ($orphans | ForEach-Object { "$($_.Name)  ->  $($_.Key)" }) -Fix 'If the program is really gone, export and delete its Uninstall registry key (shown above). Reinstall then uninstall if it is still partly present.' `
                -Command 'reg export "<key>" "%TEMP%\backup.reg"; reg delete "<key>" /f'
        }
        # Store apps that are commonly removed
        $appx = @()
        try {
            $bloat = 'king\.com\.|Microsoft\.BingNews|Microsoft\.GetHelp|Microsoft\.Getstarted|Microsoft\.MicrosoftSolitaireCollection|Microsoft\.MixedReality\.Portal|Microsoft\.SkypeApp|Microsoft\.WindowsFeedbackHub|Microsoft\.ZuneVideo|Clipchamp\.Clipchamp|Microsoft\.549981C3F5F10|Microsoft\.MicrosoftOfficeHub|Disney|SpotifyAB|Facebook|Instagram|TikTok|Twitter|AmazonVideo|Microsoft\.BingSports|Microsoft\.BingFinance|Microsoft\.People|Microsoft\.Messaging|Microsoft\.OneConnect|Microsoft\.Print3D|Microsoft\.3DBuilder|Microsoft\.Microsoft3DViewer|Microsoft\.Todos|MicrosoftTeams$|Microsoft\.GamingApp|Microsoft\.XboxApp|Microsoft\.XboxGamingOverlay|Microsoft\.Xbox\.TCUI|Microsoft\.XboxSpeechToTextOverlay|Microsoft\.XboxIdentityProvider'
            if ($isServer) { $bloat += '|Microsoft\.Xbox' }
            $appx = @(Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { $_.Name -match "^($bloat)" -and -not $_.IsFramework -and -not $_.NonRemovable } | Sort-Object Name -Unique)
        }
        catch {}
        if ($appx.Count) {
            Add-Finding -Category 'Programs' -Severity 'Low' -Title "$($appx.Count) pre-installed Store app(s) that can usually be removed" -Description 'Consumer and promotional apps that ship with Windows. They are optional; remove them if nobody uses them (Xbox components are needed for Xbox/Game Pass games).' `
                -Evidence ($appx | ForEach-Object { "$($_.Name)  $($_.Version)" }) -Fix 'Remove per user in Settings > Apps, or for all users with the commands below (run in an elevated PowerShell).' `
                -Command (($appx | ForEach-Object { "Get-AppxPackage -AllUsers -Name '$($_.Name)' | Remove-AppxPackage -AllUsers" }) -join "`n")
        }
        if ($isServer) {
            $consumer = @($apps | Where-Object { $_.Name -match '^(Spotify|Steam|Epic Games|Discord|WhatsApp|iTunes|uTorrent|BitTorrent|qBittorrent|VLC|Skype\b|Battle\.net|Origin|Telegram)' })
            if ($consumer.Count) {
                Add-Finding -Category 'Programs' -Severity 'Medium' -Title "$($consumer.Count) consumer program(s) installed on a server" -Description 'Games, media players and torrent clients do not belong on servers and increase attack surface.' `
                    -Evidence ($consumer | ForEach-Object { "$($_.Name)  $($_.Version)" }) -Fix 'Uninstall them.' -Command (($consumer | ForEach-Object { Get-MsiUninstallCommand $_ }) -join "`n")
            }
        }
    }

    #endregion

    #region ---------- Program logs and clean-up ----------

    Invoke-Check 'Windows component store (CBS log)' {
        $cbs = "$env:SystemRoot\Logs\CBS\CBS.log"
        if (Test-Path $cbs) {
            $lines = Read-FileTail $cbs 6MB
            $corrupt = @($lines | Where-Object { $_ -match 'Cannot repair member file|\[SR\] Could not reproject corrupted file|Corrupt file|STATUS_SXS_COMPONENT_STORE_CORRUPT|CBS_E_STORE_CORRUPTION|0x80073712' })
            if ($corrupt.Count) {
                Add-Finding -Category 'System' -Severity 'High' -Title 'Windows system file or component store corruption logged' -Description 'CBS.log shows corrupt system files or a damaged component store. This causes update failures and odd errors.' `
                    -Evidence ($corrupt | Select-Object -Last 15) -Fix "Run, in order, from an elevated prompt:`n1. DISM /Online /Cleanup-Image /RestoreHealth`n2. sfc /scannow`n3. Reboot and run sfc /scannow again. If DISM fails, use a matching Windows ISO as the source (/Source:wim:D:\sources\install.wim:1 /LimitAccess) or do an in-place repair upgrade." `
                    -Command "DISM /Online /Cleanup-Image /RestoreHealth`nsfc /scannow"
            }
        }
    }

    if (-not $Quick) {
        Invoke-Check 'Disk clean-up opportunities' {
            $places = [ordered]@{
                'Windows Temp'                    = "$env:SystemRoot\Temp"
                'Windows Update download cache'   = "$env:SystemRoot\SoftwareDistribution\Download"
                'Windows.old (previous Windows)'  = "$env:SystemDrive\Windows.old"
                'CBS/DISM logs'                   = "$env:SystemRoot\Logs\CBS"
                'Delivery Optimization cache'     = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
                'Windows Error Reporting'         = "$env:ProgramData\Microsoft\Windows\WER"
                'Recycle Bin (all users)'         = "$env:SystemDrive\`$Recycle.Bin"
                'IIS logs'                        = "$env:SystemDrive\inetpub\logs\LogFiles"
            }
            $rows = @(); $total = 0
            foreach ($n in $places.Keys) {
                $s = Get-FolderSize $places[$n]
                if ($s -gt 200MB) { $rows += '{0,-34} {1,10}  {2}' -f $n, (Format-Size $s), $places[$n]; $total += $s }
            }
            $userTemp = 0
            foreach ($u in @(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) { $userTemp += Get-FolderSize (Join-Path $u.FullName 'AppData\Local\Temp') }
            if ($userTemp -gt 200MB) { $rows += '{0,-34} {1,10}  {2}' -f 'User temp folders (all profiles)', (Format-Size $userTemp), "$env:SystemDrive\Users\*\AppData\Local\Temp"; $total += $userTemp }
            if ($total -gt 1GB) {
                Add-Finding -Category 'Disk' -Severity $(if ($total -gt 10GB) { 'Medium' } else { 'Low' }) -Title "About $(Format-Size $total) can likely be cleaned up" `
                    -Description 'Temporary files, caches, old logs and leftovers that are safe to clean with the right tools.' -Evidence $rows `
                    -Fix "1. Run Disk Cleanup as admin (cleanmgr), click 'Clean up system files' and tick Temporary files, Windows Update Cleanup, Previous Windows installation(s), Delivery Optimization files.`n2. Empty the Recycle Bin.`n3. For IIS logs, delete logs older than 30 days or schedule it.`n4. Clean the component store with DISM." `
                    -Command "cleanmgr /sageset:1 ; cleanmgr /sagerun:1`nDism /Online /Cleanup-Image /StartComponentCleanup`nGet-ChildItem C:\inetpub\logs\LogFiles -Recurse -File | Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) | Remove-Item"
            }
        }

        Invoke-Check 'Program logs (errors in application log files)' {
            $dirs = @($env:ProgramData, ${env:ProgramFiles}, ${env:ProgramFiles(x86)}) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
            $files = foreach ($d in $dirs) {
                Get-ChildItem -Path $d -Include *.log, *.txt -Recurse -Depth 4 -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $PF.Start -and $_.Length -gt 0 -and $_.FullName -notmatch '\\Microsoft\\(Windows|Search|Diagnosis|Network)\\|\\WER\\|\\Package Cache\\|\\Windows Defender\\|\\inetpub\\|readme|license|third.?party|notice' }
            }
            $files = @($files | Sort-Object LastWriteTime -Descending | Select-Object -First 300)
            $results = foreach ($f in $files) {
                $lines = Read-FileTail $f.FullName 262144
                $hits = @($lines | Where-Object { $_ -match '(?i)\b(error|fatal|exception|critical|failed|failure)\b' -and $_ -notmatch '(?i)\b0 errors?\b|no errors?|errors?\s*[:=]\s*0\b|without error|error.?level\s*[:=]\s*(info|debug)' })
                if ($hits.Count -ge 20) { [pscustomobject]@{ File = $f.FullName; Count = $hits.Count; Sample = @($hits | Select-Object -Last 5) ; Modified = $f.LastWriteTime } }
            }
            foreach ($r in @($results | Sort-Object Count -Descending | Select-Object -First 10)) {
                $app = ($r.File -replace '^(?i)[a-z]:\\(ProgramData|Program Files( \(x86\))?)\\', '' -split '\\')[0]
                $sample = $r.Sample | ForEach-Object { $s = "$_".Trim(); if ($s.Length -gt 300) { $s.Substring(0, 300) + '...' } else { $s } }
                Add-Finding -Category 'Program logs' -Severity $(if ($r.Count -ge 500) { 'Medium' } else { 'Low' }) -Title "$app log shows $($r.Count) error lines" `
                    -Description "The most recent part of this application log file contains many error/exception lines." `
                    -Evidence (@("File: $($r.File)", "Last written: $($r.Modified.ToString('yyyy-MM-dd HH:mm'))", 'Most recent error lines:') + $sample) `
                    -Fix "Open the log and look at the recurring error. Common causes: expired licence, wrong service account password, unreachable server or database, full disk, or a version that needs updating. Check the vendor's support site for the error text." `
                    -Command "notepad `"$($r.File)`""
            }
        }
    }

    #endregion

    #region ---------- Server roles ----------

    if ($PF.Roles -contains 'IIS (web server)') {
        Invoke-Check 'IIS web server' {
            Import-Module WebAdministration -ErrorAction Stop
            $pools = @(Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue)
            $stoppedPools = @($pools | Where-Object { $_.State -ne 'Started' })
            if ($stoppedPools.Count) {
                Add-Finding -Category 'IIS' -Severity 'Medium' -Title "$($stoppedPools.Count) IIS application pool(s) stopped" -Description 'Sites using a stopped pool return 503 Service Unavailable. Pools stop automatically after repeated crashes (Rapid-Fail Protection).' `
                    -Evidence ($stoppedPools | ForEach-Object { "$($_.Name): $($_.State)  identity $($_.processModel.identityType)" }) `
                    -Fix 'Check the System log for WAS events 5002/5021/5057 (crashes or bad identity password), fix the cause, then start the pool.' -Command 'Start-WebAppPool -Name "<pool>"'
            }
            $sites = @(Get-Website -ErrorAction SilentlyContinue)
            $stoppedSites = @($sites | Where-Object { $_.State -ne 'Started' })
            if ($stoppedSites.Count) {
                Add-Finding -Category 'IIS' -Severity 'Low' -Title "$($stoppedSites.Count) IIS site(s) stopped" -Description 'These websites are not serving requests. Remove them if they are no longer needed.' `
                    -Evidence ($stoppedSites | ForEach-Object { "$($_.Name)  bindings: $(($_.bindings.Collection | ForEach-Object { $_.bindingInformation }) -join ', ')" }) -Fix 'Start the site or delete it if obsolete.'
            }
            foreach ($site in $sites) {
                $logDir = [Environment]::ExpandEnvironmentVariables("$($site.logFile.directory)\W3SVC$($site.id)")
                $latest = Get-ChildItem $logDir -Filter 'u_ex*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if (-not $latest) { continue }
                $lines = Read-FileTail $latest.FullName 4MB
                $fields = ($lines | Where-Object { $_ -like '#Fields:*' } | Select-Object -Last 1)
                if (-not $fields) { continue }
                $cols = ($fields -replace '^#Fields:\s*', '') -split ' '
                $iStatus = [array]::IndexOf($cols, 'sc-status'); $iUri = [array]::IndexOf($cols, 'cs-uri-stem')
                if ($iStatus -lt 0) { continue }
                $data = @($lines | Where-Object { $_ -and $_ -notlike '#*' })
                $errs = @($data | Where-Object { $p = $_ -split ' '; $p.Count -gt $iStatus -and $p[$iStatus] -match '^5\d\d$' })
                if ($data.Count -gt 0 -and $errs.Count -ge 20) {
                    $top = $errs | Group-Object { $p = $_ -split ' '; "$($p[$iStatus]) $($p[$iUri])" } | Sort-Object Count -Descending | Select-Object -First 10
                    Add-Finding -Category 'IIS' -Severity $(if ($errs.Count / $data.Count -gt 0.05) { 'High' } else { 'Medium' }) -Title "Site '$($site.Name)' returned $($errs.Count) server errors (5xx)" `
                        -Description "In the latest log file ($($latest.Name)), $($errs.Count) of $($data.Count) requests failed with a 5xx error." `
                        -Evidence ($top | ForEach-Object { "$($_.Count)x  $($_.Name)" }) -Fix 'Check the Application event log and the application''s own logs for exceptions at the same times. Enable Failed Request Tracing for the failing URLs. 503 usually means the app pool stopped.'
                }
            }
            if ($PF.Roles -contains 'WSUS') {
                $mem = (Get-ItemProperty IIS:\AppPools\WsusPool -Name recycling.periodicRestart.privateMemory -ErrorAction SilentlyContinue).Value
                if ($mem -and $mem -gt 0 -and $mem -lt 4194304) {
                    Add-Finding -Category 'WSUS' -Severity 'Medium' -Title 'WSUS application pool memory limit is too low' -Description 'The default WsusPool private memory limit causes the WSUS console and clients to fail with HTTP 503 errors.' `
                        -Evidence "WsusPool privateMemory = $mem KB" -Fix 'Set the private memory limit to 0 (unlimited) or at least 4 GB.' -Command "Set-ItemProperty IIS:\AppPools\WsusPool -Name recycling.periodicRestart.privateMemory -Value 0"
                }
            }
        }
    }

    if ($PF.Roles -contains 'SQL Server') {
        Invoke-Check 'SQL Server' {
            $instRoot = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'
            $names = Get-ItemProperty "$instRoot\Instance Names\SQL" -ErrorAction SilentlyContinue
            if (-not $names) { return }
            $eolMap = @{ 9 = @('2005', '2016-04-12'); 10 = @('2008/2008 R2', '2019-07-09'); 11 = @('2012', '2022-07-12'); 12 = @('2014', '2024-07-09'); 13 = @('2016', '2026-07-14'); 14 = @('2017', '2027-10-12'); 15 = @('2019', '2030-01-08'); 16 = @('2022', '2033-01-11') }
            foreach ($p in $names.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
                $inst = $p.Name; $id = $p.Value
                $ver = Get-RegValue "$instRoot\$id\Setup" 'Version'
                $edition = Get-RegValue "$instRoot\$id\Setup" 'Edition'
                $server = if ($inst -eq 'MSSQLSERVER') { '.' } else { ".\$inst" }
                $major = if ($ver) { [int]($ver -split '\.')[0] } else { 0 }
                if ($eolMap.ContainsKey($major)) {
                    $eos = [datetime]::ParseExact($eolMap[$major][1], 'yyyy-MM-dd', $null)
                    if ($eos -lt (Get-Date)) {
                        Add-Finding -Category 'SQL Server' -Severity 'High' -Title "SQL Server $($eolMap[$major][0]) ($inst) is out of support" -Description "This SQL Server version stopped receiving security updates on $($eolMap[$major][1])." `
                            -Evidence "Instance $inst  version $ver  $edition" -Fix 'Plan an upgrade or migration to a supported SQL Server version, or buy Extended Security Updates.' -Reference 'https://learn.microsoft.com/lifecycle/products/?terms=sql%20server'
                    }
                }
                # ERRORLOG
                $params = Get-ItemProperty "$instRoot\$id\MSSQLServer\Parameters" -ErrorAction SilentlyContinue
                $elog = $null
                if ($params) { foreach ($a in $params.PSObject.Properties) { if ("$($a.Value)" -like '-e*') { $elog = "$($a.Value)".Substring(2) } } }
                if ($elog -and (Test-Path -LiteralPath $elog)) {
                    $lines = Read-FileTail $elog 4MB
                    $sev = @(); for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'Error: \d+, Severity: (1[7-9]|2\d)') { $sev += $lines[$i]; if ($i + 1 -lt $lines.Count) { $sev += '    ' + $lines[$i + 1] } } }
                    $logins = @($lines | Where-Object { $_ -match 'Login failed' })
                    if ($sev.Count) {
                        Add-Finding -Category 'SQL Server' -Severity 'High' -Title "SQL Server ($inst) logged high-severity errors" -Description 'Errors of severity 17 or higher mean resource problems, corruption or hardware faults.' `
                            -Evidence ($sev | Select-Object -Last 20) -Fix 'Look up each error number. Severity 23-24 (e.g. 823/824/825) indicates corruption or disk problems: run DBCC CHECKDB and check storage immediately.' -Command "DBCC CHECKDB WITH NO_INFOMSGS, ALL_ERRORMSGS"
                    }
                    if ($logins.Count -ge 50) {
                        $top = $logins | ForEach-Object { if ($_ -match "Login failed for user '([^']*)'.*?\[CLIENT: ([^\]]+)\]") { "$($Matches[1]) from $($Matches[2])" } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10
                        Add-Finding -Category 'SQL Server' -Severity 'Medium' -Title "$($logins.Count) failed SQL logins ($inst)" -Description 'Repeated failed logins are usually an application with a wrong password, or a brute-force attack on an exposed SQL port.' `
                            -Evidence ($top | ForEach-Object { "$($_.Count)x  $($_.Name)" }) -Fix 'Fix the connection string of the application listed, disable the sa login if unused, and do not expose port 1433 to the internet.'
                    }
                }
                # Live checks via Windows authentication
                $svcName = if ($inst -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { "MSSQL`$$inst" }
                if ($svcNames[$svcName].State -ne 'Running') { continue }
                $conn = New-Object System.Data.SqlClient.SqlConnection "Server=$server;Integrated Security=SSPI;Connect Timeout=5;Application Name=Painfree"
                try {
                    $conn.Open()
                    $q = {
                        param($sql)
                        $cmd = $conn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 20
                        $t = New-Object System.Data.DataTable; $t.Load($cmd.ExecuteReader()); , $t
                    }
                    $mem = (& $q "SELECT CAST(value_in_use AS bigint) AS v FROM sys.configurations WHERE name = 'max server memory (MB)'").Rows[0].v
                    if ($mem -ge 2147483647) {
                        Add-Finding -Category 'SQL Server' -Severity 'Medium' -Title "SQL Server ($inst) max server memory is not set" -Description 'By default SQL Server will take nearly all RAM and starve Windows and other services.' `
                            -Evidence 'max server memory (MB) = 2147483647 (default)' -Fix 'Set max server memory to leave 4 GB or 10-20% of RAM for Windows (whichever is larger).' `
                            -Command "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'max server memory (MB)', <value>; RECONFIGURE;"
                    }
                    $dbs = & $q @"
SELECT d.name, d.state_desc, d.recovery_model_desc, d.is_auto_shrink_on,
 (SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset b WHERE b.database_name = d.name AND b.type = 'D') AS last_full,
 (SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset b WHERE b.database_name = d.name AND b.type = 'L') AS last_log
FROM sys.databases d WHERE d.name <> 'tempdb' AND d.source_database_id IS NULL
"@
                    $offline = @(); $noFull = @(); $noLog = @(); $shrink = @()
                    foreach ($r in $dbs.Rows) {
                        if ($r.state_desc -ne 'ONLINE') { $offline += "$($r.name): $($r.state_desc)" }
                        if ($r.state_desc -eq 'ONLINE') {
                            if ($r.last_full -is [DBNull] -or ((Get-Date) - $r.last_full).Days -gt 7) { $noFull += "$($r.name): last full backup $(if ($r.last_full -is [DBNull]) { 'NEVER' } else { $r.last_full.ToString('yyyy-MM-dd') })" }
                            if ($r.recovery_model_desc -eq 'FULL' -and $r.name -ne 'model' -and ($r.last_log -is [DBNull] -or ((Get-Date) - $r.last_log).TotalHours -gt 24)) { $noLog += "$($r.name): last log backup $(if ($r.last_log -is [DBNull]) { 'NEVER' } else { $r.last_log.ToString('yyyy-MM-dd HH:mm') })" }
                        }
                        if ($r.is_auto_shrink_on) { $shrink += $r.name }
                    }
                    if ($offline.Count) { Add-Finding -Category 'SQL Server' -Severity 'High' -Title "$($offline.Count) database(s) not online ($inst)" -Description 'Databases in SUSPECT, RECOVERY_PENDING, OFFLINE or similar states are unavailable.' -Evidence $offline -Fix 'Check the SQL ERRORLOG for the reason. SUSPECT/RECOVERY_PENDING usually means missing/corrupt files or a full disk.' }
                    if ($noFull.Count) { Add-Finding -Category 'SQL Server' -Severity 'High' -Title "$($noFull.Count) database(s) without a recent full backup ($inst)" -Description 'No full backup recorded in msdb in the last 7 days. If your backup product does not register in msdb, confirm backups another way.' -Evidence $noFull -Fix 'Set up a maintenance plan, Ola Hallengren''s scripts, or your backup product to back up all databases daily, and test restores.' }
                    if ($noLog.Count) { Add-Finding -Category 'SQL Server' -Severity 'Medium' -Title "$($noLog.Count) FULL-recovery database(s) without log backups ($inst)" -Description 'In FULL recovery the transaction log grows until a log backup runs. Without log backups the log file will fill the disk.' -Evidence $noLog -Fix 'Schedule transaction log backups (e.g. every 15-60 minutes), or switch to SIMPLE recovery if point-in-time restore is not needed.' -Command 'ALTER DATABASE [<db>] SET RECOVERY SIMPLE;' }
                    if ($shrink.Count) { Add-Finding -Category 'SQL Server' -Severity 'Low' -Title "Auto-shrink is on for $($shrink.Count) database(s) ($inst)" -Description 'Auto-shrink causes heavy fragmentation and repeated grow/shrink cycles.' -Evidence $shrink -Fix 'Turn auto-shrink off.' -Command 'ALTER DATABASE [<db>] SET AUTO_SHRINK OFF;' }
                }
                catch { $PF.Errors.Add([pscustomobject]@{ Check = "SQL Server $inst (live checks)"; Error = $_.Exception.Message }) }
                finally { $conn.Dispose() }
            }
        }
    }

    if ($PF.Roles -contains 'Active Directory') {
        Invoke-Check 'Active Directory health' {
            $repl = Invoke-Native 'repadmin.exe' '/showrepl * /csv' 90
            if ($repl) {
                $rows = @($repl -split "`r?`n" | Where-Object { $_ } | ConvertFrom-Csv -ErrorAction SilentlyContinue)
                $failing = @($rows | Where-Object { [int]("0" + $_.'Number of Failures') -gt 0 })
                if ($failing.Count) {
                    Add-Finding -Category 'Active Directory' -Severity 'High' -Title "$($failing.Count) failing AD replication link(s)" -Description 'Domain controllers are not replicating changes. Users, passwords and Group Policy will be inconsistent between DCs.' `
                        -Evidence ($failing | ForEach-Object { "$($_.'Source DSA') -> $($_.'Destination DSA')  $($_.'Naming Context')  failures: $($_.'Number of Failures')  last success: $($_.'Last Success Time')  status: $($_.'Last Failure Status')" }) `
                        -Fix 'Look up the failure status code (e.g. 1722 RPC unavailable = network/firewall, 8524 = DNS, 8606/8614 = lingering objects/tombstone). Check DNS and connectivity between DCs, then repadmin /syncall /AdeP.' -Command 'repadmin /replsummary; repadmin /syncall /AdeP'
                }
            }
            if (-not $Quick) {
                $dc = Invoke-Native 'dcdiag.exe' '/q' 240
                if ($dc -and $dc.Trim()) {
                    Add-Finding -Category 'Active Directory' -Severity 'High' -Title 'dcdiag reported failed tests' -Description 'dcdiag (run in quiet mode) only prints tests that failed.' `
                        -Evidence ($dc -split "`r?`n" | Where-Object { $_.Trim() }) -Fix 'Address each failed test. Common ones: DNS registration (ipconfig /registerdns, restart Netlogon), SYSVOL/DFSR replication, time sync, and event log errors.' -Command 'dcdiag /v /c /e > "%TEMP%\dcdiag.txt"'
                }
            }
            $mig = Invoke-Native 'dfsrmig.exe' '/getglobalstate' 30
            if ($mig -and $mig -notmatch "Eliminated") {
                Add-Finding -Category 'Active Directory' -Severity 'High' -Title 'SYSVOL is still replicated with FRS' -Description 'FRS is deprecated and not supported for new DCs on Server 2019 and later. SYSVOL should use DFSR.' `
                    -Evidence $mig.Trim() -Fix 'Migrate SYSVOL to DFSR with dfsrmig (Prepared > Redirected > Eliminated).' -Reference 'https://learn.microsoft.com/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr'
            }
            try {
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $fqdn = "$env:COMPUTERNAME.$($domain.Name)"
                if ($domain.PdcRoleOwner.Name -eq $fqdn -and $PF.Info['Time source'] -match 'Local CMOS Clock|Free-running|VM IC Time') {
                    Add-Finding -Category 'Active Directory' -Severity 'High' -Title 'PDC emulator is not using a reliable external time source' -Description 'The PDC emulator is the time source for the whole domain. If it syncs from its own clock or the hypervisor, the domain time drifts.' `
                        -Evidence "Time source: $($PF.Info['Time source'])" -Fix 'Configure an external NTP source on the PDC and disable hypervisor time sync for it.' -Command 'w32tm /config /manualpeerlist:"time.windows.com,0x8 pool.ntp.org,0x8" /syncfromflags:manual /reliable:yes /update; w32tm /resync'
                }
                $PF.Info['FSMO PDC'] = $domain.PdcRoleOwner.Name
            }
            catch {}
            if (Get-Module -ListAvailable ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction SilentlyContinue
                if ($rb -and -not $rb.EnabledScopes.Count) {
                    Add-Finding -Category 'Active Directory' -Severity 'Low' -Title 'AD Recycle Bin is not enabled' -Description 'Without the Recycle Bin, accidentally deleted users and groups are hard to restore.' `
                        -Fix 'Enable it (one-way change, forest level 2008 R2+).' -Command 'Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name'
                }
            }
            if ($svcNames['Spooler'].State -eq 'Running') {
                Add-Finding -Category 'Active Directory' -Severity 'Medium' -Title 'Print Spooler is running on a domain controller' -Description 'Microsoft recommends disabling the Print Spooler on DCs (PrintNightmare and coercion attacks).' `
                    -Fix 'Stop and disable the Print Spooler service unless this DC is also a print server.' -Command 'Stop-Service Spooler; Set-Service Spooler -StartupType Disabled'
            }
        }
    }

    if ($PF.Roles -contains 'DNS Server') {
        Invoke-Check 'DNS server' {
            $fwd = Get-DnsServerForwarder -ErrorAction SilentlyContinue
            $dead = @()
            foreach ($ip in @($fwd.IPAddress)) {
                if (-not $ip) { continue }
                $r = Resolve-DnsName -Name 'www.microsoft.com' -Server "$ip" -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
                if (-not $r) { $dead += "$ip" }
            }
            if ($dead.Count) {
                Add-Finding -Category 'DNS' -Severity 'Medium' -Title "$($dead.Count) DNS forwarder(s) not responding" -Description 'Dead forwarders slow down every internet lookup while the server waits for timeouts.' `
                    -Evidence $dead -Fix 'Remove or replace the dead forwarders (e.g. with your ISP''s or a public resolver).' -Command "Remove-DnsServerForwarder -IPAddress $($dead -join ',') -Force"
            }
            $sc = Get-DnsServerScavenging -ErrorAction SilentlyContinue
            if ($sc -and -not $sc.ScavengingState -and $isDC) {
                Add-Finding -Category 'DNS' -Severity 'Low' -Title 'DNS scavenging is disabled' -Description 'Stale DNS records from old machines and changed IPs are never removed, causing name resolution to wrong addresses.' `
                    -Fix 'Enable aging on AD-integrated zones and scavenging on one DNS server (default 7+7 days).' -Command 'Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 -ApplyOnAllZones'
            }
        }
    }

    if ($PF.Roles -contains 'DHCP Server') {
        Invoke-Check 'DHCP server' {
            foreach ($s in @(Get-DhcpServerv4ScopeStatistics -ErrorAction Stop)) {
                if ($s.PercentageInUse -ge 85) {
                    Add-Finding -Category 'DHCP' -Severity $(if ($s.PercentageInUse -ge 95) { 'High' } else { 'Medium' }) -Title "DHCP scope $($s.ScopeId) is $([math]::Round($s.PercentageInUse))% full" `
                        -Description 'When a scope runs out of addresses new devices get 169.254 addresses and no network.' -Evidence "In use: $($s.AddressesInUse)  Free: $($s.AddressesFree)" `
                        -Fix 'Shorten the lease time, remove stale leases, or expand the scope / add a new one.' -Command "Set-DhcpServerv4Scope -ScopeId $($s.ScopeId) -LeaseDuration 1.00:00:00"
                }
            }
            $inactive = @(Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object State -ne 'Active')
            if ($inactive.Count) {
                Add-Finding -Category 'DHCP' -Severity 'Low' -Title "$($inactive.Count) inactive DHCP scope(s)" -Description 'Inactive scopes do not hand out addresses. Remove them if obsolete.' -Evidence ($inactive | ForEach-Object { "$($_.ScopeId) $($_.Name)" }) -Fix 'Activate or delete the scope.'
            }
        }
    }

    if ($PF.Roles -contains 'Hyper-V') {
        Invoke-Check 'Hyper-V' {
            $vms = @(Get-VM -ErrorAction Stop)
            $bad = @($vms | Where-Object { $_.Status -and $_.Status -ne 'Operating normally' })
            if ($bad.Count) {
                Add-Finding -Category 'Hyper-V' -Severity 'High' -Title "$($bad.Count) virtual machine(s) report a problem" -Description 'Hyper-V reports these VMs are not operating normally.' `
                    -Evidence ($bad | ForEach-Object { "$($_.Name): $($_.State) - $($_.Status)" }) -Fix 'Check Hyper-V Manager and the Hyper-V-VMMS / Worker event logs for the VM.'
            }
            $old = @(Get-VMSnapshot -VMName * -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-7) })
            if ($old.Count) {
                Add-Finding -Category 'Hyper-V' -Severity 'Medium' -Title "$($old.Count) checkpoint(s) older than 7 days" -Description 'Checkpoints are not backups. Old checkpoints grow AVHDX files, hurt performance and can fill the disk. Stale checkpoints are often left by failed backup jobs.' `
                    -Evidence ($old | ForEach-Object { "$($_.VMName): '$($_.Name)' created $($_.CreationTime.ToString('yyyy-MM-dd'))" }) -Fix 'Delete checkpoints that are no longer needed (they merge automatically).' -Command 'Get-VMSnapshot -VMName "<vm>" | Where-Object CreationTime -lt (Get-Date).AddDays(-7) | Remove-VMSnapshot'
            }
            $rep = @(Get-VMReplication -ErrorAction SilentlyContinue | Where-Object { $_.Health -ne 'Normal' })
            if ($rep.Count) {
                Add-Finding -Category 'Hyper-V' -Severity 'High' -Title "$($rep.Count) VM replica(s) unhealthy" -Description 'Hyper-V Replica is not keeping the replica copies up to date.' `
                    -Evidence ($rep | ForEach-Object { "$($_.VMName): $($_.Health) $($_.State)" }) -Fix 'Check the replication state in Hyper-V Manager; resume or resynchronise replication.' -Command 'Resume-VMReplication -VMName "<vm>"'
            }
            $turnoff = @($vms | Where-Object { "$($_.AutomaticStopAction)" -eq 'TurnOff' })
            if ($turnoff.Count) {
                Add-Finding -Category 'Hyper-V' -Severity 'Low' -Title "$($turnoff.Count) VM(s) are powered off hard when the host shuts down" -Description 'AutomaticStopAction = TurnOff is like pulling the power on the VM during host restarts.' `
                    -Evidence ($turnoff | ForEach-Object { $_.Name }) -Fix 'Use Save or ShutDown instead.' -Command 'Set-VM -Name "<vm>" -AutomaticStopAction ShutDown'
            }
        }
    }

    if ($PF.Roles -contains 'Exchange') {
        Invoke-Check 'Exchange Server' {
            $setup = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
            $maj = Get-RegValue $setup 'MsiProductMajor'; $min = Get-RegValue $setup 'MsiProductMinor'; $bld = Get-RegValue $setup 'MsiBuildMajor'
            if ($null -ne $maj) {
                $name = $null
                if ($maj -eq 15 -and $min -eq 0) { $name = 'Exchange 2013 (ended 2023-04-11)' }
                elseif ($maj -eq 15 -and $min -eq 1) { $name = 'Exchange 2016 (ended 2025-10-14)' }
                elseif ($maj -eq 15 -and $min -eq 2 -and $bld -lt 2562) { $name = 'Exchange 2019 (ended 2025-10-14)' }
                if ($name) {
                    Add-Finding -Category 'Exchange' -Severity 'High' -Title "$name is out of support" -Description 'This Exchange version no longer receives security updates, and on-premises Exchange is a top attack target.' `
                        -Evidence "Version $maj.$min.$bld" -Fix 'Upgrade to Exchange Server Subscription Edition (SE) or migrate to Exchange Online.' -Reference 'https://learn.microsoft.com/exchange/new-features/build-numbers-and-release-dates'
                }
            }
            elseif (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14') {
                Add-Finding -Category 'Exchange' -Severity 'Critical' -Title 'Exchange 2010 is installed (ended 2020-10-13)' -Description 'Exchange 2010 has been unsupported for years and has critical unpatched vulnerabilities.' -Fix 'Migrate off Exchange 2010 urgently.'
            }
            try {
                Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
                $q = @(Get-Queue -ErrorAction Stop | Where-Object { $_.MessageCount -gt 100 })
                if ($q.Count) {
                    Add-Finding -Category 'Exchange' -Severity 'High' -Title "$($q.Count) Exchange mail queue(s) backed up" -Description 'Messages are queuing instead of being delivered.' `
                        -Evidence ($q | ForEach-Object { "$($_.Identity): $($_.MessageCount) messages, status $($_.Status), last error: $($_.LastError)" }) -Fix 'Check the LastError for each queue (DNS, connector, smart host, certificate or back pressure problems).'
                }
            }
            catch {}
        }
    }

    #endregion

    #region ---------- Report ----------

    $order = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $sorted = @($PF.Findings | Sort-Object @{ e = { $order[$_.Severity] } }, Category, Title)
    $counts = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') { $counts[$s] = @($sorted | Where-Object Severity -eq $s).Count }
    $score = [math]::Max(0, 100 - ($counts.Critical * 15 + $counts.High * 7 + $counts.Medium * 3 + $counts.Low * 1))

    $payload = [ordered]@{
        version  = $PainfreeVersion
        generated = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        score    = $score
        counts   = $counts
        info     = $PF.Info
        findings = $sorted
        errors   = $PF.Errors.ToArray()
        checks   = $PF.Checks.ToArray()
    }
    $json = $payload | ConvertTo-Json -Depth 6 -Compress
    $json = $json -replace '</', '<\/' -replace '<!--', '<\!--'

    $html = @'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Painfree report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5d6675;--line:#e3e6eb;--accent:#2563eb;
--critical:#b42318;--high:#d9480f;--medium:#b7791f;--low:#2f6fb3;--info:#6b7280;--code:#f1f3f6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--text:#e6e9ef;--muted:#9aa3b2;--line:#2b3240;--accent:#6ea0ff;
--critical:#ff6b5e;--high:#ff8c4b;--medium:#e8b14c;--low:#6aa7ec;--info:#9aa3b2;--code:#11151c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 60px}
h1{font-size:26px;margin:0}h2{font-size:18px;margin:28px 0 10px}.muted{color:var(--muted)}
header{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;margin-bottom:18px}
.score{display:flex;align-items:center;gap:12px}.ring{width:64px;height:64px;border-radius:50%;display:grid;place-items:center;font-weight:700;font-size:20px;border:6px solid var(--accent)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer;user-select:none}
.card b{display:block;font-size:24px}.card.off{opacity:.45}
.sys{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:6px 14px;display:grid;grid-template-columns:minmax(150px,220px) 1fr;column-gap:16px}
.sys div{padding:5px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.sys div:nth-last-child(-n+2){border-bottom:0}
.tools{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
input,select,button{font:inherit;color:var(--text);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:7px 10px}
input{flex:1;min-width:200px}button{cursor:pointer}
.f{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--sev);border-radius:10px;margin:8px 0}
.f summary{list-style:none;cursor:pointer;padding:12px 14px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.f summary::-webkit-details-marker{display:none}
.badge{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--sev);min-width:64px}
.cat{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:20px;padding:1px 8px}
.t{font-weight:600;flex:1;min-width:220px}
.body{padding:0 14px 14px}.body h4{margin:12px 0 4px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12.5px/1.45 Consolas,ui-monospace,monospace;margin:0}
.fix{white-space:pre-wrap}.cmd{position:relative}.cmd button{position:absolute;top:6px;right:6px;font-size:12px;padding:3px 8px}
.note{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
a{color:var(--accent)}footer{margin-top:30px;font-size:13px}
@media print{.tools,.cards{display:none}.f{break-inside:avoid}details{display:block}details>.body{display:block}}
</style></head><body><div class="wrap">
<header><div><h1>Painfree report</h1><div class="muted" id="sub"></div></div>
<div class="score"><div class="ring" id="score"></div><div><b>Health score</b><div class="muted" style="font-size:13px">100 = no issues found</div></div></div></header>
<div class="note" style="margin-bottom:14px"><b>Read-only scan.</b> Nothing on this machine was changed. Review each proposed fix before running it, and back up or create a restore point first. Commands are shown as examples; replace values in &lt;angle brackets&gt;.</div>
<div class="cards" id="cards"></div>
<h2>System</h2><div class="sys" id="sys"></div>
<h2>Findings <span class="muted" id="shown"></span></h2>
<div class="tools"><input id="q" placeholder="Search findings..."><select id="cat"><option value="">All categories</option></select>
<button id="exp">Expand all</button><button id="col">Collapse all</button><button onclick="window.print()">Print / PDF</button></div>
<div id="list"></div>
<div id="errs"></div>
<footer class="muted" id="foot"></footer>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('data').textContent);
var SEV=['Critical','High','Medium','Low','Info'];
var on={Critical:1,High:1,Medium:1,Low:1,Info:0};
function el(t,c,txt){var e=document.createElement(t);if(c)e.className=c;if(txt!=null)e.textContent=txt;return e;}
function arr(x){return x==null?[]:(Array.isArray(x)?x:[x]);}
var findings=arr(D.findings);
document.getElementById('sub').textContent=(D.info['Computer']||'')+' - '+D.generated+' - Painfree '+D.version;
var sc=document.getElementById('score');sc.textContent=D.score;
sc.style.borderColor=D.score>=80?'#2f9e44':D.score>=50?'var(--medium)':'var(--critical)';
var cards=document.getElementById('cards');
SEV.forEach(function(s){var c=el('div','card'+(on[s]?'':' off'));c.style.borderTop='4px solid var(--'+s.toLowerCase()+')';
c.appendChild(el('b',null,D.counts[s]||0));c.appendChild(el('span','muted',s));
c.onclick=function(){on[s]=!on[s];c.classList.toggle('off',!on[s]);render();};cards.appendChild(c);});
var sys=document.getElementById('sys');Object.keys(D.info).forEach(function(k){sys.appendChild(el('div','muted',k));sys.appendChild(el('div',null,D.info[k]));});
var cats={};findings.forEach(function(f){cats[f.Category]=1;});
var sel=document.getElementById('cat');Object.keys(cats).sort().forEach(function(c){var o=el('option',null,c);o.value=c;sel.appendChild(o);});
function block(parent,title,text,cls,copy){if(!text)return;parent.appendChild(el('h4',null,title));
 var w=el('div',copy?'cmd':null);var p=el(cls==='fix'?'div':'pre',cls||null,text);w.appendChild(p);
 if(copy){var b=el('button',null,'Copy');b.onclick=function(ev){ev.preventDefault();navigator.clipboard.writeText(text).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1200);});};w.appendChild(b);}
 parent.appendChild(w);}
function render(){var q=document.getElementById('q').value.toLowerCase(),c=sel.value,list=document.getElementById('list');list.innerHTML='';var n=0;
 findings.forEach(function(f){if(!on[f.Severity])return;if(c&&f.Category!==c)return;
  if(q&&(f.Title+' '+f.Description+' '+f.Evidence+' '+f.Fix+' '+f.Category).toLowerCase().indexOf(q)<0)return;n++;
  var d=el('details','f');d.style.setProperty('--sev','var(--'+f.Severity.toLowerCase()+')');
  var s=el('summary');s.appendChild(el('span','badge',f.Severity));s.appendChild(el('span','t',f.Title));s.appendChild(el('span','cat',f.Category));d.appendChild(s);
  var b=el('div','body');if(f.Description)b.appendChild(el('div',null,f.Description));
  block(b,'Evidence',f.Evidence);block(b,'Proposed fix',f.Fix,'fix');block(b,'Command (review before running)',f.Command,null,true);
  if(f.Reference){b.appendChild(el('h4',null,'More information'));var a=el('a',null,f.Reference);a.href=f.Reference;a.target='_blank';a.rel='noopener';b.appendChild(a);}
  d.appendChild(b);list.appendChild(d);});
 if(!n)list.appendChild(el('div','note','No findings match the current filters.'));
 document.getElementById('shown').textContent='('+n+' of '+findings.length+')';}
document.getElementById('q').oninput=render;sel.onchange=render;
document.getElementById('exp').onclick=function(){document.querySelectorAll('details.f').forEach(function(d){d.open=true;});};
document.getElementById('col').onclick=function(){document.querySelectorAll('details.f').forEach(function(d){d.open=false;});};
var errs=arr(D.errors);if(errs.length){var e=document.getElementById('errs');e.appendChild(el('h2',null,'Checks that could not complete'));
 var p=el('pre',null,errs.map(function(x){return x.Check+': '+x.Error;}).join('\n'));e.appendChild(p);}
var checks=arr(D.checks);var tot=checks.reduce(function(a,c){return a+(c.Seconds||0);},0);
document.getElementById('foot').textContent=checks.length+' checks ran in '+Math.round(tot)+' s. Painfree is read-only and makes no changes.';
render();
})();
</script></body></html>
'@
    $html = $html.Replace('__DATA__', $json)

    if (-not $OutputPath) {
        $desk = [Environment]::GetFolderPath('Desktop')
        if (-not $desk -or -not (Test-Path $desk)) { $desk = $env:TEMP }
        $OutputPath = Join-Path $desk ("Painfree-{0}-{1:yyyyMMdd-HHmm}.html" -f $env:COMPUTERNAME, (Get-Date))
    }
    elseif ((Test-Path $OutputPath -PathType Container)) {
        $OutputPath = Join-Path $OutputPath ("Painfree-{0}-{1:yyyyMMdd-HHmm}.html" -f $env:COMPUTERNAME, (Get-Date))
    }
    [IO.File]::WriteAllText($OutputPath, $html, (New-Object Text.UTF8Encoding $false))
    $jsonPath = [IO.Path]::ChangeExtension($OutputPath, '.json')
    [IO.File]::WriteAllText($jsonPath, ($payload | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding $false))

    Write-Host ''
    Write-Host ('  Health score: {0}/100   Critical {1}  High {2}  Medium {3}  Low {4}  Info {5}' -f $score, $counts.Critical, $counts.High, $counts.Medium, $counts.Low, $counts.Info) -ForegroundColor Cyan
    Write-Host "  Report: $OutputPath" -ForegroundColor Green
    Write-Host "  Data:   $jsonPath" -ForegroundColor DarkGray
    Write-Host ''
    if (-not $NoOpen) { try { Start-Process $OutputPath } catch { Write-Host '  (Could not open a browser. Copy the report to a PC to view it.)' -ForegroundColor DarkGray } }

    #endregion
}

Start-Painfree -Days $Days -OutputPath $OutputPath -NoOpen:$NoOpen -Quick:$Quick
