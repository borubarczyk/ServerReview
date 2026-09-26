<#
.SYNOPSIS
    Przegląd serwerów – zbiorczy audyt stanu serwerów Windows w domenie z GUI (WPF).

.DESCRIPTION
    Łączy się równolegle (WinRM / Invoke-Command) ze wszystkimi serwerami z listy i zbiera:
      - system: uptime, oczekujący restart, ostatnia aktualizacja, CPU/RAM, role, WSUS
      - dyski, adresację IP, porty nasłuchujące, aktywne połączenia (z procesem i usługą)
      - usługi (nie-Microsoft, zatrzymane automatyczne, konta usług, niecytowane ścieżki)
      - harmonogram zadań (poza \Microsoft\) z wynikiem ostatniego uruchomienia
      - błędy i zdarzenia krytyczne z System/Application, historię restartów
      - zdarzenia bezpieczeństwa (nieudane logowania, zmiany kont i grup, czyszczenie logów, nowe usługi)
      - oprogramowanie, aktualizacje KB, grupy uprzywilejowane, konta lokalne, sesje RDP
      - udziały, autostart, certyfikaty, zawartość wskazanych folderów
      - Hyper-V: maszyny wirtualne i checkpointy
      - podstawowy hardening (SMBv1, NLA, WDigest, NTLM, Defender, zapora, LLMNR, autologon...)
    Każdy skan zapisuje migawkę (JSON). Kolejny skan porównuje się z poprzednim i pokazuje,
    co NOWEGO pojawiło się na serwerze (usługi, zadania, porty, admini, autostart, oprogramowanie).

.NOTES
    Wymagania:
      - Windows PowerShell 5.1 na stacji, z której uruchamiasz (WPF)
      - WinRM na serwerach (domyślnie włączony na Windows Server 2012+), port 5985
      - konto z uprawnieniami administratora lokalnego na serwerach (odczyt dziennika Security)
    Plik musi być zapisany jako UTF-8 z BOM (polskie znaki w Windows PowerShell 5.1).
#>
[CmdletBinding()]
param(
    [string]$ServerListFile
)

#region ── Konfiguracja ─────────────────────────────────────────────────────────
$Base = if ($PSScriptRoot) { $PSScriptRoot } else { Join-Path $env:USERPROFILE 'Documents\ServerReview' }

$Config = [ordered]@{
    EventDays              = 7        # domyślny zakres zdarzeń (można zmienić w GUI)
    MaxEvents              = 3000     # limit pobieranych zdarzeń na dziennik
    IncludeWarnings        = $false   # $true = także ostrzeżenia z System/Application (dużo szumu)
    DiskWarnPct            = 20
    DiskCritPct            = 10
    UptimeWarnDays         = 45
    PatchWarnDays          = 45
    CertWarnDays           = 30
    CheckpointWarnDays     = 7
    FailedLogonWarn        = 25
    RecentSoftwareDays     = 14
    RamWarnPct             = 90
    CommitWarnPct          = 90       # zajętość pamięci wirtualnej (commit) [%]
    TimeSkewWarnSec        = 60       # różnica czasu serwera względem stacji skanującej [s]
    TimeSkewCritSec        = 300      # Kerberos domyślnie toleruje 5 minut
    SupportWarnDays        = 365      # uprzedzaj o końcu wsparcia systemu [dni]
    DiskWearWarnPct        = 90       # zużycie SSD wg licznika niezawodności [%]
    DiskRetryWarn          = 10       # tyle zdarzeń 129/153/157 (reset/ponowienie I/O) w okresie = ostrzeżenie
    BugCheckCritCount      = 2        # tyle awarii BSOD w okresie = problem krytyczny
    ThrottleLimit          = 25       # ile serwerów skanować równolegle
    ScanTimeoutSec         = 900
    SnapshotsToKeep        = 30
    # Foldery sprawdzane na KAŻDYM serwerze (zmienne środowiskowe są rozwijane zdalnie)
    Folders                = @('C:\Temp', 'C:\Windows\Temp', 'C:\Users\Public\Downloads', 'C:\Install', 'C:\Scripts')
    # Usługi automatyczne, których zatrzymanie nie jest problemem (obsługiwane wildcardy)
    IgnoredStoppedServices = @(
        'gupdate', 'gupdatem', 'GoogleUpdater*', 'edgeupdate', 'edgeupdatem', 'MicrosoftEdgeElevationService',
        'sppsvc', 'RemoteRegistry', 'MapsBroker', 'ShellHWDetection', 'tiledatamodelsvc', 'CDPSvc',
        'CDPUserSvc_*', 'OneSyncSvc_*', 'WpnUserService_*', 'WbioSrvc', 'TrustedInstaller', 'clr_optimization_*',
        'stisvc', 'BITS', 'DoSvc', 'wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'AGSService', 'Net Driver HPZ12',
        'Pml Driver HPZ12', 'IaasVmProvider', 'WSearch', 'ClickToRunSvc', 'ose64', 'AdobeARMservice', 'uhssvc',
        'dmwappushservice', 'lfsvc', 'BthAvctpSvc', 'camsvc', 'Intel(R) TPM Provisioning Service', 'SysMain'
    )
    # Porty uznawane za wrażliwe przy przeglądzie reguł zapory (sekcja Ekspozycja)
    ExposedPorts           = @(21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986)
    # Subskrypcje WMI obecne w czystym systemie – nie są zgłaszane (sekcja Trwałość)
    IgnoredWmiConsumers    = @('SCM Event Log Filter', 'SCM Event Log Consumer', 'BVTFilter', 'BVTConsumer')
    # Wymagane podkategorie audytu. GUID jest niezależny od języka systemu. Need: 1 = sukces, 2 = niepowodzenie, 3 = oba
    AuditRequired          = @(
        @{ Guid = '0CCE9215-69AE-11D9-BED3-505054503030'; Need = 2; Why = 'nieudane logowania (4625)' }
        @{ Guid = '0CCE9242-69AE-11D9-BED3-505054503030'; Need = 2; Why = 'nieudane uwierzytelnienia Kerberos (4771)'; DcOnly = $true }
        @{ Guid = '0CCE9235-69AE-11D9-BED3-505054503030'; Need = 1; Why = 'zmiany kont (4720, 4722, 4724, 4726, 4740)' }
        @{ Guid = '0CCE9237-69AE-11D9-BED3-505054503030'; Need = 1; Why = 'zmiany grup (4728, 4732, 4756)' }
        @{ Guid = '0CCE9211-69AE-11D9-BED3-505054503030'; Need = 1; Why = 'instalacja usług (4697)' }
        @{ Guid = '0CCE9227-69AE-11D9-BED3-505054503030'; Need = 1; Why = 'tworzenie zadań harmonogramu (4698)' }
        @{ Guid = '0CCE922F-69AE-11D9-BED3-505054503030'; Need = 1; Why = 'zmiany polityki audytu' }
    )
    # Koniec rozszerzonego wsparcia Microsoft wg numeru kompilacji (bez płatnego ESU)
    OsSupportEnd           = @{ '9200' = '2023-10-10'; '9600' = '2023-10-10'; '14393' = '2027-01-12'; '17763' = '2029-01-09'; '20348' = '2031-10-14'; '26100' = '2034-10-10' }
    # Sekcje pomijane podczas skanu – ustawiane w oknie Ustawienia (puste = skanuj wszystko)
    SkipSections           = @()
    ServerListFile         = Join-Path $Base 'servers.txt'
    SnapshotDir            = Join-Path $Base 'Snapshots'
    ReportDir              = Join-Path $Base 'Reports'
    SettingsFile           = Join-Path $Base 'settings.json'   # zapis z okna Ustawienia (nadpisuje wartości powyżej)
}
if ($ServerListFile) { $Config.ServerListFile = $ServerListFile }
#endregion

#region ── Start w trybie STA ───────────────────────────────────────────────────
# WPF wymaga wątku STA; skrypt jest pisany pod Windows PowerShell 5.1 – z PowerShell 7 (Core) też przełączamy się na powershell.exe
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA' -or $PSVersionTable.PSEdition -eq 'Core') {
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-STA', '-File', "`"$PSCommandPath`"")
    if ($ServerListFile) { $argList += @('-ServerListFile', "`"$ServerListFile`"") }   # nie gub parametru przy ponownym uruchomieniu
    Start-Process -FilePath $exe -ArgumentList $argList
    return
}
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
New-Item -ItemType Directory -Force -Path $Base | Out-Null
#endregion

#region ── Kolektor (uruchamiany zdalnie na każdym serwerze) ─────────────────────
$Collector = {
    param([int]$Days, [string[]]$Folders, [int]$MaxEvents, [bool]$IncludeWarnings, [string[]]$SkipSections = @(), [int[]]$ExposedPorts = @())

    # Moduły ładujemy jawnie, ZANIM włączymy ErrorActionPreference = 'Stop'. Autoładowanie pod 'Stop' potrafi się nie udać
    # (np. SmbShare po wcześniejszym Get-WindowsFeature: "module could not be loaded"). Brak modułu na danym systemie nie jest błędem.
    foreach ($m in 'SmbShare', 'NetTCPIP', 'NetAdapter', 'DnsClient', 'NetSecurity', 'ScheduledTasks', 'Defender', 'Microsoft.PowerShell.LocalAccounts') {
        Import-Module $m -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    if (Get-Service vmms -ErrorAction SilentlyContinue) { Import-Module Hyper-V -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }

    $ErrorActionPreference = 'Stop'
    $ProgressPreference    = 'SilentlyContinue'
    $sw    = [Diagnostics.Stopwatch]::StartNew()
    $now   = Get-Date
    $since = $now.AddDays(-$Days)
    $errs  = New-Object System.Collections.Generic.List[string]
    try {

    # $Key = klucz sekcji (jak w danych wynikowych); sekcje z listy $SkipSections są pomijane
    function Want([string]$Key) { -not $Key -or $SkipSections -notcontains $Key }
    function S([string]$Key, [string]$Section, [scriptblock]$Block) {
        if (-not (Want $Key)) { return }
        try { & $Block } catch { $errs.Add("$Section`: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber): $("$($_.InvocationInfo.Line)".Trim())]") }
    }
    function D($dt) { if ($dt) { try { ([datetime]$dt).ToString('yyyy-MM-dd HH:mm') } catch { "$dt" } } else { '' } }
    function Short([string]$s, [int]$n) { $s = "$s" -replace '\s+', ' '; if ($s.Length -gt $n) { $s.Substring(0, $n) + '...' } else { $s.Trim() } }

    # ── System ──
    $sys = [ordered]@{}
    try {
        $os  = Get-CimInstance Win32_OperatingSystem
        $cs  = Get-CimInstance Win32_ComputerSystem
        $cpu = @(Get-CimInstance Win32_Processor)
        $roles = @('Stacja robocza', 'Stacja robocza (domena)', 'Serwer autonomiczny', 'Serwer członkowski', 'Kontroler domeny', 'Kontroler domeny (PDC)')
        $ubr = ''
        try { $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR } catch {}
        $sys.ComputerName  = $env:COMPUTERNAME
        $sys.FQDN          = $env:COMPUTERNAME
        try { $sys.FQDN = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch {}
        $sys.OS            = $os.Caption
        $sys.Build         = if ($ubr) { "$($os.Version).$ubr" } else { $os.Version }
        $sys.OSInstallDate = D $os.InstallDate
        $sys.LastBoot      = D $os.LastBootUpTime
        $sys.UptimeDays    = [math]::Round(($now - $os.LastBootUpTime).TotalDays, 1)
        $sys.Model         = "$($cs.Manufacturer) $($cs.Model)".Trim()
        $sys.CPUName       = ("$($cpu[0].Name)" -replace '\s+', ' ').Trim()
        $sys.Cores         = [int](($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
        $sys.CpuLoad       = [int](($cpu | Measure-Object LoadPercentage -Average).Average)
        $sys.RamGB         = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        $sys.RamUsedPct    = [int](100 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize * 100))
        $sys.Domain        = $cs.Domain
        $sys.DomainRole    = $roles[[int]$cs.DomainRole]
        $sys.IsDC          = ([int]$cs.DomainRole -ge 4)
        $sys.DomainRoleId  = [int]$cs.DomainRole
        $sys.BuildNumber   = [int]$os.BuildNumber
        # Pamięć wirtualna (commit): limit = RAM + pliki stronicowania
        $sys.CommitLimitGB = [math]::Round($os.TotalVirtualMemorySize / 1MB, 1)
        $sys.CommitUsedPct = if ($os.TotalVirtualMemorySize) { [int](100 - ($os.FreeVirtualMemory / $os.TotalVirtualMemorySize * 100)) } else { $null }
        $sys.PageFileAuto  = [bool]$cs.AutomaticManagedPagefile
    } catch { $errs.Add("System: $($_.Exception.Message)") }
    try { $sys.PageFiles = (@(Get-CimInstance Win32_PageFileUsage | ForEach-Object { "$($_.Name) $($_.AllocatedBaseSize) MB (szczyt $($_.PeakUsage) MB)" }) -join '; ') } catch { $sys.PageFiles = '' }
    $sys.ResourceExhaustion = 0
    try { $sys.ResourceExhaustion = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Id = 2004; StartTime = $since } -MaxEvents 500 -ErrorAction SilentlyContinue).Count } catch {}

    # ── Czas ── (typ źródła z rejestru W32Time: NT5DS / NTP / NoSync / AllSync – wartości niezależne od języka)
    try {
        $w32 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction Stop
        $sys.TimeSource = "$($w32.Type)"; $sys.NtpServer = "$($w32.NtpServer)"
    } catch { $sys.TimeSource = ''; $sys.NtpServer = '' }
    $hvts = $false
    try {
        # gość Hyper-V: usługa vmictimesync działa tylko w maszynie wirtualnej z usługami integracji
        $vts = Get-Service vmictimesync -ErrorAction SilentlyContinue
        $vtp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider' -ErrorAction SilentlyContinue
        $hvts = ($vts -and "$($vts.Status)" -eq 'Running' -and (-not $vtp -or $vtp.Enabled -ne 0))
    } catch {}
    $sys.HvTimeSync = [bool]$hvts

    $pr = @()
    try {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pr += 'CBS' }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pr += 'Windows Update' }
        $a = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
        $b = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
        if ($a -ne $b) { $pr += 'zmiana nazwy komputera' }
    } catch {}
    $sys.PendingReboot = ($pr -join ', ')

    # ── Aktualizacje ──
    $hfAll = @(S '' 'Aktualizacje' {
        Get-HotFix | ForEach-Object {
            $dt = $null; try { $dt = $_.InstalledOn } catch {}
            [pscustomobject]@{ HotFixID = $_.HotFixID; Description = $_.Description; InstalledOn = $(D $dt); InstalledBy = $_.InstalledBy; _dt = $dt }
        }
    })
    $hfSorted = @($hfAll | Sort-Object _dt -Descending)
    $lastHf   = $hfSorted | Where-Object { $_._dt } | Select-Object -First 1
    $sys.LastHotfix     = if ($lastHf) { D $lastHf._dt } else { '' }
    $sys.LastHotfixDays = if ($lastHf) { [int]($now - $lastHf._dt).TotalDays } else { -1 }
    # Get-HotFix jest zbierany zawsze (zasila pole "Ostatnia aktualizacja"), lista KB tylko gdy sekcja Updates jest włączona
    $updates = @()
    if (Want 'Updates') { $updates = @($hfSorted | Select-Object -First 30 HotFixID, Description, InstalledOn, InstalledBy) }

    try { $sys.WSUS = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop).WUServer)" } catch { $sys.WSUS = '' }
    $features = @()
    try { if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { $features = @(Get-WindowsFeature) } } catch {}
    $sys.Roles = (@($features | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object { $_.DisplayName }) -join ', ')
    $sys.IsHyperV  = [bool](Get-Service vmms -ErrorAction SilentlyContinue)
    try { $sys.TimeZone = (Get-TimeZone).Id } catch { $sys.TimeZone = '' }
    $sys.PSVersion = $PSVersionTable.PSVersion.ToString()

    # ── Konfiguracja bezpieczeństwa ──
    $hard = New-Object System.Collections.Generic.List[object]
    function Add-Check($check, $value, $status) { $hard.Add([pscustomobject]@{ Check = $check; Value = "$value"; Status = $status }) }
    if (Want 'Hardening') {

    try {
        $mp = Get-MpComputerStatus
        if (-not $mp.AMServiceEnabled -or "$($mp.AMRunningMode)" -match 'Passive|EDR') {
            $sys.AV = "Defender (tryb: $($mp.AMRunningMode))"
            Add-Check 'Defender' "tryb $($mp.AMRunningMode) – prawdopodobnie inny antywirus" 'Info'
        } else {
            $sys.AV = 'Microsoft Defender'
            Add-Check 'Defender – ochrona w czasie rzeczywistym' $(if ($mp.RealTimeProtectionEnabled) { 'włączona' } else { 'WYŁĄCZONA' }) $(if ($mp.RealTimeProtectionEnabled) { 'OK' } else { 'Krytyczne' })
            $age = [int]$mp.AntivirusSignatureAge
            Add-Check 'Defender – wiek sygnatur [dni]' $age $(if ($age -le 3) { 'OK' } elseif ($age -le 7) { 'Uwaga' } else { 'Krytyczne' })
            Add-Check 'Defender – dni od szybkiego skanu' $mp.QuickScanAge $(if ($mp.QuickScanAge -le 14) { 'OK' } else { 'Info' })
            if ($mp.PSObject.Properties['IsTamperProtected']) { Add-Check 'Defender – ochrona przed naruszeniami' $(if ($mp.IsTamperProtected) { 'włączona' } else { 'wyłączona' }) $(if ($mp.IsTamperProtected) { 'OK' } else { 'Info' }) }
        }
    } catch { $sys.AV = 'brak danych z Defendera'; Add-Check 'Antywirus' 'Defender niedostępny (inny AV lub starszy system)' 'Info' }

    try {
        foreach ($p in (Get-NetFirewallProfile -PolicyStore ActiveStore)) {
            $on = "$($p.Enabled)" -eq 'True'
            Add-Check "Zapora – profil $($p.Name)" $(if ($on) { 'włączona' } else { 'wyłączona' }) $(if ($on) { 'OK' } else { 'Uwaga' })
        }
    } catch { $errs.Add("Konfiguracja bezpieczeństwa: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]") }
    try {
        $smb = Get-SmbServerConfiguration
        Add-Check 'SMBv1 (serwer)' $(if ($smb.EnableSMB1Protocol) { 'włączony' } else { 'wyłączony' }) $(if ($smb.EnableSMB1Protocol) { 'Uwaga' } else { 'OK' })
        Add-Check 'Wymagane podpisywanie SMB' $(if ($smb.RequireSecuritySignature) { 'tak' } else { 'nie' }) $(if ($smb.RequireSecuritySignature) { 'OK' } else { 'Info' })
    } catch { $errs.Add("Konfiguracja bezpieczeństwa: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]") }
    try {
        $ts    = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $rdp   = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $rdpOn = ($ts.fDenyTSConnections -eq 0)
        Add-Check 'Pulpit zdalny (RDP)' $(if ($rdpOn) { "włączony, port $($rdp.PortNumber)" } else { 'wyłączony' }) 'Info'
        if ($rdpOn) { Add-Check 'RDP – uwierzytelnianie NLA' $(if ($rdp.UserAuthentication -eq 1) { 'wymagane' } else { 'NIE wymagane' }) $(if ($rdp.UserAuthentication -eq 1) { 'OK' } else { 'Uwaga' }) }
    } catch { $errs.Add("Konfiguracja bezpieczeństwa: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]") }
    try {
        $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $lm  = $lsa.LmCompatibilityLevel
        if ($null -eq $lm) { Add-Check 'Poziom uwierzytelniania LAN Manager' 'domyślny (3 – tylko NTLMv2)' 'OK' }
        else { Add-Check 'Poziom uwierzytelniania LAN Manager' $lm $(if ($lm -lt 3) { 'Uwaga' } else { 'OK' }) }
        Add-Check 'Ochrona LSA (RunAsPPL)' $(if ($lsa.RunAsPPL -ge 1) { 'włączona' } else { 'wyłączona' }) $(if ($lsa.RunAsPPL -ge 1) { 'OK' } else { 'Info' })
    } catch { $errs.Add("Konfiguracja bezpieczeństwa: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]") }
    try {
        $wd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue
        Add-Check 'WDigest – hasła w pamięci' $(if ($wd.UseLogonCredential -eq 1) { 'WŁĄCZONE' } else { 'wyłączone' }) $(if ($wd.UseLogonCredential -eq 1) { 'Krytyczne' } else { 'OK' })
    } catch { $errs.Add("Konfiguracja bezpieczeństwa: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]") }
    try {
        $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if ("$($wl.AutoAdminLogon)" -eq '1') { Add-Check 'Automatyczne logowanie' "włączone ($($wl.DefaultUserName))" $(if ($wl.DefaultPassword) { 'Krytyczne' } else { 'Uwaga' }) }
        else { Add-Check 'Automatyczne logowanie' 'wyłączone' 'OK' }
    } catch { $errs.Add("Konfiguracja bezpieczeństwa: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]") }
    try {
        $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Add-Check 'UAC (EnableLUA)' $(if ($uac.EnableLUA -eq 0) { 'wyłączony' } else { 'włączony' }) $(if ($uac.EnableLUA -eq 0) { 'Uwaga' } else { 'OK' })
    } catch { $errs.Add("Konfiguracja bezpieczeństwa: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]") }
    try {
        $llmnr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
        Add-Check 'LLMNR' $(if ($llmnr.EnableMulticast -eq 0) { 'wyłączony' } else { 'włączony' }) $(if ($llmnr.EnableMulticast -eq 0) { 'OK' } else { 'Info' })
    } catch { $errs.Add("Konfiguracja bezpieczeństwa: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]") }
    if ($sys.IsDC) {
        try {
            $sp = Get-Service Spooler -ErrorAction SilentlyContinue
            Add-Check 'Bufor wydruku na kontrolerze domeny' "$($sp.Status)" $(if ("$($sp.Status)" -eq 'Running') { 'Uwaga' } else { 'OK' })
        } catch { $errs.Add("Konfiguracja bezpieczeństwa: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]") }
    } else {
        $laps = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS') -or (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS')
        Add-Check 'LAPS (polityka)' $(if ($laps) { 'wykryto' } else { 'nie wykryto' }) $(if ($laps) { 'OK' } else { 'Info' })
    }
    # Przestarzałe protokoły SChannel (strona serwera). Oceniamy tylko jawne wpisy w rejestrze – brak wpisu = domyślne zachowanie danej wersji systemu
    foreach ($proto in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
        try {
            $pk  = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -ErrorAction SilentlyContinue
            $bad = if ($proto -like 'SSL*') { 'Krytyczne' } else { 'Uwaga' }
            if ($pk -and $null -ne $pk.Enabled -and [int64]$pk.Enabled -eq 0) { Add-Check "Protokół $proto (serwer)" 'wyłączony' 'OK' }
            elseif ($pk -and $null -ne $pk.Enabled) { Add-Check "Protokół $proto (serwer)" 'włączony jawnie w rejestrze' $bad }
            elseif ($pk -and $null -ne $pk.DisabledByDefault -and [int64]$pk.DisabledByDefault -eq 1) { Add-Check "Protokół $proto (serwer)" 'domyślnie wyłączony (DisabledByDefault)' 'OK' }
            else { Add-Check "Protokół $proto (serwer)" 'brak wpisu w rejestrze – domyślne ustawienie systemu' 'Info' }
        } catch { $errs.Add("Konfiguracja bezpieczeństwa: $proto – $($_.Exception.Message)") }
    }
    $ps2 = $features | Where-Object { $_.Name -eq 'PowerShell-V2' } | Select-Object -First 1
    if ($ps2) { Add-Check 'Silnik PowerShell 2.0 (obejście logowania skryptów)' $(if ($ps2.Installed) { 'zainstalowany' } else { 'niezainstalowany' }) $(if ($ps2.Installed) { 'Uwaga' } else { 'OK' }) }
    }   # Want 'Hardening'

    # ── Dyski ──
    $disks = @(S 'Disks' 'Dyski' {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object { $_.Size -gt 0 } | ForEach-Object {
            [pscustomobject]@{
                Drive = $_.DeviceID; Label = $_.VolumeName
                SizeGB = [math]::Round($_.Size / 1GB, 1); FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
                FreePct = [math]::Round($_.FreeSpace / $_.Size * 100, 1)
            }
        }
    })

    # ── Sieć ──
    $network = @(S 'Network' 'Sieć' {
        $np = @{}
        try { foreach ($c in @(Get-NetConnectionProfile -ErrorAction Stop)) { $np[[int]$c.InterfaceIndex] = "$($c.NetworkCategory)" } } catch {}
        foreach ($a in (Get-NetAdapter)) {
            $ips = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
            $gw  = @(Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop)
            $dns = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
            [pscustomobject]@{
                Adapter = $a.Name; Description = $a.InterfaceDescription; Status = "$($a.Status)"; Profile = "$($np[[int]$a.ifIndex])"
                MAC = $a.MacAddress; Speed = "$($a.LinkSpeed)"
                IPv4 = (@($ips | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ', ')
                DHCP = $(if ($ips | Where-Object { "$($_.PrefixOrigin)" -eq 'Dhcp' }) { 'Tak' } else { 'Nie' })
                Gateway = ($gw -join ', '); DNS = ($dns -join ', ')
            }
        }
    })

    # ── Procesy / usługi wg PID ──
    $procNames = @{}; try { Get-Process | ForEach-Object { $procNames[[int]$_.Id] = $_.ProcessName } } catch {}
    $svcByPid  = @{}
    try { Get-CimInstance Win32_Service -Filter 'ProcessId > 0' | Group-Object ProcessId | ForEach-Object { $svcByPid[[int]$_.Name] = ($_.Group.Name -join ',') } } catch {}
    function PName($id) { $n = $procNames[[int]$id]; if ($n) { $n } else { "PID $id" } }
    function PSvc($id)  { Short $svcByPid[[int]$id] 80 }

    # ── Porty nasłuchujące ──
    $listenPorts = @{}
    # potrzebne do ustalenia kierunku połączeń także wtedy, gdy sekcja Listening jest pominięta
    try { foreach ($lc in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) { $listenPorts[[int]$lc.LocalPort] = $true } } catch {}
    $listening = @(S 'Listening' 'Porty' {
        Get-NetTCPConnection -State Listen | Group-Object LocalPort, OwningProcess | ForEach-Object {
            $f = $_.Group[0]
            $listenPorts[[int]$f.LocalPort] = $true
            $addrs = @($_.Group.LocalAddress | Sort-Object -Unique)
            $scope = if ($addrs | Where-Object { $_ -in '0.0.0.0', '::' }) { 'Wszystkie interfejsy' }
                     elseif (-not ($addrs | Where-Object { $_ -notmatch '^(127\.|::1$)' })) { 'Tylko lokalnie' }
                     else { 'Wybrane adresy' }
            [pscustomobject]@{ Proto = 'TCP'; Port = [int]$f.LocalPort; Address = ($addrs -join ', '); Scope = $scope; Process = (PName $f.OwningProcess); Service = (PSvc $f.OwningProcess); PID = [int]$f.OwningProcess }
        }
        Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 49152 -and $_.LocalAddress -notmatch '^(127\.|::1$)' } | Group-Object LocalPort, OwningProcess | ForEach-Object {
            $f = $_.Group[0]
            $addrs = @($_.Group.LocalAddress | Sort-Object -Unique)
            $scope = if ($addrs | Where-Object { $_ -in '0.0.0.0', '::' }) { 'Wszystkie interfejsy' } else { 'Wybrane adresy' }
            [pscustomobject]@{ Proto = 'UDP'; Port = [int]$f.LocalPort; Address = ($addrs -join ', '); Scope = $scope; Process = (PName $f.OwningProcess); Service = (PSvc $f.OwningProcess); PID = [int]$f.OwningProcess }
        }
    })
    $listening = @($listening | Sort-Object Proto, Port)

    # ── Aktywne połączenia ──
    $connections = @(S 'Connections' 'Połączenia' {
        Get-NetTCPConnection -State Established |
            Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0|::ffff:127\.)' } |
            ForEach-Object {
                $ra = $_.RemoteAddress -replace '^::ffff:', ''
                $in = $listenPorts.ContainsKey([int]$_.LocalPort)
                [pscustomobject]@{
                    Direction = $(if ($in) { 'Przychodzące' } else { 'Wychodzące' }); Remote = $ra
                    RemotePort = $(if ($in) { $null } else { [int]$_.RemotePort }); LocalPort = $(if ($in) { [int]$_.LocalPort } else { $null })
                    P = [int]$_.OwningProcess
                }
            } | Group-Object Direction, Remote, RemotePort, LocalPort, P | ForEach-Object {
                $f = $_.Group[0]
                [pscustomobject]@{
                    Direction = $f.Direction; Remote = $f.Remote; RemotePort = $f.RemotePort; LocalPort = $f.LocalPort
                    Network = $(if ($f.Remote -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|f[cd][0-9a-f]{2}:)') { 'Prywatna' } else { 'Publiczna' })
                    Process = (PName $f.P); Service = (PSvc $f.P); Count = $_.Count
                }
            } | Sort-Object Count -Descending | Select-Object -First 400
    })

    # ── Usługi ──
    $vendorCache = @{}
    $services = @(S 'Services' 'Usługi' {
        foreach ($s in (Get-CimInstance Win32_Service)) {
            $raw = "$($s.PathName)"
            $exe = $raw
            if ($raw -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
            elseif ($raw -match '^\s*(.+?\.exe)(\s|$)') { $exe = $Matches[1] }
            $exe = [Environment]::ExpandEnvironmentVariables($exe) -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:SystemRoot\"
            if (-not $vendorCache.ContainsKey($exe)) {
                $v = ''; try { $v = (Get-Item -LiteralPath $exe -ErrorAction Stop).VersionInfo.CompanyName } catch {}
                $vendorCache[$exe] = "$v"
            }
            $vendor   = $vendorCache[$exe]
            $isMs     = $vendor -match 'Microsoft'
            $acct     = "$($s.StartName)"
            $builtin  = $acct -match '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|$)'
            $unquoted = ($raw -notmatch '^\s*"') -and ($exe -match '\s') -and ($exe -notmatch '^[A-Za-z]:\\Windows\\')
            $mode     = "$($s.StartMode)"; if ($s.DelayedAutoStart) { $mode += ' (opóźniony)' }
            $autoStop = ($s.StartMode -eq 'Auto' -and $s.State -ne 'Running')
            if ((-not $isMs) -or $autoStop -or (-not $builtin) -or $unquoted) {
                [pscustomobject]@{
                    Name = $s.Name; DisplayName = $s.DisplayName; State = "$($s.State)"; StartMode = $mode; Account = $acct
                    Vendor = $vendor; Microsoft = $(if ($isMs) { 'Tak' } else { 'Nie' }); Unquoted = $(if ($unquoted) { 'Tak' } else { '' }); Path = $raw
                }
            }
        }
    })
    $services = @($services | Sort-Object Microsoft, Name)

    # ── Harmonogram zadań ──
    $okCodes = '0x0', '0x41300', '0x41301', '0x41302', '0x41303', '0x41304', '0x41325'
    $resText = @{
        '0x0' = 'OK'; '0x1' = 'Błąd (kod 1)'; '0x2' = 'Nie znaleziono pliku'; '0x41300' = 'Gotowe'; '0x41301' = 'W trakcie'
        '0x41302' = 'Wyłączone'; '0x41303' = 'Jeszcze nie uruchomione'; '0x41304' = 'Brak kolejnych uruchomień'
        '0x41306' = 'Przerwane (limit czasu / zatrzymane)'; '0x41325' = 'W kolejce'; '0x8004131F' = 'Poprzednia instancja nadal działa'
        '0x800710E0' = 'Odmowa (warunki lub uprawnienia)'; '0x80070002' = 'Nie znaleziono pliku'; '0x80070005' = 'Odmowa dostępu'
        '0x8007052E' = 'Błędny login lub hasło'; '0xC000013A' = 'Przerwane (zamknięcie aplikacji)'; '0xFFFD0000' = 'Błąd skryptu PowerShell'
    }
    $tasks = @(S 'Tasks' 'Zadania' {
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
            $t = $_
            $info = $null; try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
            $hex = ''
            if ($info) { $hex = '0x{0:X}' -f [uint32]$info.LastTaskResult }
            $last = if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 2000) { D $info.LastRunTime } else { '' }
            $next = if ($info -and $info.NextRunTime -and $info.NextRunTime.Year -gt 2000) { D $info.NextRunTime } else { '' }
            $runAs = if ($t.Principal.UserId) { $t.Principal.UserId } else { $t.Principal.GroupId }
            $acts = (@($t.Actions | ForEach-Object { if ($_.Execute) { ("$($_.Execute) $($_.Arguments)").Trim() } else { 'Obsługa COM' } }) -join ' | ')
            $state = "$($t.State)"
            [pscustomobject]@{
                Path = "$($t.TaskPath)$($t.TaskName)"; State = $state; RunAs = $runAs; LastRun = $last; Result = $hex
                ResultText = $(if ($resText.ContainsKey($hex)) { $resText[$hex] } elseif ($hex) { 'Kod błędu' } else { '' })
                Failed = $(if ($hex -and $last -and ($okCodes -notcontains $hex) -and $state -ne 'Disabled') { 'Tak' } else { '' })
                NextRun = $next; Author = $t.Author; Action = $acts
            }
        }
    })

    # ── Zdarzenia System / Application ──
    $levels = if ($IncludeWarnings) { 1, 2, 3 } else { 1, 2 }
    $events = @(S 'Events' 'Zdarzenia' {
        $evLogs = @('System', 'Application')
        if ($sys.IsHyperV) { foreach ($l in 'Microsoft-Windows-Hyper-V-VMMS-Admin', 'Microsoft-Windows-Hyper-V-Worker-Admin') { try { if (Get-WinEvent -ListLog $l -ErrorAction Stop) { $evLogs += $l } } catch {} } }
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = [string[]]$evLogs; Level = $levels; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
        $ev | Group-Object LogName, ProviderName, Id | ForEach-Object {
            $g = @($_.Group | Sort-Object TimeCreated -Descending)
            $f = $g[0]
            [pscustomobject]@{
                Log = $f.LogName
                Level = $(switch ($f.Level) { 1 { 'Krytyczny' } 2 { 'Błąd' } 3 { 'Ostrzeżenie' } default { "$($f.Level)" } })
                Source = $f.ProviderName; Id = $f.Id; Count = $g.Count
                First = $(D $g[-1].TimeCreated); Last = $(D $f.TimeCreated); Message = $(Short $f.Message 400)
            }
        } | Sort-Object @{ e = { if ($_.Level -eq 'Krytyczny') { 0 } else { 1 } } }, @{ e = 'Count'; Descending = $true }
    })

    # ── Restarty ──
    $restarts = @(S 'Restarts' 'Restarty' {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1074, 6008, 41; StartTime = $since } -MaxEvents 100 -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -ne 41 -or $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' } | ForEach-Object {
                $type = switch ($_.Id) { 1074 { 'Zaplanowany restart / wyłączenie' } 6008 { 'Nieoczekiwane wyłączenie' } 41 { 'Reset bez poprawnego zamknięcia (Kernel-Power)' } }
                [pscustomobject]@{ Time = $(D $_.TimeCreated); Id = $_.Id; Type = $type; Detail = $(Short $_.Message 300) }
            }
    })

    # ── Zdarzenia bezpieczeństwa ──
    function EvData($e) {
        $h = @{}
        try {
            $x = [xml]$e.ToXml()
            if ($x.Event.EventData -and $x.Event.EventData.Data) { foreach ($d in @($x.Event.EventData.Data)) { if ($d.Name) { $h[$d.Name] = $d.'#text' } } }
            elseif ($x.Event.UserData) { foreach ($n in $x.Event.UserData.FirstChild.ChildNodes) { $h[$n.LocalName] = $n.InnerText } }
        } catch {}
        $h
    }
    $secNames = @{
        4625 = 'Nieudane logowanie'; 4771 = 'Nieudane uwierzytelnienie Kerberos'; 4740 = 'Zablokowanie konta'
        4720 = 'Utworzenie konta'; 4726 = 'Usunięcie konta'; 4722 = 'Włączenie konta'; 4724 = 'Reset hasła'
        4728 = 'Dodanie do grupy globalnej'; 4732 = 'Dodanie do grupy lokalnej'; 4756 = 'Dodanie do grupy uniwersalnej'
        1102 = 'Wyczyszczenie dziennika Security'; 104 = 'Wyczyszczenie dziennika'; 4698 = 'Utworzenie zadania harmonogramu'
        4697 = 'Instalacja usługi'; 7045 = 'Instalacja usługi'
    }
    $secEvents = @(S 'SecurityEvents' 'Bezpieczeństwo' {
        $list = @()
        $list += @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625, 4771, 4740, 4720, 4726, 4722, 4724, 4728, 4732, 4756, 1102, 4698, 4697; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
        $list += @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045, 104; StartTime = $since } -MaxEvents 300 -ErrorAction SilentlyContinue |
                   Where-Object { $_.Id -eq 7045 -or $_.ProviderName -eq 'Microsoft-Windows-Eventlog' })
        $fails = @(); $rows = @()
        foreach ($e in $list) {
            $d = EvData $e
            if ($e.Id -eq 4625) {
                $fails += [pscustomobject]@{ Id = 4625; Account = "$($d.TargetDomainName)\$($d.TargetUserName)"; Source = ("$($d.IpAddress) $($d.WorkstationName)").Trim(' -'); T = $e.TimeCreated; Detail = "typ logowania $($d.LogonType), status $($d.SubStatus)" }
                continue
            }
            if ($e.Id -eq 4771) {
                $fails += [pscustomobject]@{ Id = 4771; Account = "$($d.TargetUserName)"; Source = ("$($d.IpAddress)" -replace '^::ffff:', ''); T = $e.TimeCreated; Detail = "status $($d.Status)" }
                continue
            }
            $acc = ''; $by = "$($d.SubjectUserName)"; $src = ''; $det = ''
            switch ($e.Id) {
                { $_ -in 4720, 4726, 4722, 4724 } { $acc = "$($d.TargetDomainName)\$($d.TargetUserName)" }
                4740 { $acc = "$($d.TargetUserName)"; $src = "$($d.TargetDomainName)" }
                { $_ -in 4728, 4732, 4756 } { $acc = $(if ($d.MemberName -and $d.MemberName -ne '-') { $d.MemberName } else { $d.MemberSid }); $det = "grupa: $($d.TargetUserName)" }
                104  { $det = "dziennik: $($d.Channel)" }
                4698 { $det = "$($d.TaskName)" }
                4697 { $det = "$($d.ServiceName) -> $($d.ServiceFileName)" }
                7045 { $det = "$($d.ServiceName) -> $($d.ImagePath)"; $acc = "$($d.AccountName)"; $by = '' }
            }
            $rows += [pscustomobject]@{ Time = $(D $e.TimeCreated); Id = $e.Id; Event = $secNames[$e.Id]; Account = $acc; By = $by; Source = $src; Count = 1; Detail = $det }
        }
        $grp = @($fails | Group-Object Id, Account, Source | ForEach-Object {
            $g = @($_.Group | Sort-Object T -Descending)
            [pscustomobject]@{ Time = $(D $g[0].T); Id = $g[0].Id; Event = $secNames[$g[0].Id]; Account = $g[0].Account; By = ''; Source = $g[0].Source; Count = $g.Count; Detail = "$($g[0].Detail); pierwsze: $(D $g[-1].T)" }
        })
        $rows += $grp
        $rows | Sort-Object @{ e = { if ($_.Id -in 4625, 4771) { 1 } else { 0 } } }, @{ e = 'Count'; Descending = $true }
    })

    # ── Oprogramowanie ──
    $software = @(S 'Software' 'Oprogramowanie' {
        foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
            if (-not (Test-Path $k)) { continue }
            Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
                $p = $null; try { $p = $_ | Get-ItemProperty -ErrorAction Stop } catch { return }
                if (-not $p.DisplayName -or $p.SystemComponent -eq 1 -or $p.ParentKeyName -or $p.ReleaseType) { return }
                $idate = ''; $idays = $null
                if ("$($p.InstallDate)" -match '^\d{8}$') {
                    try { $dt = [datetime]::ParseExact("$($p.InstallDate)", 'yyyyMMdd', $null); $idate = $dt.ToString('yyyy-MM-dd'); $idays = [int]($now - $dt).TotalDays } catch {}
                }
                [pscustomobject]@{
                    Name = "$($p.DisplayName)".Trim(); Version = "$($p.DisplayVersion)"; Publisher = "$($p.Publisher)"
                    InstallDate = $idate; InstallDays = $idays; Arch = $(if ($k -match 'WOW6432Node') { 'x86' } else { 'x64' }); Location = "$($p.InstallLocation)"
                }
            }
        }
    })
    $software = @($software | Sort-Object Name, Version -Unique)

    # ── Grupy uprzywilejowane ──
    $admins = @(S 'Admins' 'Grupy' {
        foreach ($sid in 'S-1-5-32-544', 'S-1-5-32-555', 'S-1-5-32-580') {
            try {
                $gname = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
                $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$gname,group"
                foreach ($m in @($grp.psbase.Invoke('Members'))) {
                    $path  = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                    $cls   = $m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
                    $parts = ($path -replace '^WinNT://', '').Split('/')
                    $name  = if ($parts.Count -ge 3) { "$($parts[-2])\$($parts[-1])" } elseif ($parts.Count -eq 2) { "$($parts[0])\$($parts[1])" } else { $parts[0] }
                    [pscustomobject]@{ Group = $gname; Member = $name; Type = $(if ($cls -eq 'Group') { 'Grupa' } elseif ($cls -eq 'User') { 'Użytkownik' } else { "$cls" }) }
                }
            } catch { $errs.Add("Grupy ($sid): $($_.Exception.Message)") }
        }
    })

    # ── Konta lokalne ──
    $localUsers = @()
    if (-not $sys.IsDC) {
        $localUsers = @(S 'LocalUsers' 'Konta lokalne' {
            if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
                Get-LocalUser | ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.Name; Enabled = $(if ($_.Enabled) { 'Tak' } else { 'Nie' }); LastLogon = $(D $_.LastLogon); PasswordLastSet = $(D $_.PasswordLastSet)
                        PasswordNeverExpires = $(if (-not $_.PasswordExpires) { 'Tak' } else { '' }); Description = $_.Description; SID = "$($_.SID)"
                    }
                }
            } else {
                Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.Name; Enabled = $(if ($_.Disabled) { 'Nie' } else { 'Tak' }); LastLogon = ''; PasswordLastSet = ''
                        PasswordNeverExpires = $(if (-not $_.PasswordExpires) { 'Tak' } else { '' }); Description = $_.Description; SID = $_.SID
                    }
                }
            }
        })
    }

    # ── Udziały ──
    $everyone = 'Everyone'
    try { $everyone = (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')).Translate([System.Security.Principal.NTAccount]).Value } catch {}
    $shares = @(S 'Shares' 'Udziały' {
        Get-SmbShare | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|print\$|[A-Z]\$)$' } | ForEach-Object {
            $acc = @(Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue)
            $ew  = $acc | Where-Object { $_.AccountName -eq $everyone -and "$($_.AccessControlType)" -eq 'Allow' -and "$($_.AccessRight)" -in 'Full', 'Change' }
            [pscustomobject]@{
                Name = $_.Name; Path = $_.Path; Description = $_.Description
                Access = (@($acc | ForEach-Object { "$($_.AccountName): $($_.AccessControlType) $($_.AccessRight)" }) -join '; ')
                EveryoneWrite = $(if ($ew) { 'Tak' } else { '' })
            }
        }
    })

    # ── Autostart ──
    $autostart = @(S 'Autostart' 'Autostart' {
        $skip = 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider'
        foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                       'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce') {
            if (-not (Test-Path $k)) { continue }
            $p = Get-ItemProperty $k
            foreach ($prop in $p.PSObject.Properties) {
                if ($skip -notcontains $prop.Name) { [pscustomobject]@{ Location = ($k -replace '^HKLM:\\', 'HKLM\'); Name = $prop.Name; Command = "$($prop.Value)" } }
            }
        }
        $sf = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
        if (Test-Path $sf) {
            Get-ChildItem $sf -File -Force | Where-Object Name -ne 'desktop.ini' | ForEach-Object { [pscustomobject]@{ Location = 'Folder Autostart (wszyscy)'; Name = $_.Name; Command = $_.FullName } }
        }
        $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if ($wl.Userinit -and $wl.Userinit -notmatch '^[A-Za-z]:\\Windows\\system32\\userinit\.exe,?$') { [pscustomobject]@{ Location = 'Winlogon'; Name = 'Userinit'; Command = "$($wl.Userinit)" } }
        if ($wl.Shell -and $wl.Shell -ne 'explorer.exe') { [pscustomobject]@{ Location = 'Winlogon'; Name = 'Shell'; Command = "$($wl.Shell)" } }
    })

    # ── Certyfikaty ──
    $certs = @(S 'Certificates' 'Certyfikaty' {
        Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
            [pscustomobject]@{
                Subject = $_.Subject; Issuer = $_.Issuer; NotAfter = $(D $_.NotAfter); DaysLeft = [int]($_.NotAfter - $now).TotalDays
                PrivateKey = $(if ($_.HasPrivateKey) { 'Tak' } else { 'Nie' }); Thumbprint = $_.Thumbprint
            }
        }
    })
    $certs = @($certs | Sort-Object DaysLeft)

    # ── Foldery ──
    $execExt = '.exe', '.dll', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.msi', '.scr', '.jar'
    # UWAGA: zmienne w PowerShell nie rozróżniają wielkości liter – $folders to ten sam [string[]]$Folders z param(),
    # dlatego wynik ląduje w $folderRows (inaczej obiekty zamieniały się w napisy "@{Folder=...}")
    $folderRows = @(S 'Folders' 'Foldery' {
        foreach ($f in $Folders) {
            $p = [Environment]::ExpandEnvironmentVariables($f)
            if (-not (Test-Path -LiteralPath $p)) { continue }
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                $files = @(Get-ChildItem -LiteralPath $p -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue)
            } else {
                # PowerShell 4.0 (np. Windows Server 2012 R2 bez WMF 5.1) nie ma parametru -Depth
                $rootLen = $p.TrimEnd('\').Length
                $files = @(Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue |
                           Where-Object { -not $_.PSIsContainer -and ($_.FullName.Substring($rootLen).TrimStart('\').Split('\').Count -le 4) })
            }
            $total = ($files | Measure-Object Length -Sum).Sum
            $execCount = @($files | Where-Object { $execExt -contains $_.Extension.ToLower() }).Count
            [pscustomobject]@{ Folder = $p; File = "[podsumowanie] plików: $($files.Count), wykonywalnych/skryptów: $execCount"; SizeKB = [math]::Round($total / 1KB); Modified = ''; Executable = $(if ($execCount) { "$execCount" } else { '' }) }
            $root = $p.TrimEnd('\').Length
            $files | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | ForEach-Object {
                [pscustomobject]@{
                    Folder = $p; File = $_.FullName.Substring($root).TrimStart('\'); SizeKB = [math]::Round($_.Length / 1KB, 1)
                    Modified = $(D $_.LastWriteTime); Executable = $(if ($execExt -contains $_.Extension.ToLower()) { 'Tak' } else { '' })
                }
            }
        }
    })

    # ── Hyper-V ──
    $hyperv = @(); $checkpoints = @(); $vmStorage = @()
    if ($sys.IsHyperV) {
        $hyperv = @(S 'HyperV' 'Hyper-V' {
            Get-VM | ForEach-Object {
                $vm = $_
                $disksGB = $null
                try { $disksGB = [math]::Round(((@($vm | Get-VMHardDiskDrive | ForEach-Object { (Get-VHD -Path $_.Path -ErrorAction Stop).FileSize }) | Measure-Object -Sum).Sum) / 1GB, 1) } catch {}
                [pscustomobject]@{
                    Name = $vm.Name; State = "$($vm.State)"; Status = "$($vm.Status)"; Heartbeat = "$($vm.Heartbeat)"; UptimeDays = [math]::Round($vm.Uptime.TotalDays, 1)
                    CPU = $vm.ProcessorCount; MemGB = [math]::Round($vm.MemoryAssigned / 1GB, 1); DynamicMem = $(if ($vm.DynamicMemoryEnabled) { 'Tak' } else { 'Nie' })
                    Gen = $vm.Generation; Version = "$($vm.Version)"; Replication = "$($vm.ReplicationHealth)"
                    IntegrationServices = "$($vm.IntegrationServicesState)"; DisksGB = $disksGB; Path = $vm.Path
                }
            }
        })
        $checkpoints = @(S 'Checkpoints' 'Checkpointy' {
            Get-VMSnapshot -VMName * -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{ VM = $_.VMName; Name = $_.Name; Created = $(D $_.CreationTime); AgeDays = [int]($now - $_.CreationTime).TotalDays; Type = "$($_.SnapshotType)" }
            }
        })
        $checkpoints = @($checkpoints | Sort-Object AgeDays -Descending)
        # Dyski VM: ile mogą jeszcze urosnąć dyski dynamiczne/różnicowe względem wolnego miejsca na wolumenie
        $vmStorage = @(S 'VMStorage' 'Hyper-V: dyski VM' {
            $vols = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' | Where-Object { $_.Name } | Sort-Object { $_.Name.Length } -Descending)
            foreach ($vm in @(Get-VM)) {
                foreach ($hd in @($vm | Get-VMHardDiskDrive)) {
                    if (-not $hd.Path) { continue }   # dysk pass-through
                    $v = $null; try { $v = Get-VHD -Path $hd.Path -ErrorAction Stop } catch {}
                    $vol  = $vols | Where-Object { $hd.Path.StartsWith($_.Name, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
                    $type = if ($v) { "$($v.VhdType)" } else { 'nieznany' }
                    [pscustomobject]@{
                        VM = $vm.Name; Disk = $hd.Path; Type = $type
                        CurrentGB = $(if ($v) { [math]::Round($v.FileSize / 1GB, 1) } else { $null })
                        MaxGB     = $(if ($v) { [math]::Round($v.Size / 1GB, 1) } else { $null })
                        GrowthGB  = $(if ($v -and $type -ne 'Fixed') { [math]::Round([math]::Max([double]0, [double]($v.Size - $v.FileSize)) / 1GB, 1) } else { 0 })
                        Volume    = $(if ($vol) { $vol.Name } elseif ($hd.Path -match '^(\\\\[^\\]+\\[^\\]+)') { $Matches[1] } else { '' })
                        VolumeFreeGB = $(if ($vol) { [math]::Round($vol.FreeSpace / 1GB, 1) } else { $null })
                    }
                }
            }
        })
    }

    # ── Dzienniki zdarzeń: rozmiar, tryb i ile dni faktycznie obejmują ──
    $eventLogs = @(S 'EventLogs' 'Dzienniki' {
        foreach ($ln in 'Security', 'System', 'Application') {
            $l = Get-WinEvent -ListLog $ln -ErrorAction Stop
            $old = $null; try { $old = (Get-WinEvent -LogName $ln -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch {}
            [pscustomobject]@{
                Log = $ln; MaxSizeMB = [math]::Round($l.MaximumSizeInBytes / 1MB); UsedMB = [math]::Round($l.FileSize / 1MB)
                Mode = "$($l.LogMode)"; Records = [int64]$l.RecordCount; Full = $(if ($l.IsLogFull) { 'Tak' } else { '' })
                Oldest = $(D $old); CoveredDays = $(if ($old) { [math]::Round(($now - $old).TotalDays, 1) } else { $null })
            }
        }
    })

    # ── Polityka audytu (auditpol /backup: GUID podkategorii i wartość 0–3 są niezależne od języka) ──
    $auditMap = @{ 0 = 'Brak'; 1 = 'Sukces'; 2 = 'Niepowodzenie'; 3 = 'Sukces i niepowodzenie' }
    $auditPolicy = @(S 'AuditPolicy' 'Polityka audytu' {
        $tmp = Join-Path $env:TEMP ("sr_audit_{0}.csv" -f [guid]::NewGuid())
        try {
            $null = & { $ErrorActionPreference = 'Continue'; & auditpol.exe /backup "/file:$tmp" 2>&1 }
            if (-not (Test-Path -LiteralPath $tmp)) { throw "auditpol /backup nie utworzył pliku (kod $LASTEXITCODE)" }
            foreach ($line in @(Get-Content -LiteralPath $tmp | Select-Object -Skip 1)) {
                $m = [regex]::Match($line, ',\{([0-9A-Fa-f-]{36})\},')
                if (-not $m.Success) { continue }   # opcje audytu bez GUID
                $head = @($line.Substring(0, $m.Index) -split ',', 3)
                $v = 0; [void][int]::TryParse($line.Substring($line.LastIndexOf(',') + 1).Trim(), [ref]$v)
                [pscustomobject]@{ Subcategory = $(if ($head.Count -ge 3) { $head[2] } else { '' }); Guid = $m.Groups[1].Value.ToUpper(); Setting = $auditMap[$v]; Value = $v }
            }
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    })

    # ── Awarie systemu: BSOD (zdarzenie 1001 BugCheck) i pliki zrzutów ──
    $crashes = @(S 'Crashes' 'Awarie systemu' {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001; StartTime = $since } -MaxEvents 50 -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -in 'Microsoft-Windows-WER-SystemErrorReporting', 'BugCheck' } | ForEach-Object {
                $code = ''; try { $code = "$(@(([xml]$_.ToXml()).Event.EventData.Data)[0].'#text')" } catch {}
                [pscustomobject]@{ Time = $(D $_.TimeCreated); Type = 'BSOD (BugCheck)'; Code = $code; Detail = $(Short $_.Message 300); AgeDays = [math]::Round(($now - $_.TimeCreated).TotalDays, 1) }
            }
        $dumps = @()
        $md = Join-Path $env:SystemRoot 'Minidump'
        if (Test-Path -LiteralPath $md) { $dumps += @(Get-ChildItem -LiteralPath $md -Filter *.dmp -File -Force -ErrorAction SilentlyContinue) }
        $full = Join-Path $env:SystemRoot 'MEMORY.DMP'
        if (Test-Path -LiteralPath $full) { $dumps += @(Get-Item -LiteralPath $full -Force) }
        $dumps | Sort-Object LastWriteTime -Descending | Select-Object -First 10 | ForEach-Object {
            [pscustomobject]@{
                Time = $(D $_.LastWriteTime); Type = $(if ($_.Name -eq 'MEMORY.DMP') { 'Pełny zrzut pamięci' } else { 'Minizrzut' }); Code = ''
                Detail = "$($_.FullName), $([math]::Round($_.Length / 1MB, 1)) MB"; AgeDays = [math]::Round(($now - $_.LastWriteTime).TotalDays, 1)
            }
        }
    })

    # ── Zdrowie dysków: dyski fizyczne (Storage) i zdarzenia błędów dyskowych ──
    $hsMap = @{ 0 = 'OK'; 1 = 'Ostrzeżenie'; 2 = 'Awaria'; 5 = 'Nieznany' }
    $opMap = @{ 2 = 'OK'; 3 = 'zdegradowany'; 5 = 'przewidywana awaria'; 6 = 'błąd'; 7 = 'błąd nienaprawialny'; 10 = 'zatrzymany'; 11 = 'w serwisie'; 13 = 'utrata komunikacji' }
    $diskHealth = @(S 'DiskHealth' 'Zdrowie dysków' {
        if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            foreach ($pd in @(Get-PhysicalDisk)) {
                $hs  = $pd.CimInstanceProperties['HealthStatus'].Value
                $ops = @($pd.CimInstanceProperties['OperationalStatus'].Value | ForEach-Object { if ($opMap.ContainsKey([int]$_)) { $opMap[[int]$_] } else { "kod $_" } })
                $rc  = $null; try { $rc = $pd | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
                $unc = if ($rc -and ($null -ne $rc.ReadErrorsUncorrected -or $null -ne $rc.WriteErrorsUncorrected)) { [int64]$rc.ReadErrorsUncorrected + [int64]$rc.WriteErrorsUncorrected } else { $null }
                [pscustomobject]@{
                    Source = 'Dysk fizyczny'; Id = $null; Name = "$($pd.FriendlyName) ($($pd.MediaType), $($pd.BusType), $([math]::Round($pd.Size / 1GB)) GB)"
                    Health = $(if ($null -ne $hs -and $hsMap.ContainsKey([int]$hs)) { $hsMap[[int]$hs] } else { "$hs" })
                    WearPct = $(if ($rc -and $rc.Wear) { [int]$rc.Wear } else { $null }); TempC = $(if ($rc -and $rc.Temperature) { [int]$rc.Temperature } else { $null })
                    UncorrectedErrors = $unc; PowerOnHours = $(if ($rc -and $rc.PowerOnHours) { [int64]$rc.PowerOnHours } else { $null })
                    Count = $null; Last = ''; Detail = "stan: $($ops -join ', ')"
                }
            }
        }
        # disk 7 (uszkodzony blok), 51 (błąd stronicowania), 153/157 (ponowienie/usunięcie I/O), Ntfs 55/98 (uszkodzenie systemu plików), 129 (reset urządzenia przez sterownik)
        $dEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7, 51, 55, 98, 129, 153, 157; StartTime = $since } -MaxEvents 1000 -ErrorAction SilentlyContinue |
                 Where-Object { ($_.ProviderName -match '^(disk|Ntfs|Microsoft-Windows-Ntfs)$' -or $_.Id -eq 129) -and -not ($_.Id -eq 98 -and $_.Level -ge 4) })
        $dEv | Group-Object ProviderName, Id | ForEach-Object {
            $g = @($_.Group | Sort-Object TimeCreated -Descending)
            [pscustomobject]@{
                Source = "Zdarzenie $($g[0].ProviderName)"; Id = $g[0].Id; Name = ''; Health = ''; WearPct = $null; TempC = $null; UncorrectedErrors = $null; PowerOnHours = $null
                Count = $g.Count; Last = $(D $g[0].TimeCreated); Detail = $(Short $g[0].Message 300)
            }
        }
    })

    # ── Kontroler domeny: SYSVOL, replikacja AD, zdarzenia replikacji, LDAP ──
    $dcRows = @()
    if ($sys.IsDC) {
        $dcRows = @(S 'DomainController' 'Kontroler domeny' {
            $ck = { param($c, $v, $st) [pscustomobject]@{ Check = $c; Value = "$v"; Status = $st } }
            $dfsr = @()
            try { $dfsr = @(Get-CimInstance -Namespace root/microsoftdfs -ClassName DfsrReplicatedFolderInfo -ErrorAction Stop | Where-Object { $_.ReplicationGroupName -eq 'Domain System Volume' }) } catch {}
            if ($dfsr.Count) {
                $stMap = @{ 0 = 'niezainicjowany'; 1 = 'zainicjowany'; 2 = 'synchronizacja początkowa'; 3 = 'automatyczne odzyskiwanie'; 4 = 'normalny'; 5 = 'BŁĄD' }
                foreach ($f in $dfsr) {
                    $st = [int]$f.State
                    & $ck "SYSVOL (DFSR) – $($f.ReplicatedFolderName)" "$($stMap[$st]) ($st)" $(if ($st -eq 4) { 'OK' } elseif ($st -eq 5) { 'Krytyczne' } else { 'Uwaga' })
                }
            } else { & $ck 'SYSVOL' 'brak replikacji DFSR – prawdopodobnie przestarzała FRS (migracja: dfsrmig)' 'Uwaga' }

            Import-Module ActiveDirectory -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if (Get-Command Get-ADReplicationPartnerMetadata -ErrorAction SilentlyContinue) {
                try {
                    $pm = @(Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -ErrorAction Stop)
                    if (-not $pm.Count) { & $ck 'Replikacja AD' 'brak partnerów replikacji (jedyny kontroler domeny?)' 'Info' }
                    foreach ($p in $pm) {
                        $partner = "$($p.Partner)" -replace '^CN=NTDS Settings,CN=([^,]+),.*$', '$1'
                        $fails = [int]$p.ConsecutiveReplicationFailures
                        $age = if ($p.LastReplicationSuccess) { ($now - $p.LastReplicationSuccess).TotalHours } else { 1e6 }
                        & $ck "Replikacja AD z $partner" "ostatni sukces: $(D $p.LastReplicationSuccess), błędy z rzędu: $fails, wynik: $($p.LastReplicationResult)" $(if ($fails -eq 0 -and [int64]$p.LastReplicationResult -eq 0) { 'OK' } elseif ($age -gt 24) { 'Krytyczne' } else { 'Uwaga' })
                    }
                } catch { & $ck 'Replikacja AD' "nie udało się odczytać: $($_.Exception.Message)" 'Info' }
            } else { & $ck 'Replikacja AD' 'brak modułu ActiveDirectory – pominięto' 'Info' }

            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 1311, 1388, 1925, 1988, 2042, 2087, 2088; StartTime = $since } -MaxEvents 500 -ErrorAction SilentlyContinue)
            $ev += @(Get-WinEvent -FilterHashtable @{ LogName = 'DFS Replication'; Id = 2213, 4012, 5002, 5008; StartTime = $since } -MaxEvents 500 -ErrorAction SilentlyContinue)
            foreach ($g in @($ev | Group-Object LogName, Id)) {
                $f = @($g.Group | Sort-Object TimeCreated -Descending)[0]
                & $ck "Zdarzenie $($f.LogName) $($f.Id)" "×$($g.Count), ostatnio $(D $f.TimeCreated): $(Short $f.Message 200)" $(if ($f.Id -in 1988, 2042, 2213, 4012) { 'Krytyczne' } else { 'Uwaga' })
            }
            if (-not $ev.Count) { & $ck 'Zdarzenia replikacji (Directory Service, DFS Replication)' "brak błędów z $Days dni" 'OK' }

            $ntds = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
            $li = $ntds.LDAPServerIntegrity; $cb = $ntds.LdapEnforceChannelBinding
            & $ck 'LDAP – wymagane podpisywanie (LDAPServerIntegrity)' $(if ($null -eq $li) { 'brak wpisu – domyślne ustawienie systemu' } elseif ($li -ge 2) { "$li (wymagane)" } else { "$li (niewymagane)" }) $(if ($null -eq $li) { 'Info' } elseif ($li -ge 2) { 'OK' } else { 'Uwaga' })
            & $ck 'LDAP – channel binding (LdapEnforceChannelBinding)' $(if ($null -eq $cb) { 'brak wpisu – domyślne ustawienie systemu' } elseif ($cb -ge 2) { "$cb (zawsze)" } elseif ($cb -eq 1) { "$cb (gdy obsługiwane)" } else { "$cb (nigdy)" }) $(if ($null -eq $cb) { 'Info' } elseif ($cb -ge 1) { 'OK' } else { 'Uwaga' })
        })
    }

    # ── Ekspozycja: reguły zapory wpuszczające porty wrażliwe (lista portów przychodzi ze stacji: $Config.ExposedPorts) ──
    $exposure = @(S 'Exposure' 'Ekspozycja' {
        $ports = @($ExposedPorts | ForEach-Object { "$_" })
        $pf = @{};  foreach ($x in @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -All)) { $pf[$x.InstanceID] = $x }
        $af = @{};  foreach ($x in @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore -All)) { $af[$x.InstanceID] = $x }
        $apf = @{}; foreach ($x in @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -All)) { $apf[$x.InstanceID] = $x }
        foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow)) {
            $p = $pf[$r.InstanceID]; if (-not $p) { continue }
            $lp   = @($p.LocalPort | ForEach-Object { "$_" })
            $prog = "$($apf[$r.InstanceID].Program)"
            $hit  = @($lp | Where-Object { $ports -contains $_ })
            foreach ($rg in @($lp | Where-Object { $_ -match '^\d+-\d+$' })) { $lo, $hi = $rg.Split('-'); $hit += @($ports | Where-Object { [int]$_ -ge [int]$lo -and [int]$_ -le [int]$hi }) }
            if ($lp -contains 'RPCEPMap' -and $ports -contains '135') { $hit += '135' }
            # reguły aplikacji Sklepu (AppContainer) mają Program=Any, ale dotyczą tylko danego pakietu – pomijamy je
            $allPorts = ($lp -contains 'Any' -and ($prog -eq 'Any' -or -not $prog) -and "$($p.Protocol)" -in 'Any', 'TCP' -and -not "$($apf[$r.InstanceID].Package)")
            if (-not ($hit.Count -or $allPorts)) { continue }
            $ra = @($af[$r.InstanceID].RemoteAddress | ForEach-Object { "$_" })
            $anyAddr = ($ra -contains 'Any' -or $ra -contains 'Internet')
            $prof = [int]$r.Profile
            [pscustomobject]@{
                Rule = $r.DisplayName; Ports = $(if ($allPorts) { 'wszystkie' } else { (@($hit | Sort-Object -Unique) -join ', ') }); Protocol = "$($p.Protocol)"
                Profiles = "$($r.Profile)"; RemoteAddress = ($ra -join ', '); Program = $prog
                Public = $(if (($prof -eq 0 -or ($prof -band 4)) -and $anyAddr) { 'Tak' } else { '' })
            }
        }
    })

    # ── Mechanizmy trwałości: subskrypcje WMI i wykluczenia Defendera ──
    $persistence = @(S 'Persistence' 'Trwałość' {
        foreach ($f in @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{ Type = 'WMI – filtr zdarzeń'; Name = "$($f.Name)"; Detail = "$($f.Query)" }
        }
        foreach ($c in @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)) {
            $cls = $c.CimClass.CimClassName
            $det = switch ($cls) {
                'CommandLineEventConsumer'  { "$($c.CommandLineTemplate) $($c.ExecutablePath)".Trim() }
                'ActiveScriptEventConsumer' { if ($c.ScriptFileName) { "$($c.ScriptFileName)" } else { Short $c.ScriptText 300 } }
                default                     { '' }
            }
            [pscustomobject]@{ Type = "WMI – konsument ($cls)"; Name = "$($c.Name)"; Detail = "$det" }
        }
        foreach ($b in @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{ Type = 'WMI – powiązanie'; Name = "$($b.Filter.Name) -> $($b.Consumer.Name)"; Detail = '' }
        }
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            $mpp = $null; try { $mpp = Get-MpPreference -ErrorAction Stop } catch {}
            if ($mpp) {
                foreach ($pair in @(@('ExclusionPath', 'ścieżka'), @('ExclusionProcess', 'proces'), @('ExclusionExtension', 'rozszerzenie'), @('ExclusionIpAddress', 'adres IP'))) {
                    foreach ($x in @($mpp.($pair[0]))) { if ($x -and "$x" -notlike 'N/A*') { [pscustomobject]@{ Type = "Defender – wykluczenie ($($pair[1]))"; Name = "$x"; Detail = '' } } }
                }
            }
        }
    })

    # ── Sesje użytkowników ──
    $sessions = @(S 'Sessions' 'Sesje' {
        $out = & { $ErrorActionPreference = 'SilentlyContinue'; quser.exe 2>$null }
        @($out) | Select-Object -Skip 1 | ForEach-Object {
            $c = (("$_" -replace '^>', ' ').Trim()) -split '\s{2,}'
            if ($c.Count -ge 6) { [pscustomobject]@{ User = $c[0]; Session = $c[1]; Id = $c[2]; State = $c[3]; Idle = $c[4]; LogonTime = $c[5] } }
            elseif ($c.Count -eq 5) { [pscustomobject]@{ User = $c[0]; Session = ''; Id = $c[1]; State = $c[2]; Idle = $c[3]; LogonTime = $c[4] } }
        }
    })

    # PS 5.1: @(List[object]) wewnątrz literału [pscustomobject]@{} rzuca "Argument types do not match" – konwersja wcześniej
    $hardening = [object[]]$hard.ToArray()
    $sys.CollectedUtc = [DateTime]::UtcNow.ToString('o')   # do wyliczenia różnicy czasu względem stacji skanującej
    $errList   = [string[]]$errs.ToArray()
    [pscustomobject]@{
        System         = [pscustomobject]$sys
        Hardening      = $hardening
        Disks          = $disks
        Network        = $network
        Listening      = $listening
        Connections    = $connections
        Services       = $services
        Tasks          = $tasks
        Events         = $events
        Restarts       = $restarts
        SecurityEvents = $secEvents
        Software       = $software
        Updates        = $updates
        Admins         = $admins
        LocalUsers     = $localUsers
        Shares         = $shares
        Autostart      = $autostart
        Certificates   = $certs
        Folders        = $folderRows
        HyperV         = $hyperv
        Checkpoints    = $checkpoints
        Sessions       = $sessions
        EventLogs      = $eventLogs
        AuditPolicy    = $auditPolicy
        Crashes        = $crashes
        DiskHealth     = $diskHealth
        DomainController = $dcRows
        Exposure       = $exposure
        Persistence    = $persistence
        VMStorage      = $vmStorage
        Skipped        = [string[]]@($SkipSections | Where-Object { $_ })
        Errors         = $errList
        Days           = $Days
        DurationSec    = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    } | ConvertTo-Json -Depth 4 -Compress
    } catch {
        $ii = $_.InvocationInfo
        [pscustomobject]@{ Fatal = "$($_.Exception.Message) [linia $($ii.ScriptLineNumber): $("$($ii.Line)".Trim())]" } | ConvertTo-Json -Compress
    }
}
#endregion

#region ── Wątek skanujący (osobny runspace, GUI się nie zawiesza) ───────────────
$ScanWorker = {
    param($Sync, [string[]]$Targets, [string]$CollectorText, [object[]]$CollectorArgs, $Credential, [int]$Throttle, [int]$TimeoutSec)
    try {
        $sb = [scriptblock]::Create($CollectorText)
        $p = @{ ComputerName = $Targets; ScriptBlock = $sb; ArgumentList = $CollectorArgs; AsJob = $true; ThrottleLimit = $Throttle }
        if ($Credential) { $p.Credential = $Credential }
        $job = Invoke-Command @p
        $pending = New-Object System.Collections.ArrayList
        foreach ($cj in $job.ChildJobs) { [void]$pending.Add($cj) }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($pending.Count -gt 0) {
            if ($Sync.Cancel -or $sw.Elapsed.TotalSeconds -gt $TimeoutSec) {
                $reason = if ($Sync.Cancel) { 'Skan przerwany przez użytkownika' } else { "Przekroczono limit czasu ($TimeoutSec s)" }
                foreach ($cj in @($pending)) { $Sync.Queue.Enqueue([pscustomobject]@{ Name = $cj.Location; Json = $null; Error = $reason }); $Sync.Done++ }
                try { $job | Stop-Job } catch {}
                break
            }
            foreach ($cj in @($pending)) {
                if ("$($cj.State)" -in 'Completed', 'Failed', 'Stopped') {
                    $rcv  = [DateTime]::UtcNow   # moment odbioru – do wyliczenia różnicy czasu serwera
                    $rerr = $null
                    $out  = @(Receive-Job -Job $cj -ErrorAction SilentlyContinue -ErrorVariable rerr)
                    $json = $out | Where-Object { $_ -is [string] } | Select-Object -Last 1
                    $err  = $null
                    if (-not $json) {
                        if ($cj.JobStateInfo.Reason) { $err = $cj.JobStateInfo.Reason.Message }
                        elseif ($rerr) { $err = "$($rerr[0])" }
                        else { $err = 'Serwer nie zwrócił danych' }
                    }
                    $Sync.Queue.Enqueue([pscustomobject]@{ Name = $cj.Location; Json = $json; Error = $err; ReceivedUtc = $rcv })
                    [void]$pending.Remove($cj)
                    $Sync.Done++
                }
            }
            Start-Sleep -Milliseconds 300
        }
        try { Remove-Job -Job $job -Force } catch {}
    } catch { $Sync.Fatal = $_.Exception.Message }
    finally { $Sync.Finished = $true }
}
#endregion

#region ── Definicje sekcji, nagłówków, ważności ─────────────────────────────────
$script:Sections = @(
    @{ Key = 'Issues';         Header = 'Problemy' }
    @{ Key = 'Changes';        Header = 'Zmiany od poprzedniego skanu' }
    @{ Key = 'System';         Header = 'System' }
    @{ Key = 'Hardening';      Header = 'Konfiguracja bezpieczeństwa' }
    @{ Key = 'EventLogs';      Header = 'Dzienniki zdarzeń' }
    @{ Key = 'AuditPolicy';    Header = 'Polityka audytu' }
    @{ Key = 'Disks';          Header = 'Dyski' }
    @{ Key = 'DiskHealth';     Header = 'Zdrowie dysków' }
    @{ Key = 'Services';       Header = 'Usługi' }
    @{ Key = 'Tasks';          Header = 'Harmonogram zadań' }
    @{ Key = 'Events';         Header = 'Błędy w dziennikach' }
    @{ Key = 'SecurityEvents'; Header = 'Zdarzenia bezpieczeństwa' }
    @{ Key = 'Restarts';       Header = 'Restarty' }
    @{ Key = 'Crashes';        Header = 'Awarie systemu (BSOD)' }
    @{ Key = 'Network';        Header = 'Adresacja i karty sieciowe' }
    @{ Key = 'Listening';      Header = 'Porty nasłuchujące' }
    @{ Key = 'Connections';    Header = 'Aktywne połączenia' }
    @{ Key = 'Exposure';       Header = 'Ekspozycja (reguły zapory)' }
    @{ Key = 'Software';       Header = 'Oprogramowanie' }
    @{ Key = 'Updates';        Header = 'Aktualizacje (KB)' }
    @{ Key = 'Admins';         Header = 'Grupy uprzywilejowane' }
    @{ Key = 'LocalUsers';     Header = 'Konta lokalne' }
    @{ Key = 'Sessions';       Header = 'Sesje użytkowników' }
    @{ Key = 'Shares';         Header = 'Udziały' }
    @{ Key = 'Autostart';      Header = 'Autostart' }
    @{ Key = 'Persistence';    Header = 'Trwałość (WMI, wykluczenia AV)' }
    @{ Key = 'Certificates';   Header = 'Certyfikaty' }
    @{ Key = 'Folders';        Header = 'Foldery' }
    @{ Key = 'DomainController'; Header = 'Kontroler domeny' }
    @{ Key = 'HyperV';         Header = 'Hyper-V: maszyny' }
    @{ Key = 'Checkpoints';    Header = 'Hyper-V: checkpointy' }
    @{ Key = 'VMStorage';      Header = 'Hyper-V: dyski VM' }
)
$script:ArrayKeys = @($script:Sections | Where-Object { $_.Key -notin 'Issues', 'Changes', 'System' } | ForEach-Object { $_.Key })

$script:SevMeta = @{
    'Krytyczny'   = @{ Rank = 0; Color = '#FF6B78'; Bg = '#2EFF5C6C'; Flag = 'crit' }
    'Ostrzeżenie' = @{ Rank = 1; Color = '#FFC15E'; Bg = '#2EFFB547'; Flag = 'warn' }
    'Info'        = @{ Rank = 2; Color = '#7DB5FF'; Bg = '#2E60A5FA'; Flag = 'info' }
}

# Co porównujemy między skanami (klucz identyfikujący pozycję)
$script:DiffDefs = [ordered]@{
    Services   = @{ Label = 'usługi';          KeyFn = { param($r) "$($r.Name) [$($r.Account)]" }; Filter = { $_.Microsoft -eq 'Nie' }; Sev = 'Ostrzeżenie' }
    Tasks      = @{ Label = 'zadania';         KeyFn = { param($r) "$($r.Path)" };                  Filter = $null; Sev = 'Ostrzeżenie' }
    Listening  = @{ Label = 'porty';           KeyFn = { param($r) "$($r.Proto)/$($r.Port) $($r.Process)" }; Filter = $null; Sev = 'Ostrzeżenie' }
    Admins     = @{ Label = 'grupy uprzyw.';   KeyFn = { param($r) "$($r.Group): $($r.Member)" };  Filter = $null; Sev = 'Ostrzeżenie' }
    LocalUsers = @{ Label = 'konta lokalne';   KeyFn = { param($r) "$($r.Name)" };                  Filter = $null; Sev = 'Ostrzeżenie' }
    Shares     = @{ Label = 'udziały';         KeyFn = { param($r) "$($r.Name) ($($r.Path))" };    Filter = $null; Sev = 'Ostrzeżenie' }
    Autostart  = @{ Label = 'autostart';       KeyFn = { param($r) "$($r.Location)\$($r.Name): $($r.Command)" }; Filter = $null; Sev = 'Ostrzeżenie' }
    Software   = @{ Label = 'oprogramowanie';  KeyFn = { param($r) "$($r.Name) $($r.Version)" };   Filter = $null; Sev = 'Info' }
    Persistence = @{ Label = 'trwałość (WMI, AV)'; KeyFn = { param($r) "$($r.Type): $($r.Name)" };   Filter = $null; Sev = 'Ostrzeżenie' }
    Exposure   = @{ Label = 'reguły zapory';   KeyFn = { param($r) "$($r.Rule) [$($r.Ports)]" };    Filter = $null; Sev = 'Ostrzeżenie' }
}

$script:Headers = @{
    Drive = 'Dysk'; Label = 'Etykieta'; SizeGB = 'Rozmiar [GB]'; FreeGB = 'Wolne [GB]'; FreePct = 'Wolne [%]'
    Adapter = 'Karta'; Description = 'Opis'; Status = 'Status'; MAC = 'MAC'; Speed = 'Prędkość'; IPv4 = 'IPv4'; DHCP = 'DHCP'; Gateway = 'Brama'; DNS = 'DNS'
    Proto = 'Protokół'; Port = 'Port'; Address = 'Adres'; Scope = 'Nasłuch na'; Process = 'Proces'; Service = 'Usługa'; PID = 'PID'
    Direction = 'Kierunek'; Remote = 'Adres zdalny'; RemotePort = 'Port zdalny'; LocalPort = 'Port lokalny'; Network = 'Sieć'; Count = 'Liczba'
    Name = 'Nazwa'; DisplayName = 'Nazwa wyświetlana'; State = 'Stan'; StartMode = 'Uruchamianie'; Account = 'Konto'; Vendor = 'Producent'
    Microsoft = 'Microsoft'; Unquoted = 'Niecytowana ścieżka'; Path = 'Ścieżka'
    RunAs = 'Uruchom jako'; LastRun = 'Ostatnio'; Result = 'Kod'; ResultText = 'Wynik'; Failed = 'Błąd'; NextRun = 'Następne'; Author = 'Autor'; Action = 'Akcja'
    Log = 'Dziennik'; Level = 'Poziom'; Source = 'Źródło'; Id = 'ID'; First = 'Pierwsze'; Last = 'Ostatnie'; Message = 'Komunikat'
    Time = 'Czas'; Type = 'Typ'; Detail = 'Szczegóły'; Event = 'Zdarzenie'; By = 'Wykonał'
    Version = 'Wersja'; Publisher = 'Wydawca'; InstallDate = 'Instalacja'; InstallDays = 'Dni temu'; Arch = 'Arch.'; Location = 'Lokalizacja'
    Group = 'Grupa'; Member = 'Członek'; Enabled = 'Włączone'; LastLogon = 'Ostatnie logowanie'; PasswordLastSet = 'Zmiana hasła'
    PasswordNeverExpires = 'Hasło nie wygasa'; SID = 'SID'; Access = 'Uprawnienia udziału'; EveryoneWrite = 'Wszyscy: zapis'; Command = 'Polecenie'
    Subject = 'Podmiot'; Issuer = 'Wystawca'; NotAfter = 'Ważny do'; DaysLeft = 'Dni do wygaśnięcia'; PrivateKey = 'Klucz prywatny'; Thumbprint = 'Odcisk'
    Folder = 'Folder'; File = 'Plik'; SizeKB = 'Rozmiar [KB]'; Modified = 'Zmodyfikowano'; Executable = 'Wykonywalny'
    UptimeDays = 'Uptime [dni]'; CPU = 'CPU'; MemGB = 'RAM [GB]'; DynamicMem = 'Pamięć dynamiczna'; Gen = 'Generacja'; Replication = 'Replikacja'
    IntegrationServices = 'Usługi integracji'; DisksGB = 'Dyski [GB]'; VM = 'Maszyna'; Created = 'Utworzono'; AgeDays = 'Wiek [dni]'
    User = 'Użytkownik'; Session = 'Sesja'; Idle = 'Bezczynność'; LogonTime = 'Zalogowano'
    HotFixID = 'KB'; InstalledOn = 'Zainstalowano'; InstalledBy = 'Zainstalował'
    Check = 'Sprawdzenie'; Value = 'Wartość'; Severity = 'Poziom'; Category = 'Kategoria'; Section = 'Obszar'; Change = 'Zmiana'; Item = 'Pozycja'; Property = 'Właściwość'
    Server = 'Serwer'; OS = 'System'; RAM = 'RAM [%]'; MinDiskPct = 'Min. wolne na dysku [%]'; Crit = 'Krytyczne'; Warn = 'Ostrzeżenia'; PatchDays = 'Dni od aktualizacji'
    ScanSec = 'Skan [s]'; Scanned = 'Skanowano'
    ComputerName = 'Nazwa komputera'; FQDN = 'FQDN'; Build = 'Kompilacja'; OSInstallDate = 'Instalacja systemu'; LastBoot = 'Ostatni start'
    Model = 'Model'; CPUName = 'Procesor'; Cores = 'Procesory logiczne'; CpuLoad = 'Obciążenie CPU [%]'; RamGB = 'RAM [GB]'; RamUsedPct = 'Użycie RAM [%]'
    Domain = 'Domena'; DomainRole = 'Rola w domenie'; IsDC = 'Kontroler domeny'; PendingReboot = 'Oczekujący restart'; LastHotfix = 'Ostatnia aktualizacja'
    LastHotfixDays = 'Dni od aktualizacji'; WSUS = 'Serwer WSUS'; Roles = 'Zainstalowane role'; IsHyperV = 'Host Hyper-V'; TimeZone = 'Strefa czasowa'
    PSVersion = 'Wersja PowerShell'; AV = 'Antywirus'
    Subcategory = 'Podkategoria'; Guid = 'GUID'; Setting = 'Ustawienie'; Required = 'Wymagane'
    MaxSizeMB = 'Rozmiar maks. [MB]'; UsedMB = 'Zajęte [MB]'; Mode = 'Tryb'; Records = 'Liczba zdarzeń'; Full = 'Pełny'; Oldest = 'Najstarsze zdarzenie'; CoveredDays = 'Pokrycie [dni]'
    Code = 'Kod'; Health = 'Stan'; WearPct = 'Zużycie [%]'; TempC = 'Temp. [°C]'; UncorrectedErrors = 'Błędy nieskorygowane'; PowerOnHours = 'Godziny pracy'
    Disk = 'Dysk'; CurrentGB = 'Obecnie [GB]'; MaxGB = 'Maks. [GB]'; GrowthGB = 'Może urosnąć [GB]'; Volume = 'Wolumen'; VolumeFreeGB = 'Wolne na wolumenie [GB]'; Heartbeat = 'Heartbeat'
    Rule = 'Reguła zapory'; Ports = 'Porty'; Protocol = 'Protokół'; Profiles = 'Profile zapory'; RemoteAddress = 'Adresy zdalne'; Program = 'Program'; Public = 'Publiczny, z dowolnego adresu'
    Profile = 'Profil sieci'; DomainRoleId = 'Rola w domenie (kod)'; BuildNumber = 'Numer kompilacji'; CommitLimitGB = 'Limit pamięci wirtualnej [GB]'; CommitUsedPct = 'Użycie pamięci wirtualnej [%]'
    PageFileAuto = 'Plik stronicowania zarządzany automatycznie'; PageFiles = 'Pliki stronicowania'; ResourceExhaustion = 'Wyczerpanie pamięci (zdarzenia 2004)'
    TimeSource = 'Źródło czasu (W32Time)'; NtpServer = 'Serwer NTP'; HvTimeSync = 'Czas z hosta Hyper-V'; CollectedUtc = 'Czas zebrania danych (UTC)'; TimeOffsetSec = 'Różnica czasu vs stacja [s]'
}
#endregion

#region ── Funkcje pomocnicze ───────────────────────────────────────────────────
$script:BrushConv = New-Object System.Windows.Media.BrushConverter
function Brush([string]$Hex) { $script:BrushConv.ConvertFromString($Hex) }
function Get-Header([string]$Name) { if ($script:Headers.ContainsKey($Name)) { $script:Headers[$Name] } else { $Name } }
function Get-DisplayName([string]$Name) { if ($Name) { $Name.Split('.')[0].ToUpper() } else { '' } }
function Get-SafeName([string]$Name) { $Name -replace '[\\/:*?"<>|]', '_' }
function Get-ShortText([string]$s, [int]$n) { $s = "$s" -replace '\s+', ' '; if ($s.Length -gt $n) { $s.Substring(0, $n) + '…' } else { $s.Trim() } }
function Join-Short($Items, [int]$Max) {
    $a = @($Items | Where-Object { $_ })
    $t = (@($a | Select-Object -First $Max)) -join ', '
    if ($a.Count -gt $Max) { $t += " (+$($a.Count - $Max))" }
    $t
}
function Show-Msg([string]$Text, [string]$Icon = 'Information', [string]$Buttons = 'OK') {
    [System.Windows.MessageBox]::Show($window, $Text, 'Przegląd serwerów', $Buttons, $Icon)
}

function New-Issue($ServerKey, $Severity, $Category, $Message, $Section) {
    $m = $script:SevMeta[$Severity]
    [pscustomobject]@{
        Severity = $Severity; Server = (Get-DisplayName $ServerKey); Category = $Category; Message = $Message
        ServerKey = $ServerKey; Section = $Section; Rank = $m.Rank; SevColor = $m.Color; SevBg = $m.Bg; Flag = $m.Flag
    }
}

function ConvertFrom-ServerJson([string]$Json) {
    $d = $Json | ConvertFrom-Json
    $present = [string[]]@($d.PSObject.Properties | ForEach-Object { $_.Name })   # sekcje faktycznie obecne w danych (starsze migawki nie mają nowych sekcji)
    foreach ($k in $script:ArrayKeys) {
        $rows = @()
        if ($d.PSObject.Properties[$k]) { $rows = @($d.$k | Where-Object { $null -ne $_ }) }
        foreach ($r in $rows) { $r | Add-Member -NotePropertyName Flag -NotePropertyValue '' -Force }
        $d | Add-Member -NotePropertyName $k -NotePropertyValue $rows -Force
    }
    $d | Add-Member -NotePropertyName _Present -NotePropertyValue $present -Force
    $d
}

function Get-SnapshotFiles([string]$Name) {
    if (-not (Test-Path -LiteralPath $Config.SnapshotDir)) { return }
    $safe = Get-SafeName $Name
    Get-ChildItem -LiteralPath $Config.SnapshotDir -Directory | Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName "$safe.json" } | Where-Object { Test-Path -LiteralPath $_ }
}
function Read-Snapshot([string]$Path) {
    try { ConvertFrom-ServerJson ([IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)) } catch { $null }
}
function Remove-OldSnapshots {
    try {
        Get-ChildItem -LiteralPath $Config.SnapshotDir -Directory | Sort-Object Name -Descending |
            Select-Object -Skip $Config.SnapshotsToKeep | Remove-Item -Recurse -Force
    } catch {}
}
#endregion

#region ── Ustawienia użytkownika (okno Ustawienia, plik settings.json) ─────────
# Wartości domyślne są w bloku $Config na górze pliku. settings.json (obok skryptu) nadpisuje tylko pozycje z poniższej listy.
$script:SettingDefs = @(
    @{ Key = 'EventDays';              Type = 'int';  Min = 1;   Max = 180;    Label = 'Zakres zdarzeń [dni]' }
    @{ Key = 'MaxEvents';              Type = 'int';  Min = 100; Max = 100000; Label = 'Limit pobieranych zdarzeń na dziennik' }
    @{ Key = 'IncludeWarnings';        Type = 'bool';                          Label = 'Uwzględniaj ostrzeżenia z dzienników System/Application (dużo szumu)' }
    @{ Key = 'DiskWarnPct';            Type = 'int';  Min = 1;   Max = 99;     Label = 'Dysk: ostrzeżenie poniżej [% wolnego]' }
    @{ Key = 'DiskCritPct';            Type = 'int';  Min = 1;   Max = 99;     Label = 'Dysk: krytyczne poniżej [% wolnego]' }
    @{ Key = 'RamWarnPct';             Type = 'int';  Min = 1;   Max = 100;    Label = 'RAM: ostrzeżenie od [%]' }
    @{ Key = 'CommitWarnPct';          Type = 'int';  Min = 1;   Max = 100;    Label = 'Pamięć wirtualna (commit): ostrzeżenie od [%]' }
    @{ Key = 'UptimeWarnDays';         Type = 'int';  Min = 1;   Max = 3650;   Label = 'Uptime: ostrzeżenie powyżej [dni]' }
    @{ Key = 'PatchWarnDays';          Type = 'int';  Min = 1;   Max = 3650;   Label = 'Aktualizacje: ostrzeżenie po [dniach]' }
    @{ Key = 'CertWarnDays';           Type = 'int';  Min = 1;   Max = 3650;   Label = 'Certyfikaty: ostrzeżenie na [dni] przed wygaśnięciem' }
    @{ Key = 'CheckpointWarnDays';     Type = 'int';  Min = 1;   Max = 3650;   Label = 'Checkpoint Hyper-V: ostrzeżenie po [dniach]' }
    @{ Key = 'FailedLogonWarn';        Type = 'int';  Min = 1;   Max = 1000000; Label = 'Nieudane logowania: ostrzeżenie od [liczba]' }
    @{ Key = 'RecentSoftwareDays';     Type = 'int';  Min = 1;   Max = 3650;   Label = 'Nowe oprogramowanie: z ostatnich [dni]' }
    @{ Key = 'TimeSkewWarnSec';        Type = 'int';  Min = 1;   Max = 86400;  Label = 'Różnica czasu: ostrzeżenie od [s]' }
    @{ Key = 'TimeSkewCritSec';        Type = 'int';  Min = 1;   Max = 86400;  Label = 'Różnica czasu: krytyczne od [s]' }
    @{ Key = 'SupportWarnDays';        Type = 'int';  Min = 1;   Max = 3650;   Label = 'Koniec wsparcia systemu: uprzedzaj [dni] wcześniej' }
    @{ Key = 'DiskWearWarnPct';        Type = 'int';  Min = 1;   Max = 100;    Label = 'Zużycie SSD: ostrzeżenie od [%]' }
    @{ Key = 'DiskRetryWarn';          Type = 'int';  Min = 1;   Max = 100000; Label = 'Ponowienia/resety I/O dysku: ostrzeżenie od [liczba]' }
    @{ Key = 'BugCheckCritCount';      Type = 'int';  Min = 1;   Max = 1000;   Label = 'BSOD: krytyczne od [liczba w okresie]' }
    @{ Key = 'ThrottleLimit';          Type = 'int';  Min = 1;   Max = 200;    Label = 'Ile serwerów skanować równolegle' }
    @{ Key = 'ScanTimeoutSec';         Type = 'int';  Min = 60;  Max = 86400;  Label = 'Limit czasu całego skanu [s]' }
    @{ Key = 'SnapshotsToKeep';        Type = 'int';  Min = 1;   Max = 10000;  Label = 'Ile migawek (skanów) przechowywać' }
    @{ Key = 'Folders';                Type = 'list';    Label = 'Foldery sprawdzane na serwerach (jeden na linię, zmienne środowiskowe dozwolone)' }
    @{ Key = 'IgnoredStoppedServices'; Type = 'list';    Label = 'Usługi automatyczne, których zatrzymanie jest OK (jedna na linię, wildcardy *)' }
    @{ Key = 'ExposedPorts';           Type = 'intlist'; Label = 'Porty wrażliwe dla sekcji Ekspozycja (jeden na linię)' }
    @{ Key = 'IgnoredWmiConsumers';    Type = 'list';    Label = 'Subskrypcje WMI traktowane jako systemowe (jedna na linię)' }
)
$script:SectionGroups = [ordered]@{
    'System i stabilność'  = @('Disks', 'DiskHealth', 'Crashes', 'Events', 'Restarts', 'EventLogs', 'Updates', 'Software')
    'Bezpieczeństwo'       = @('Hardening', 'SecurityEvents', 'AuditPolicy', 'Exposure', 'Persistence', 'Admins', 'LocalUsers', 'Certificates', 'Shares', 'Autostart')
    'Usługi, sieć i pliki' = @('Services', 'Tasks', 'Network', 'Listening', 'Connections', 'Sessions', 'Folders')
    'Role serwera'         = @('DomainController', 'HyperV', 'Checkpoints', 'VMStorage')
}

function ConvertTo-Hashtable($Object) { $h = @{}; foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = $p.Value }; $h }
function Get-ConfigSnapshot {
    $h = @{}
    foreach ($d in $script:SettingDefs) { $v = $Config[$d.Key]; if ($v -is [array]) { $h[$d.Key] = $v.Clone() } else { $h[$d.Key] = $v } }
    $h.SkipSections = [string[]]@($Config.SkipSections | Where-Object { $_ })
    $h
}
function Set-ConfigFromValues([hashtable]$Values) {
    # nieznane klucze są ignorowane, wartości spoza zakresu lub złego typu – pomijane (zostaje poprzednia wartość)
    foreach ($d in $script:SettingDefs) {
        if (-not $Values.ContainsKey($d.Key)) { continue }
        $v = $Values[$d.Key]
        try {
            if ($d.Type -eq 'bool') { $Config[$d.Key] = [bool]$v }
            elseif ($d.Type -eq 'list') { $Config[$d.Key] = [string[]]@(@($v) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
            elseif ($d.Type -eq 'intlist') { $Config[$d.Key] = [int[]]@(@($v) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | ForEach-Object { [int]$_ }) }
            else { $n = [int]$v; if ($n -ge $d.Min -and $n -le $d.Max) { $Config[$d.Key] = $n } }
        } catch {}
    }
    if ($Values.ContainsKey('SkipSections')) { $Config.SkipSections = [string[]]@(@($Values.SkipSections) | Where-Object { $script:ArrayKeys -contains $_ }) }
}
function Import-UserSettings {
    $script:SettingsWarning = $null
    if (-not (Test-Path -LiteralPath $Config.SettingsFile)) { return }
    try { Set-ConfigFromValues (ConvertTo-Hashtable ([IO.File]::ReadAllText($Config.SettingsFile, [Text.Encoding]::UTF8) | ConvertFrom-Json)) }
    catch { $script:SettingsWarning = "Nie udało się wczytać ustawień z $($Config.SettingsFile): $($_.Exception.Message). Użyto wartości domyślnych." }
}
function Save-UserSettings {
    $o = [ordered]@{ Saved = (Get-Date -Format 's') }
    foreach ($d in $script:SettingDefs) { $o[$d.Key] = $Config[$d.Key] }
    $o.SkipSections = [string[]]@($Config.SkipSections | Where-Object { $_ })
    [IO.File]::WriteAllText($Config.SettingsFile, ([pscustomobject]$o | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding $false))
}
$script:ConfigDefaults = Get-ConfigSnapshot
Import-UserSettings
#endregion

#region ── Analiza wyników ──────────────────────────────────────────────────────
function Invoke-ServerAnalysis {
    param([string]$Name, $D, $Prev)
    $C = $Config
    $list = New-Object System.Collections.Generic.List[object]
    function AddI($sev, $cat, $msg, $sec) { $list.Add((New-Issue $Name $sev $cat $msg $sec)) }
    function SetFlag($row, $f) {
        if (-not $row) { return }
        $rank = @{ crit = 0; warn = 1; info = 2 }
        $cur = "$($row.Flag)"
        if (-not $cur -or $rank[$f] -lt $rank[$cur]) { $row.Flag = $f }
    }

    if ($D.Offline) {
        AddI 'Krytyczny' 'Łączność' ("Brak połączenia z serwerem: " + (Get-ShortText $D.Error 300)) 'Issues'
        $D | Add-Member -NotePropertyName _Changes -NotePropertyValue @() -Force
        return , $list.ToArray()
    }
    $days = if ($D.Days) { $D.Days } else { $C.EventDays }

    # System
    $s = $D.System
    if ($s) {
        if ($s.UptimeDays -gt $C.UptimeWarnDays) { AddI 'Ostrzeżenie' 'System' "Uptime $($s.UptimeDays) dni – serwer dawno nie był restartowany" 'System' }
        if ($s.PendingReboot) { AddI 'Ostrzeżenie' 'System' "Oczekuje na restart ($($s.PendingReboot))" 'System' }
        if ($null -ne $s.LastHotfixDays) {
            if ($s.LastHotfixDays -lt 0) { AddI 'Info' 'Aktualizacje' 'Nie udało się ustalić daty ostatniej aktualizacji' 'Updates' }
            elseif ($s.LastHotfixDays -gt $C.PatchWarnDays) { AddI 'Ostrzeżenie' 'Aktualizacje' "Ostatnia aktualizacja $($s.LastHotfixDays) dni temu ($($s.LastHotfix))" 'Updates' }
        }
        if ($s.RamUsedPct -ge $C.RamWarnPct) { AddI 'Ostrzeżenie' 'Zasoby' "Wysokie użycie RAM: $($s.RamUsedPct)% z $($s.RamGB) GB" 'System' }
    }

    # Dyski
    foreach ($r in $D.Disks) {
        $msg = "Dysk $($r.Drive) $($r.Label): wolne $($r.FreePct)% ($($r.FreeGB) z $($r.SizeGB) GB)"
        if ($r.FreePct -lt $C.DiskCritPct) { AddI 'Krytyczny' 'Dyski' $msg 'Disks'; SetFlag $r 'crit' }
        elseif ($r.FreePct -lt $C.DiskWarnPct) { AddI 'Ostrzeżenie' 'Dyski' $msg 'Disks'; SetFlag $r 'warn' }
    }

    # Usługi
    foreach ($r in $D.Services) {
        if ($r.StartMode -like 'Auto*' -and $r.State -ne 'Running') {
            $ignored = $false
            foreach ($p in $C.IgnoredStoppedServices) { if ($r.Name -like $p) { $ignored = $true; break } }
            if (-not $ignored) { AddI 'Ostrzeżenie' 'Usługi' "Usługa automatyczna zatrzymana: $($r.DisplayName) ($($r.Name))" 'Services'; SetFlag $r 'warn' }
        }
        if ($r.Unquoted -eq 'Tak') { AddI 'Ostrzeżenie' 'Bezpieczeństwo' "Niecytowana ścieżka usługi ze spacjami: $($r.Name) – $($r.Path)" 'Services'; SetFlag $r 'warn' }
    }

    # Zadania
    foreach ($r in $D.Tasks) {
        if ($r.Failed -eq 'Tak') { AddI 'Ostrzeżenie' 'Harmonogram' "Zadanie $($r.Path): $($r.ResultText) ($($r.Result)), ostatnio $($r.LastRun)" 'Tasks'; SetFlag $r 'warn' }
    }

    # Zdarzenia
    foreach ($r in @($D.Events | Where-Object Level -eq 'Krytyczny' | Select-Object -First 8)) {
        AddI 'Ostrzeżenie' 'Zdarzenia' "Zdarzenie krytyczne $($r.Source) (ID $($r.Id)) ×$($r.Count), ostatnio $($r.Last): $(Get-ShortText $r.Message 140)" 'Events'
        SetFlag $r 'warn'
    }
    $errRows = @($D.Events | Where-Object Level -eq 'Błąd')
    if ($errRows.Count) {
        $total = ($errRows | Measure-Object Count -Sum).Sum
        $top   = $errRows | Sort-Object Count -Descending | Select-Object -First 1
        AddI 'Info' 'Zdarzenia' "$total błędów ($($errRows.Count) rodzajów) w System/Application z $days dni; najczęstszy: $($top.Source) ID $($top.Id) ×$($top.Count)" 'Events'
        foreach ($r in $errRows) { if ($r.Count -ge 20) { SetFlag $r 'info' } }
    }

    # Restarty
    foreach ($r in $D.Restarts) {
        if ($r.Id -in 6008, 41) { AddI 'Ostrzeżenie' 'Stabilność' "$($r.Type): $($r.Time)" 'Restarts'; SetFlag $r 'warn' }
    }

    # Bezpieczeństwo
    $sec   = @($D.SecurityEvents)
    $fails = @($sec | Where-Object { $_.Id -in 4625, 4771 })
    if ($fails.Count) {
        $ft  = ($fails | Measure-Object Count -Sum).Sum
        $top = $fails | Sort-Object Count -Descending | Select-Object -First 1
        $sv  = if ($ft -ge $C.FailedLogonWarn) { 'Ostrzeżenie' } else { 'Info' }
        AddI $sv 'Bezpieczeństwo' "$ft nieudanych logowań w $days dni$(if ($ft -ge $C.MaxEvents) { " (osiągnięto limit $($C.MaxEvents) pobieranych zdarzeń – faktycznie może być więcej)" }); najwięcej: $($top.Account) z $($top.Source) ×$($top.Count)" 'SecurityEvents'
        foreach ($r in $fails) { if ($r.Count -ge 5) { SetFlag $r 'warn' } }
    }
    # Nieudane logowania z adresów publicznych = usługa logowania dostępna z internetu
    $privRx   = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.|0\.0\.0\.0|fe80:|f[cd][0-9a-f]{2}:|::1$|-$)'
    $pubFails = @($fails | Where-Object { $ip = @((("$($_.Source)" -replace '^::ffff:', '').Trim()) -split '\s+')[0]; $ip -match '^(\d{1,3}\.){3}\d{1,3}$|:' -and $ip -notmatch $privRx })
    if ($pubFails.Count) {
        $pn  = ($pubFails | Measure-Object Count -Sum).Sum
        $ips = @($pubFails | ForEach-Object { @((("$($_.Source)" -replace '^::ffff:', '').Trim()) -split '\s+')[0] } | Sort-Object -Unique)
        AddI 'Krytyczny' 'Bezpieczeństwo' "Nieudane logowania z adresów publicznych: $pn prób z $($ips.Count) adresów (np. $(Join-Short $ips 3)) – logowanie (RDP/SMB) jest prawdopodobnie dostępne z internetu" 'SecurityEvents'
        foreach ($r in $pubFails) { SetFlag $r 'crit' }
    }
    $n = 0
    foreach ($r in @($sec | Where-Object { $_.Id -in 1102, 104, 4720, 4726, 4728, 4732, 4756 })) {
        $n++; if ($n -gt 25) { break }
        if ($r.Id -in 1102, 104) { AddI 'Krytyczny' 'Bezpieczeństwo' "$($r.Event) – wykonał: $($r.By), $($r.Time) $($r.Detail)" 'SecurityEvents'; SetFlag $r 'crit' }
        else { AddI 'Ostrzeżenie' 'Bezpieczeństwo' "$($r.Event): $($r.Account) $($r.Detail) (wykonał: $($r.By), $($r.Time))" 'SecurityEvents'; SetFlag $r 'warn' }
    }
    $inst = @($sec | Where-Object { $_.Id -in 4697, 7045 })
    if ($inst.Count) { AddI 'Info' 'Bezpieczeństwo' ("Zainstalowane usługi w $days dni: " + (Join-Short ($inst | ForEach-Object { $_.Detail }) 3)) 'SecurityEvents' }
    foreach ($r in @($sec | Where-Object { $_.Id -in 4697, 7045, 4698, 4740, 4722, 4724 })) { SetFlag $r 'info' }

    # Oprogramowanie
    $recent = @($D.Software | Where-Object { $null -ne $_.InstallDays -and $_.InstallDays -le $C.RecentSoftwareDays })
    if ($recent.Count) {
        AddI 'Info' 'Oprogramowanie' ("Zainstalowane lub zaktualizowane w ostatnich $($C.RecentSoftwareDays) dniach: " + (Join-Short ($recent | ForEach-Object { "$($_.Name) $($_.Version)" }) 4)) 'Software'
        foreach ($r in $recent) { SetFlag $r 'info' }
    }

    # Grupy, konta
    foreach ($r in $D.Admins) { if ($r.Member -match '^S-1-5-') { AddI 'Info' 'Uprawnienia' "Osierocony SID w grupie $($r.Group): $($r.Member)" 'Admins'; SetFlag $r 'info' } }
    foreach ($r in $D.LocalUsers) {
        if ($r.Enabled -eq 'Tak' -and "$($r.SID)" -like '*-501') { AddI 'Ostrzeżenie' 'Konta' "Włączone konto Gość ($($r.Name))" 'LocalUsers'; SetFlag $r 'warn' }
        elseif ($r.Enabled -eq 'Tak' -and $r.PasswordNeverExpires -eq 'Tak') { SetFlag $r 'info' }
    }
    $pne = @($D.LocalUsers | Where-Object { $_.Enabled -eq 'Tak' -and $_.PasswordNeverExpires -eq 'Tak' })
    if ($pne.Count) { AddI 'Info' 'Konta' ("Włączone konta lokalne z hasłem bez wygasania: " + (Join-Short ($pne | ForEach-Object { $_.Name }) 5)) 'LocalUsers' }

    # Udziały, certyfikaty, foldery
    foreach ($r in $D.Shares) { if ($r.EveryoneWrite -eq 'Tak') { AddI 'Info' 'Udziały' "Udział $($r.Name) ($($r.Path)): Wszyscy mają zapis na poziomie udziału – sprawdź NTFS" 'Shares'; SetFlag $r 'info' } }
    foreach ($r in $D.Certificates) {
        if ($r.PrivateKey -ne 'Tak') { continue }
        if ($r.DaysLeft -lt 0) { AddI 'Info' 'Certyfikaty' "Wygasły certyfikat: $(Get-ShortText $r.Subject 80) ($($r.NotAfter))" 'Certificates'; SetFlag $r 'info' }
        elseif ($r.DaysLeft -le $C.CertWarnDays) { AddI 'Ostrzeżenie' 'Certyfikaty' "Certyfikat wygasa za $($r.DaysLeft) dni: $(Get-ShortText $r.Subject 80)" 'Certificates'; SetFlag $r 'warn' }
    }
    foreach ($r in $D.Folders) {
        if ($r.File -like '`[podsumowanie`]*' -and $r.Executable) { AddI 'Info' 'Foldery' "W $($r.Folder) jest $($r.Executable) plików wykonywalnych/skryptów" 'Folders' }
        elseif ($r.Executable -eq 'Tak') { SetFlag $r 'info' }
    }

    # Hyper-V
    foreach ($r in $D.HyperV) { if ($r.State -eq 'Running' -and "$($r.Heartbeat)" -match '^(LostCommunication|NoContact|Error)') { AddI 'Ostrzeżenie' 'Hyper-V' "Maszyna $($r.Name) działa, ale nie odpowiada na heartbeat ($($r.Heartbeat))" 'HyperV'; SetFlag $r 'warn' } }
    foreach ($r in $D.HyperV) { if ($r.Replication -in 'Critical', 'Warning') { AddI 'Ostrzeżenie' 'Hyper-V' "Replikacja VM $($r.Name): $($r.Replication)" 'HyperV'; SetFlag $r 'warn' } }
    $off = @($D.HyperV | Where-Object { $_.State -eq 'Off' })
    if ($off.Count) { AddI 'Info' 'Hyper-V' ("Wyłączone maszyny: " + (Join-Short ($off | ForEach-Object { $_.Name }) 5)) 'HyperV'; foreach ($r in $off) { SetFlag $r 'info' } }
    foreach ($r in $D.Checkpoints) {
        if ($r.AgeDays -gt $C.CheckpointWarnDays) { AddI 'Ostrzeżenie' 'Hyper-V' "Checkpoint '$($r.Name)' na $($r.VM) ma $($r.AgeDays) dni" 'Checkpoints'; SetFlag $r 'warn' }
    }

    # Konfiguracja bezpieczeństwa
    foreach ($r in $D.Hardening) {
        switch ($r.Status) {
            'Krytyczne' { AddI 'Krytyczny' 'Konfiguracja' "$($r.Check): $($r.Value)" 'Hardening'; SetFlag $r 'crit' }
            'Uwaga'     { AddI 'Ostrzeżenie' 'Konfiguracja' "$($r.Check): $($r.Value)" 'Hardening'; SetFlag $r 'warn' }
            'Info'      { SetFlag $r 'info' }
        }
    }

    # Kontroler domeny (ten sam układ co konfiguracja bezpieczeństwa)
    foreach ($r in $D.DomainController) {
        switch ($r.Status) {
            'Krytyczne' { AddI 'Krytyczny' 'Kontroler domeny' "$($r.Check): $($r.Value)" 'DomainController'; SetFlag $r 'crit' }
            'Uwaga'     { AddI 'Ostrzeżenie' 'Kontroler domeny' "$($r.Check): $($r.Value)" 'DomainController'; SetFlag $r 'warn' }
            'Info'      { SetFlag $r 'info' }
        }
    }

    # Czas, pamięć wirtualna, koniec wsparcia
    if ($s) {
        if ($s.PSObject.Properties['TimeOffsetSec'] -and "$($s.TimeOffsetSec)" -ne '') {
            $ao  = [math]::Abs([double]$s.TimeOffsetSec)
            $msg = "Różnica czasu względem stacji skanującej: $($s.TimeOffsetSec) s (Kerberos domyślnie toleruje 300 s)"
            if ($ao -ge $C.TimeSkewCritSec) { AddI 'Krytyczny' 'Czas' $msg 'System' } elseif ($ao -ge $C.TimeSkewWarnSec) { AddI 'Ostrzeżenie' 'Czas' $msg 'System' }
        }
        if ($s.IsDC -eq $true) {
            $isPdc = ("$($s.DomainRoleId)" -eq '5')
            if ($isPdc -and "$($s.TimeSource)" -in 'NT5DS', 'NoSync', '') { AddI 'Ostrzeżenie' 'Czas' "Kontroler PDC nie ma zewnętrznego źródła czasu (W32Time Type: $(if ($s.TimeSource) { $s.TimeSource } else { 'brak' })) – z jego zegarem synchronizuje się cała domena" 'System' }
            if ($s.HvTimeSync -eq $true) { AddI $(if ($isPdc) { 'Ostrzeżenie' } else { 'Info' }) 'Czas' 'Kontroler domeny w maszynie Hyper-V bierze czas z hosta (VMICTimeProvider) – dla DC zalecane jest wyłączenie tego dostawcy' 'System' }
        }
        if ("$($s.CommitUsedPct)" -ne '' -and [int]$s.CommitUsedPct -ge $C.CommitWarnPct) { AddI 'Ostrzeżenie' 'Zasoby' "Wysokie użycie pamięci wirtualnej (commit): $($s.CommitUsedPct)% z $($s.CommitLimitGB) GB – aplikacjom może zabraknąć pamięci" 'System' }
        if ("$($s.ResourceExhaustion)" -ne '' -and [int]$s.ResourceExhaustion -gt 0) { AddI 'Ostrzeżenie' 'Zasoby' "Windows zgłosił wyczerpanie pamięci wirtualnej $($s.ResourceExhaustion)× w $days dni (zdarzenie 2004)" 'System' }
        $bn = "$($s.BuildNumber)"
        if (-not $bn -and $s.Build) { $bn = "$(@("$($s.Build)" -split '\.')[2])" }
        if ($bn -and $C.OsSupportEnd -and $C.OsSupportEnd.ContainsKey($bn)) {
            $endTxt = $C.OsSupportEnd[$bn]
            $left = [int]([datetime]::ParseExact($endTxt, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) - (Get-Date)).TotalDays
            if ($left -lt 0) { AddI 'Krytyczny' 'System' "$($s.OS): koniec wsparcia $endTxt – system nie dostaje poprawek bezpieczeństwa (chyba że ma wykupione ESU)" 'System' }
            elseif ($left -le $C.SupportWarnDays) { AddI 'Info' 'System' "$($s.OS): koniec wsparcia $endTxt (za $left dni)" 'System' }
        }
    }

    # Dzienniki zdarzeń: czy obejmują okres analizy
    foreach ($r in $D.EventLogs) {
        if ($r.Full -eq 'Tak') { AddI 'Ostrzeżenie' 'Dzienniki' "Dziennik $($r.Log) jest pełny (tryb $($r.Mode)) – nowe zdarzenia nie są zapisywane" 'EventLogs'; SetFlag $r 'warn'; continue }
        if ("$($r.CoveredDays)" -ne '' -and $r.Mode -eq 'Circular' -and [double]$r.CoveredDays -lt $days) {
            $sv = if ($r.Log -eq 'Security') { 'Ostrzeżenie' } else { 'Info' }
            AddI $sv 'Dzienniki' "Dziennik $($r.Log) obejmuje tylko $($r.CoveredDays) dni ($($r.MaxSizeMB) MB) – analiza z $days dni jest niepełna, zwiększ rozmiar dziennika" 'EventLogs'
            SetFlag $r $(if ($sv -eq 'Ostrzeżenie') { 'warn' } else { 'info' })
        }
    }

    # Polityka audytu: czy zbierane są zdarzenia, na których opiera się sekcja Zdarzenia bezpieczeństwa
    $req = @{}
    foreach ($a in @($C.AuditRequired)) { if ($a -and $a.Guid) { $req["$($a.Guid)".Trim('{}').ToUpper()] = $a } }
    $needTxt = @{ 1 = 'sukces'; 2 = 'niepowodzenie'; 3 = 'sukces i niepowodzenie' }
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($r in $D.AuditPolicy) {
        $a = $req["$($r.Guid)".Trim('{}').ToUpper()]
        $need = ''
        if ($a -and (-not $a.DcOnly -or ($s -and $s.IsDC -eq $true))) {
            $need = "$($needTxt[[int]$a.Need]) – $($a.Why)"
            if (([int]$r.Value -band [int]$a.Need) -ne [int]$a.Need) { $missing.Add("$($r.Subcategory): brak '$($needTxt[[int]$a.Need])' ($($a.Why))"); SetFlag $r 'warn' }
        }
        $r | Add-Member -NotePropertyName Required -NotePropertyValue $need -Force
    }
    if ($missing.Count) { AddI 'Ostrzeżenie' 'Audyt' ("Niepełna polityka audytu – część zdarzeń bezpieczeństwa nie jest rejestrowana: " + (Join-Short $missing 4)) 'AuditPolicy' }

    # Awarie systemu
    $bsod = @($D.Crashes | Where-Object { "$($_.Type)" -like 'BSOD*' })
    if ($bsod.Count) {
        $sv = if ($bsod.Count -ge $C.BugCheckCritCount) { 'Krytyczny' } else { 'Ostrzeżenie' }
        AddI $sv 'Stabilność' "Awarie systemu (BSOD) w $days dni: $($bsod.Count); ostatnia $($bsod[0].Time), kod $($bsod[0].Code)" 'Crashes'
        foreach ($r in $bsod) { SetFlag $r $(if ($sv -eq 'Krytyczny') { 'crit' } else { 'warn' }) }
    }
    $newDumps = @($D.Crashes | Where-Object { "$($_.Type)" -notlike 'BSOD*' -and "$($_.AgeDays)" -ne '' -and [double]$_.AgeDays -le $days })
    if ($newDumps.Count -and -not $bsod.Count) { AddI 'Ostrzeżenie' 'Stabilność' "Nowe pliki zrzutu pamięci z ostatnich $days dni: $(Join-Short ($newDumps | ForEach-Object { "$($_.Type) $($_.Time)" }) 3)" 'Crashes' }
    foreach ($r in $newDumps) { SetFlag $r 'warn' }

    # Zdrowie dysków
    foreach ($r in $D.DiskHealth) {
        if ("$($r.Id)" -eq '') {
            if ($r.Health -eq 'Awaria') { AddI 'Krytyczny' 'Dyski' "Dysk fizyczny w stanie awarii: $($r.Name) – $($r.Detail)" 'DiskHealth'; SetFlag $r 'crit' }
            elseif ($r.Health -eq 'Ostrzeżenie') { AddI 'Ostrzeżenie' 'Dyski' "Dysk fizyczny zgłasza problem: $($r.Name) – $($r.Detail)" 'DiskHealth'; SetFlag $r 'warn' }
            if ("$($r.WearPct)" -ne '' -and [int]$r.WearPct -ge $C.DiskWearWarnPct) { AddI 'Ostrzeżenie' 'Dyski' "Zużycie dysku $($r.Name): $($r.WearPct)%" 'DiskHealth'; SetFlag $r 'warn' }
            if ("$($r.UncorrectedErrors)" -ne '' -and [int64]$r.UncorrectedErrors -gt 0) { AddI 'Ostrzeżenie' 'Dyski' "Nieskorygowane błędy odczytu/zapisu na $($r.Name): $($r.UncorrectedErrors)" 'DiskHealth'; SetFlag $r 'warn' }
        } elseif ([int]$r.Id -in 7, 51, 55, 98) {
            AddI 'Ostrzeżenie' 'Dyski' "$($r.Source) ID $($r.Id) ×$($r.Count), ostatnio $($r.Last): $(Get-ShortText $r.Detail 140)" 'DiskHealth'; SetFlag $r 'warn'
        } elseif ([int]$r.Count -ge $C.DiskRetryWarn) {
            AddI 'Ostrzeżenie' 'Dyski' "Ponowienia lub resety operacji dyskowych: $($r.Source) ID $($r.Id) ×$($r.Count) w $days dni" 'DiskHealth'; SetFlag $r 'warn'
        } else { SetFlag $r 'info' }
    }

    # Hyper-V: zapas miejsca dla dysków dynamicznych
    foreach ($g in @($D.VMStorage | Where-Object { $_.Volume -and "$($_.VolumeFreeGB)" -ne '' } | Group-Object Volume)) {
        $growth = [math]::Round([double](@($g.Group) | Measure-Object GrowthGB -Sum).Sum, 1)
        $free   = [double]@($g.Group)[0].VolumeFreeGB
        if ($growth -gt $free) {
            AddI 'Ostrzeżenie' 'Hyper-V' "Dyski dynamiczne VM na $($g.Name) mogą urosnąć o $growth GB, a wolne jest $free GB – zapełnienie wolumenu wstrzyma maszyny" 'VMStorage'
            foreach ($r in $g.Group) { if ([double]$r.GrowthGB -gt 0) { SetFlag $r 'warn' } }
        }
    }

    # Ekspozycja: reguły wpuszczające porty wrażliwe z dowolnego adresu mają znaczenie, gdy karta jest w profilu Publicznym
    $expo    = @($D.Exposure | Where-Object { $_.Public -eq 'Tak' })
    $pubNics = @($D.Network | Where-Object { $_.Profile -eq 'Public' })
    if ($expo.Count -and $pubNics.Count) {
        AddI 'Ostrzeżenie' 'Sieć' ("Karta w profilu sieci Publicznym ($(Join-Short ($pubNics | ForEach-Object { $_.Adapter }) 3)), a zapora wpuszcza porty wrażliwe z dowolnego adresu: " + (Join-Short ($expo | ForEach-Object { "$($_.Ports) ($($_.Rule))" }) 4)) 'Exposure'
        foreach ($r in $expo) { SetFlag $r 'warn' }
    } else { foreach ($r in $expo) { SetFlag $r 'info' } }

    # Mechanizmy trwałości
    $ign = @($C.IgnoredWmiConsumers)
    foreach ($r in @($D.Persistence | Where-Object { "$($_.Type)" -like 'WMI – konsument*' -and $ign -notcontains $_.Name })) {
        $sv = if ("$($r.Type)" -match 'CommandLine|ActiveScript') { 'Ostrzeżenie' } else { 'Info' }
        AddI $sv 'Bezpieczeństwo' "Subskrypcja WMI (możliwy mechanizm trwałości): $($r.Name) – $($r.Type) $(Get-ShortText $r.Detail 120)" 'Persistence'
        SetFlag $r $(if ($sv -eq 'Ostrzeżenie') { 'warn' } else { 'info' })
    }
    foreach ($r in @($D.Persistence | Where-Object { "$($_.Type)" -like 'WMI*' -and "$($_.Type)" -notlike 'WMI – konsument*' })) {
        if (@(("$($r.Name)" -split ' -> ') | Where-Object { $ign -notcontains $_ }).Count) { SetFlag $r 'info' }
    }
    $exc = @($D.Persistence | Where-Object { "$($_.Type)" -like 'Defender*' })
    if ($exc.Count) { AddI 'Info' 'Bezpieczeństwo' ("Wykluczenia Defendera ($($exc.Count)): " + (Join-Short ($exc | ForEach-Object { $_.Name }) 4)) 'Persistence'; foreach ($r in $exc) { SetFlag $r 'info' } }

    # Sesje, połączenia, błędy zbierania
    # Rozłączona sesja nie ma nazwy sesji (kolumna SESSIONNAME w quser jest pusta) – niezależne od języka systemu
    $disc = @($D.Sessions | Where-Object { (-not "$($_.Session)" -and "$($_.Id)") -or $_.State -match '^(Disc|Roz)' })
    if ($disc.Count) { AddI 'Info' 'Sesje' ("Rozłączone sesje: " + (Join-Short ($disc | ForEach-Object { "$($_.User) ($($_.Idle))" }) 5)) 'Sessions'; foreach ($r in $disc) { SetFlag $r 'info' } }
    $pub = @($D.Connections | Where-Object { $_.Direction -eq 'Przychodzące' -and $_.Network -eq 'Publiczna' })
    if ($pub.Count) {
        AddI 'Info' 'Sieć' ("Połączenia przychodzące z adresów publicznych: " + (Join-Short ($pub | ForEach-Object { "$($_.Remote) na port $($_.LocalPort) ($($_.Process))" }) 4)) 'Connections'
        foreach ($r in $pub) { SetFlag $r 'warn' }
    }
    foreach ($e in @($D.Errors | Where-Object { $_ })) { AddI 'Info' 'Zbieranie danych' "Nie udało się zebrać: $e" 'System' }

    # Porównanie z poprzednim skanem
    $changes = New-Object System.Collections.Generic.List[object]
    if ($Prev -and -not $Prev.Offline) {
        foreach ($k in $script:DiffDefs.Keys) {
            $def = $script:DiffDefs[$k]
            # nie porównuj sekcji pominiętej w którymś ze skanów ani sekcji, której nie było w starszej migawce
            if (@($D.Skipped) -contains $k -or @($Prev.Skipped) -contains $k) { continue }
            if (@($Prev._Present) -notcontains $k -or @($D._Present) -notcontains $k) { continue }
            $curRows = @($D.$k); $oldRows = @($Prev.$k)
            if ($def.Filter) { $curRows = @($curRows | Where-Object $def.Filter); $oldRows = @($oldRows | Where-Object $def.Filter) }
            $oldSet = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($r in $oldRows) { [void]$oldSet.Add((& $def.KeyFn $r)) }
            $curSet = New-Object 'System.Collections.Generic.HashSet[string]'
            $new = New-Object System.Collections.Generic.List[string]
            $fl = if ($def.Sev -eq 'Info') { 'info' } else { 'warn' }
            foreach ($r in $curRows) {
                $key = & $def.KeyFn $r
                [void]$curSet.Add($key)
                if (-not $oldSet.Contains($key)) { $new.Add($key); SetFlag $r $fl }
            }
            $removed = @($oldSet | Where-Object { -not $curSet.Contains($_) })
            foreach ($x in $new)     { $changes.Add([pscustomobject]@{ Section = $def.Label; Change = 'Nowe'; Item = $x; Flag = $fl }) }
            foreach ($x in $removed) { $changes.Add([pscustomobject]@{ Section = $def.Label; Change = 'Usunięte'; Item = $x; Flag = '' }) }
            if ($new.Count -gt 0 -and $new.Count -le 5) { foreach ($x in $new) { AddI $def.Sev 'Zmiany' "Nowe od poprzedniego skanu ($($def.Label)): $x" 'Changes' } }
            elseif ($new.Count -gt 5) { AddI $def.Sev 'Zmiany' "$($new.Count) nowych pozycji ($($def.Label)), np.: $(Join-Short $new 3)" 'Changes' }
            if ($removed.Count) { AddI 'Info' 'Zmiany' "Usunięte od poprzedniego skanu ($($def.Label)): $(Join-Short $removed 3)" 'Changes' }
        }
    }
    # PS 5.1: @(List[object]) rzuca "Argument types do not match" – stąd ToArray()
    $D | Add-Member -NotePropertyName _Changes -NotePropertyValue ([object[]]$changes.ToArray()) -Force

    return , @($list | Sort-Object Rank)
}
#endregion

#region ── XAML ─────────────────────────────────────────────────────────────────
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Przegląd serwerów" Width="1540" Height="940" MinWidth="1180" MinHeight="680"
        WindowStartupLocation="CenterScreen" Background="#0F1318" Foreground="#E4E8EF"
        FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Muted" Color="#8791A5"/>
    <SolidColorBrush x:Key="Faint" Color="#5E6779"/>

    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="#161B22"/>
      <Setter Property="BorderBrush" Value="#242B36"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="10"/>
      <Setter Property="Padding" Value="16,14"/>
    </Style>

    <Style x:Key="ScrollThumb" TargetType="Thumb">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb">
            <Border CornerRadius="4" Background="#39414F"/>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ScrollBar">
      <Setter Property="Width" Value="10"/>
      <Setter Property="MinWidth" Value="10"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Grid Background="Transparent">
              <Track x:Name="PART_Track" IsDirectionReversed="True">
                <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}" Margin="2"/></Track.Thumb>
              </Track>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Width" Value="Auto"/>
          <Setter Property="MinWidth" Value="0"/>
          <Setter Property="Height" Value="10"/>
          <Setter Property="MinHeight" Value="10"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="ScrollBar">
                <Grid Background="Transparent">
                  <Track x:Name="PART_Track" IsDirectionReversed="False">
                    <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}" Margin="2"/></Track.Thumb>
                  </Track>
                </Grid>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style TargetType="Button">
      <Setter Property="Background" Value="#1B212A"/>
      <Setter Property="Foreground" Value="#E4E8EF"/>
      <Setter Property="BorderBrush" Value="#2A323F"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="7" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#4C7DF0"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.8"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#3E6FE0"/>
      <Setter Property="BorderBrush" Value="#3E6FE0"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="18,7"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#5582EC"/></Trigger>
      </Style.Triggers>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#1B212A"/>
      <Setter Property="Foreground" Value="#E4E8EF"/>
      <Setter Property="BorderBrush" Value="#2A323F"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="CaretBrush" Value="#E4E8EF"/>
      <Setter Property="SelectionBrush" Value="#3E6FE0"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="7">
              <Grid Margin="{TemplateBinding Padding}">
                <ScrollViewer x:Name="PART_ContentHost" VerticalAlignment="Center"/>
                <TextBlock x:Name="wm" Text="{TemplateBinding Tag}" Foreground="#5E6779" Margin="2,0,0,0"
                           VerticalAlignment="Center" IsHitTestVisible="False" Visibility="Collapsed"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="Text" Value=""><Setter TargetName="wm" Property="Visibility" Value="Visible"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#4C7DF0"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="RadioButton">
      <Setter Property="Foreground" Value="#8791A5"/>
      <Setter Property="Padding" Value="14,5"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="b" Background="Transparent" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter Property="Foreground" Value="#E4E8EF"/></Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="b" Property="Background" Value="#28303D"/>
                <Setter Property="Foreground" Value="#E4E8EF"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="ItemCard" TargetType="ListBoxItem">
      <Setter Property="Foreground" Value="#E4E8EF"/>
      <Setter Property="Padding" Value="10,8"/>
      <Setter Property="Margin" Value="0,1"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListBoxItem">
            <Border x:Name="b" Background="Transparent" BorderBrush="Transparent" BorderThickness="1" CornerRadius="7" Padding="{TemplateBinding Padding}">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#1A2029"/></Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="b" Property="Background" Value="#1A2640"/>
                <Setter TargetName="b" Property="BorderBrush" Value="#2F4478"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="NavItem" TargetType="ListBoxItem" BasedOn="{StaticResource ItemCard}">
      <Setter Property="Padding" Value="10,6"/>
    </Style>
    <Style TargetType="ListBox">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="ItemContainerStyle" Value="{StaticResource ItemCard}"/>
      <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Disabled"/>
    </Style>

    <Style TargetType="ProgressBar">
      <Setter Property="Background" Value="#262D39"/>
      <Setter Property="Foreground" Value="#4C7DF0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ProgressBar">
            <Grid>
              <Border x:Name="PART_Track" CornerRadius="3" Background="{TemplateBinding Background}"/>
              <Border x:Name="PART_Indicator" CornerRadius="3" Background="{TemplateBinding Foreground}" HorizontalAlignment="Left"/>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="DarkGrid" TargetType="DataGrid">
      <Style.Resources>
        <SolidColorBrush x:Key="{x:Static SystemColors.ControlBrushKey}" Color="#161B22"/>
      </Style.Resources>
      <Setter Property="Background" Value="#161B22"/>
      <Setter Property="Foreground" Value="#D5DAE3"/>
      <Setter Property="RowBackground" Value="#161B22"/>
      <Setter Property="AlternatingRowBackground" Value="#181E26"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#1F2530"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserResizeRows" Value="False"/>
      <Setter Property="SelectionMode" Value="Extended"/>
      <Setter Property="ClipboardCopyMode" Value="IncludeHeader"/>
      <Setter Property="MinRowHeight" Value="28"/>
      <Setter Property="FontSize" Value="12.5"/>
      <Setter Property="EnableRowVirtualization" Value="True"/>
      <Setter Property="ColumnHeaderStyle">
        <Setter.Value>
          <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="#1B212A"/>
            <Setter Property="Foreground" Value="#8791A5"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="BorderBrush" Value="#252C38"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
          </Style>
        </Setter.Value>
      </Setter>
      <Setter Property="CellStyle">
        <Setter.Value>
          <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Template">
              <Setter.Value>
                <ControlTemplate TargetType="DataGridCell">
                  <Border Background="{TemplateBinding Background}" Padding="10,4">
                    <ContentPresenter VerticalAlignment="Center"/>
                  </Border>
                </ControlTemplate>
              </Setter.Value>
            </Setter>
            <Style.Triggers>
              <Trigger Property="IsSelected" Value="True">
                <Setter Property="Background" Value="#233354"/>
                <Setter Property="Foreground" Value="White"/>
              </Trigger>
            </Style.Triggers>
          </Style>
        </Setter.Value>
      </Setter>
      <Setter Property="RowStyle">
        <Setter.Value>
          <Style TargetType="DataGridRow">
            <Style.Triggers>
              <DataTrigger Binding="{Binding Flag}" Value="crit"><Setter Property="Foreground" Value="#FF7A86"/></DataTrigger>
              <DataTrigger Binding="{Binding Flag}" Value="warn"><Setter Property="Foreground" Value="#FFC46B"/></DataTrigger>
              <DataTrigger Binding="{Binding Flag}" Value="info"><Setter Property="Foreground" Value="#8CC0FF"/></DataTrigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#1D2430"/></Trigger>
            </Style.Triggers>
          </Style>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Pasek górny -->
    <Border Grid.Row="0" Background="#12171D" BorderBrush="#1E242E" BorderThickness="0,0,0,1" Padding="20,12">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
          <StackPanel VerticalAlignment="Center">
            <TextBlock Text="Przegląd serwerów" FontSize="18" FontWeight="SemiBold"/>
            <TextBlock x:Name="txtSubtitle" Foreground="{StaticResource Muted}" FontSize="11.5"/>
          </StackPanel>
          <Border Background="#161B22" BorderBrush="#242B36" BorderThickness="1" CornerRadius="8" Padding="3" Margin="32,0,0,0" VerticalAlignment="Center">
            <StackPanel Orientation="Horizontal">
              <RadioButton x:Name="rbOverview" GroupName="view" Content="Wszystkie serwery" IsChecked="True"/>
              <RadioButton x:Name="rbServer" GroupName="view" Content="Szczegóły serwera"/>
            </StackPanel>
          </Border>
        </StackPanel>
        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
          <TextBlock Text="Zdarzenia z ostatnich" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="0,0,8,0"/>
          <TextBox x:Name="txtDays" Width="48" TextAlignment="Center"/>
          <TextBlock Text="dni" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="8,0,18,0"/>
          <Button x:Name="btnAD" Content="Pobierz z AD"/>
          <Button x:Name="btnFile" Content="Wczytaj listę" Margin="6,0,0,0"/>
          <Button x:Name="btnCred" Content="Konto: bieżące" Margin="6,0,0,0"/>
          <Button x:Name="btnSettings" Content="⚙" FontFamily="Segoe UI Symbol" FontSize="15" Padding="12,4" ToolTip="Ustawienia skanu" Margin="6,0,0,0"/>
          <Button x:Name="btnExport" Content="Raport HTML" Margin="6,0,0,0"/>
          <Button x:Name="btnScan" Content="Skanuj wszystkie" Style="{StaticResource PrimaryButton}" Margin="12,0,0,0"/>
        </StackPanel>
      </Grid>
    </Border>

    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="270"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Lista serwerów -->
      <Border Background="#12171D" BorderBrush="#1E242E" BorderThickness="0,0,1,0" Padding="12,14">
        <DockPanel>
          <DockPanel DockPanel.Dock="Top" Margin="4,0,4,10">
            <TextBlock x:Name="txtServerCount" DockPanel.Dock="Right" Foreground="{StaticResource Muted}" FontSize="12"/>
            <TextBlock Text="Serwery" FontSize="14" FontWeight="SemiBold"/>
          </DockPanel>
          <TextBox x:Name="txtServerFilter" DockPanel.Dock="Top" Tag="Szukaj serwera" Margin="0,0,0,8"/>
          <StackPanel DockPanel.Dock="Bottom" Margin="0,10,0,0">
            <DockPanel>
              <Button x:Name="btnAdd" DockPanel.Dock="Right" Content="Dodaj" Margin="6,0,0,0"/>
              <TextBox x:Name="txtAdd" Tag="SRV01, SRV02…"/>
            </DockPanel>
            <TextBlock Text="Delete usuwa z listy, prawy klik otwiera RDP i konsole" Foreground="{StaticResource Faint}" FontSize="11" Margin="3,6,0,0" TextWrapping="Wrap"/>
          </StackPanel>
          <ListBox x:Name="lstServers">
            <ListBox.ItemTemplate>
              <DataTemplate>
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <Ellipse Width="9" Height="9" Fill="{Binding Color}" VerticalAlignment="Center" Margin="0,0,10,0"/>
                  <StackPanel Grid.Column="1">
                    <TextBlock Text="{Binding Display}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
                    <TextBlock Text="{Binding Sub}" Foreground="#8791A5" FontSize="11" TextTrimming="CharacterEllipsis"/>
                  </StackPanel>
                  <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                    <Border Background="#2EFF5C6C" CornerRadius="8" Padding="7,1" Margin="4,0,0,0" Visibility="{Binding CritVis}">
                      <TextBlock Text="{Binding Crit}" Foreground="#FF7A86" FontSize="11" FontWeight="Bold"/>
                    </Border>
                    <Border Background="#2EFFB547" CornerRadius="8" Padding="7,1" Margin="4,0,0,0" Visibility="{Binding WarnVis}">
                      <TextBlock Text="{Binding Warn}" Foreground="#FFC46B" FontSize="11" FontWeight="Bold"/>
                    </Border>
                  </StackPanel>
                </Grid>
              </DataTemplate>
            </ListBox.ItemTemplate>
          </ListBox>
        </DockPanel>
      </Border>

      <Grid Grid.Column="1" Margin="20,16,20,12">

        <!-- Widok: wszystkie serwery -->
        <Grid x:Name="viewOverview">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="3*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="2*"/>
          </Grid.RowDefinitions>
          <UniformGrid Grid.Row="0" Columns="5" Margin="0,0,0,18">
            <Border Style="{StaticResource Card}" Margin="0,0,10,0">
              <StackPanel><TextBlock Text="Serwery na liście" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tTotal" Text="0" FontSize="30" FontWeight="SemiBold" Margin="0,2,0,0"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0">
              <StackPanel><TextBlock Text="Odpowiada" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tOnline" Text="0" FontSize="30" FontWeight="SemiBold" Foreground="#4FD1A1" Margin="0,2,0,0"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0">
              <StackPanel><TextBlock Text="Bez połączenia" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tOffline" Text="0" FontSize="30" FontWeight="SemiBold" Margin="0,2,0,0"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0">
              <StackPanel><TextBlock Text="Problemy krytyczne" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tCrit" Text="0" FontSize="30" FontWeight="SemiBold" Foreground="#FF7A86" Margin="0,2,0,0"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}">
              <StackPanel><TextBlock Text="Ostrzeżenia" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tWarn" Text="0" FontSize="30" FontWeight="SemiBold" Foreground="#FFC46B" Margin="0,2,0,0"/></StackPanel>
            </Border>
          </UniformGrid>

          <DockPanel Grid.Row="1" Margin="0,0,0,10">
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
              <Border Background="#161B22" BorderBrush="#242B36" BorderThickness="1" CornerRadius="8" Padding="3" Margin="0,0,10,0">
                <StackPanel Orientation="Horizontal">
                  <RadioButton x:Name="rbSevAll" GroupName="sev" Content="Wszystkie" IsChecked="True" Padding="10,4"/>
                  <RadioButton x:Name="rbSevCrit" GroupName="sev" Content="Krytyczne" Padding="10,4"/>
                  <RadioButton x:Name="rbSevWarn" GroupName="sev" Content="Ostrzeżenia" Padding="10,4"/>
                  <RadioButton x:Name="rbSevInfo" GroupName="sev" Content="Info" Padding="10,4"/>
                </StackPanel>
              </Border>
              <TextBox x:Name="txtIssueFilter" Width="240" Tag="Filtruj problemy"/>
            </StackPanel>
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
              <TextBlock Text="Wykryte problemy" FontSize="15" FontWeight="SemiBold"/>
              <TextBlock Text="dwuklik otwiera serwer w odpowiedniej sekcji" Foreground="{StaticResource Faint}" FontSize="11.5" Margin="12,0,0,0" VerticalAlignment="Bottom" Padding="0,0,0,1"/>
            </StackPanel>
          </DockPanel>

          <Border Grid.Row="2" Style="{StaticResource Card}" Padding="1">
            <DockPanel>
            <Border DockPanel.Dock="Bottom" BorderBrush="#242B36" BorderThickness="0,1,0,0" Background="#131820">
                    <TextBox x:Name="dIssueDetail" IsReadOnly="True" TextWrapping="Wrap" Height="64" BorderThickness="0" Background="Transparent"
                             VerticalScrollBarVisibility="Auto" VerticalContentAlignment="Top" FontFamily="Consolas, Segoe UI" FontSize="12"
                             Tag="Zaznacz wiersz, żeby zobaczyć pełną treść (można ją stąd skopiować)"/>
                  </Border>
            <DataGrid x:Name="gridIssues" Style="{StaticResource DarkGrid}" AutoGenerateColumns="False">
              <DataGrid.Columns>
                <DataGridTemplateColumn Header="Poziom" Width="118" SortMemberPath="Rank">
                  <DataGridTemplateColumn.CellTemplate>
                    <DataTemplate>
                      <Border Background="{Binding SevBg}" CornerRadius="9" Padding="9,2" HorizontalAlignment="Left">
                        <TextBlock Text="{Binding Severity}" Foreground="{Binding SevColor}" FontSize="11.5" FontWeight="SemiBold"/>
                      </Border>
                    </DataTemplate>
                  </DataGridTemplateColumn.CellTemplate>
                </DataGridTemplateColumn>
                <DataGridTextColumn Header="Serwer" Binding="{Binding Server}" Width="140"/>
                <DataGridTextColumn Header="Kategoria" Binding="{Binding Category}" Width="140"/>
                <DataGridTextColumn Header="Opis" Binding="{Binding Message}" Width="*">
                  <DataGridTextColumn.ElementStyle>
                    <Style TargetType="TextBlock">
                      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
                      <Setter Property="ToolTip" Value="{Binding Message}"/>
                    </Style>
                  </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
              </DataGrid.Columns>
            </DataGrid>
            </DockPanel>
          </Border>

          <TextBlock Grid.Row="3" Text="Stan serwerów" FontSize="15" FontWeight="SemiBold" Margin="0,18,0,10"/>
          <Border Grid.Row="4" Style="{StaticResource Card}" Padding="1">
            <DataGrid x:Name="gridServers" Style="{StaticResource DarkGrid}"/>
          </Border>
        </Grid>

        <!-- Widok: szczegóły serwera -->
        <Grid x:Name="viewServer" Visibility="Collapsed">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <Border Style="{StaticResource Card}" Padding="20,16">
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <StackPanel>
                <TextBlock x:Name="dName" Text="Wybierz serwer z listy po lewej" FontSize="24" FontWeight="SemiBold"/>
                <TextBlock x:Name="dOS" Foreground="{StaticResource Muted}" Margin="0,2,0,0" TextTrimming="CharacterEllipsis"/>
                <WrapPanel x:Name="dChips" Margin="0,12,0,0"/>
              </StackPanel>
              <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Top" Margin="20,0,0,0">
                <StackPanel Width="120" Margin="0,0,18,0">
                  <TextBlock Text="CPU" Foreground="{StaticResource Muted}" FontSize="11.5"/>
                  <TextBlock x:Name="dCpu" Text="–" FontSize="22" FontWeight="SemiBold"/>
                  <ProgressBar x:Name="pCpu" Height="5" Margin="0,6,0,0" Maximum="100"/>
                </StackPanel>
                <StackPanel Width="120" Margin="0,0,18,0">
                  <TextBlock Text="RAM" Foreground="{StaticResource Muted}" FontSize="11.5"/>
                  <TextBlock x:Name="dRam" Text="–" FontSize="22" FontWeight="SemiBold"/>
                  <ProgressBar x:Name="pRam" Height="5" Margin="0,6,0,0" Maximum="100"/>
                </StackPanel>
                <Border Background="#22FF5C6C" CornerRadius="8" Padding="14,8" Margin="0,0,8,0">
                  <StackPanel>
                    <TextBlock Text="Krytyczne" Foreground="#FF7A86" FontSize="11.5"/>
                    <TextBlock x:Name="dCrit" Text="0" FontSize="22" FontWeight="SemiBold" Foreground="#FF7A86"/>
                  </StackPanel>
                </Border>
                <Border Background="#22FFB547" CornerRadius="8" Padding="14,8">
                  <StackPanel>
                    <TextBlock Text="Ostrzeżenia" Foreground="#FFC46B" FontSize="11.5"/>
                    <TextBlock x:Name="dWarn" Text="0" FontSize="22" FontWeight="SemiBold" Foreground="#FFC46B"/>
                  </StackPanel>
                </Border>
                <Button x:Name="btnRescan" Content="Skanuj ponownie" Margin="16,0,0,0" VerticalAlignment="Center"/>
              </StackPanel>
            </Grid>
          </Border>

          <Grid Grid.Row="1" Margin="0,14,0,0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="250"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Border Style="{StaticResource Card}" Padding="6" Margin="0,0,14,0">
              <ListBox x:Name="lstSections" ItemContainerStyle="{StaticResource NavItem}">
                <ListBox.ItemTemplate>
                  <DataTemplate>
                    <DockPanel>
                      <Border DockPanel.Dock="Right" Background="{Binding BadgeBg}" CornerRadius="8" Padding="7,1" MinWidth="26">
                        <TextBlock Text="{Binding Count}" Foreground="{Binding BadgeFg}" FontSize="11" FontWeight="SemiBold" HorizontalAlignment="Center"/>
                      </Border>
                      <TextBlock Text="{Binding Header}" TextTrimming="CharacterEllipsis" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    </DockPanel>
                  </DataTemplate>
                </ListBox.ItemTemplate>
              </ListBox>
            </Border>
            <DockPanel Grid.Column="1">
              <DockPanel DockPanel.Dock="Top" Margin="0,0,0,10">
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                  <TextBox x:Name="txtGridFilter" Width="260" Tag="Filtruj wiersze"/>
                  <Button x:Name="btnCsv" Content="Eksport CSV" Margin="8,0,0,0"/>
                </StackPanel>
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                  <TextBlock x:Name="dSectionTitle" FontSize="16" FontWeight="SemiBold"/>
                  <TextBlock x:Name="dSectionCount" Foreground="{StaticResource Muted}" Margin="10,0,0,0" VerticalAlignment="Bottom" Padding="0,0,0,2"/>
                </StackPanel>
              </DockPanel>
              <Border Style="{StaticResource Card}" Padding="1">
                <DockPanel>
                  <Border DockPanel.Dock="Bottom" BorderBrush="#242B36" BorderThickness="0,1,0,0" Background="#131820">
                    <TextBox x:Name="dRowDetail" IsReadOnly="True" TextWrapping="Wrap" Height="120" BorderThickness="0" Background="Transparent"
                             VerticalScrollBarVisibility="Auto" VerticalContentAlignment="Top" FontFamily="Consolas, Segoe UI" FontSize="12"
                             Tag="Zaznacz wiersz, żeby zobaczyć pełną treść (można ją stąd skopiować)"/>
                  </Border>
                <Grid>
                  <DataGrid x:Name="gridDetail" Style="{StaticResource DarkGrid}"/>
                  <TextBlock x:Name="dEmpty" Text="Brak pozycji w tej sekcji" Foreground="{StaticResource Muted}"
                             HorizontalAlignment="Center" VerticalAlignment="Center" Visibility="Collapsed"/>
                </Grid>
                </DockPanel>
              </Border>
            </DockPanel>
          </Grid>
        </Grid>
      </Grid>
    </Grid>

    <!-- Pasek stanu -->
    <Border Grid.Row="2" Background="#12171D" BorderBrush="#1E242E" BorderThickness="0,1,0,0" Padding="20,8">
      <DockPanel>
        <TextBlock x:Name="txtLastScan" DockPanel.Dock="Right" Foreground="{StaticResource Muted}"/>
        <ProgressBar x:Name="prg" Width="220" Height="6" Margin="0,0,12,0" Maximum="100" Visibility="Collapsed" VerticalAlignment="Center"/>
        <TextBlock x:Name="txtStatus" Foreground="{StaticResource Muted}" Text="Gotowy"/>
      </DockPanel>
    </Border>
  </Grid>
</Window>
'@
#endregion

#region ── Budowa okna ──────────────────────────────────────────────────────────
$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$ui = @{}
$xNs = 'http://schemas.microsoft.com/winfx/2006/xaml'
foreach ($node in $xaml.SelectNodes("//*[@*[local-name()='Name']]")) {
    $n = $node.GetAttribute('Name', $xNs)
    if ($n) { $el = $window.FindName($n); if ($el) { $ui[$n] = $el } }
}

$script:Servers        = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
$script:Data           = @{}
$script:AllIssues      = @()
$script:Cred           = $null
$script:Sync           = $null
$script:CurrentServer  = $null
$script:CurrentSection = 'Issues'
$script:PendingSection = $null
$script:Refreshing     = $false

$ui.lstServers.ItemsSource = $script:Servers
$ui.txtDays.Text = "$($Config.EventDays)"
$ui.txtSubtitle.Text = "Domena $env:USERDNSDOMAIN, uruchomione jako $env:USERDOMAIN\$env:USERNAME"
#endregion

#region ── Lista serwerów ───────────────────────────────────────────────────────
function Get-ServerItem([string]$Name) {
    foreach ($i in $script:Servers) { if ($i.Name -eq $Name) { return $i } }
    $null
}
function New-ServerItem([string]$Name, [string]$OS) {
    [pscustomobject]@{
        Name = $Name; Display = (Get-DisplayName $Name)
        Sub = $(if ($OS) { $OS -replace '^(Microsoft )?Windows Server ', 'Windows Server ' } else { 'jeszcze nie skanowano' })
        Color = '#4A5263'; Crit = 0; Warn = 0; CritVis = 'Collapsed'; WarnVis = 'Collapsed'
    }
}
function Add-ServerEntry([string]$Name, [string]$OS) {
    $Name = "$Name".Trim()
    if (-not $Name -or $Name -in 'Name', 'ComputerName', 'Server', 'Serwer') { return }
    if (Get-ServerItem $Name) { return }
    $script:Servers.Add((New-ServerItem $Name $OS))
}
function Save-ServerList {
    try { Set-Content -LiteralPath $Config.ServerListFile -Value @($script:Servers | ForEach-Object { $_.Name }) -Encoding UTF8 } catch {}
    $ui.txtServerCount.Text = "$($script:Servers.Count)"
}
function Import-ServerFile([string]$Path) {
    Get-Content -LiteralPath $Path | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } |
        ForEach-Object { ($_ -split '[,;\s]+')[0] } | ForEach-Object { Add-ServerEntry $_ }
}
function Get-ServersFromAD {
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.Filter = '(&(objectCategory=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $s.PageSize = 1000
    [void]$s.PropertiesToLoad.AddRange([string[]]@('dnshostname', 'name', 'operatingsystem', 'lastlogontimestamp'))
    $cut = (Get-Date).AddDays(-60)
    foreach ($r in $s.FindAll()) {
        $llt = if ($r.Properties['lastlogontimestamp'].Count) { [datetime]::FromFileTime([int64]$r.Properties['lastlogontimestamp'][0]) } else { [datetime]::MinValue }
        if ($llt -lt $cut) { continue }
        $n = if ($r.Properties['dnshostname'].Count) { $r.Properties['dnshostname'][0] } else { $r.Properties['name'][0] }
        [pscustomobject]@{ Name = "$n"; OS = "$($r.Properties['operatingsystem'][0])" }
    }
}
function Update-ServerItem([string]$Name) {
    $it = Get-ServerItem $Name
    $d  = $script:Data[$Name]
    if (-not $it -or -not $d) { return }
    $iss = @($d._Issues)
    $c = @($iss | Where-Object { $_.Severity -eq 'Krytyczny' }).Count
    $w = @($iss | Where-Object { $_.Severity -eq 'Ostrzeżenie' }).Count
    $it.Crit = $c; $it.Warn = $w
    $it.CritVis = if ($c) { 'Visible' } else { 'Collapsed' }
    $it.WarnVis = if ($w) { 'Visible' } else { 'Collapsed' }
    if ($d.Offline) {
        $it.Color = '#FF5C6C'; $it.Sub = 'brak połączenia'
    } else {
        $it.Color = if ($c) { '#FF5C6C' } elseif ($w) { '#FFB547' } else { '#34D399' }
        $os = "$($d.System.OS)" -replace '^Microsoft Windows Server ', 'WS ' -replace ' (Standard|Datacenter|Essentials|Evaluation).*$', ''
        $it.Sub = "$os, uptime $([math]::Round([double]$d.System.UptimeDays)) dni"
    }
}
function Refresh-ServerList {
    $script:Refreshing = $true
    try { $ui.lstServers.Items.Refresh() } finally { $script:Refreshing = $false }
    $ui.txtServerCount.Text = "$($script:Servers.Count)"
}
function Register-ServerData([string]$Name, $D, $Prev) {
    $issues = Invoke-ServerAnalysis -Name $Name -D $D -Prev $Prev
    $D | Add-Member -NotePropertyName _Issues -NotePropertyValue @($issues) -Force
    $script:Data[$Name] = $D
    Update-ServerItem $Name
}
function Import-LastSnapshots {
    $last = $null
    foreach ($it in @($script:Servers)) {
        $files = @(Get-SnapshotFiles $it.Name)
        if (-not $files.Count) { continue }
        $d = Read-Snapshot $files[0]
        if (-not $d) { continue }
        $prev = if ($files.Count -gt 1) { Read-Snapshot $files[1] } else { $null }
        $t = (Get-Item -LiteralPath $files[0]).LastWriteTime
        if (-not $last -or $t -gt $last) { $last = $t }
        $d | Add-Member -NotePropertyName ScannedAt -NotePropertyValue $t.ToString('yyyy-MM-dd HH:mm') -Force
        Register-ServerData $it.Name $d $prev
    }
    if ($last) { $ui.txtLastScan.Text = "Wyniki z ostatniego skanu: $($last.ToString('yyyy-MM-dd HH:mm'))" }
}
#endregion

#region ── Widok ogólny ─────────────────────────────────────────────────────────
function Update-Overview {
    $all = New-Object System.Collections.Generic.List[object]
    $sum = New-Object System.Collections.Generic.List[object]
    $online = 0; $offline = 0; $crit = 0; $warn = 0
    foreach ($it in $script:Servers) {
        $d = $script:Data[$it.Name]
        if (-not $d) { continue }
        foreach ($i in @($d._Issues)) { $all.Add($i) }
        $c = @($d._Issues | Where-Object { $_.Severity -eq 'Krytyczny' }).Count
        $w = @($d._Issues | Where-Object { $_.Severity -eq 'Ostrzeżenie' }).Count
        $crit += $c; $warn += $w
        if ($d.Offline) {
            $offline++
            $sum.Add([pscustomobject]@{ Key = $it.Name; Server = $it.Display; Status = 'Brak połączenia'; OS = ''; UptimeDays = $null; CPU = $null; RAM = $null; MinDiskPct = $null; PatchDays = $null; Crit = $c; Warn = $w; ScanSec = $null; Scanned = $d.ScannedAt; Flag = 'crit' })
        } else {
            $online++
            $s = $d.System
            $minDisk = (@($d.Disks) | Measure-Object FreePct -Minimum).Minimum
            $sum.Add([pscustomobject]@{
                Key = $it.Name; Server = $it.Display; Status = 'OK'; OS = $("$($s.OS)" -replace '^Microsoft ', '')
                UptimeDays = $s.UptimeDays; CPU = $s.CpuLoad; RAM = $s.RamUsedPct; MinDiskPct = $minDisk
                PatchDays = $(if ($s.LastHotfixDays -ge 0) { $s.LastHotfixDays } else { $null }); Crit = $c; Warn = $w
                ScanSec = $d.DurationSec; Scanned = $d.ScannedAt
                Flag = $(if ($c) { 'crit' } elseif ($w) { 'warn' } else { '' })
            })
        }
    }
    $script:AllIssues = @($all | Sort-Object Rank, Server)
    $ui.gridIssues.ItemsSource = $script:AllIssues
    Update-IssueFilter
    $ui.gridServers.Columns.Clear()
    $ui.gridServers.ItemsSource = @($sum | Sort-Object @{ e = 'Crit'; Descending = $true }, @{ e = 'Warn'; Descending = $true }, Server)
    $ui.tTotal.Text   = "$($script:Servers.Count)"
    $ui.tOnline.Text  = "$online"
    $ui.tOffline.Text = "$offline"
    $ui.tOffline.Foreground = Brush $(if ($offline) { '#FF7A86' } else { '#E4E8EF' })
    $ui.tCrit.Text    = "$crit"
    $ui.tWarn.Text    = "$warn"
}
function Update-IssueFilter {
    if ($null -eq $ui.gridIssues.ItemsSource) { return }
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridIssues.ItemsSource)
    if (-not $view) { return }
    $t = $ui.txtIssueFilter.Text.Trim()
    $sev = if ($ui.rbSevCrit.IsChecked) { 'Krytyczny' } elseif ($ui.rbSevWarn.IsChecked) { 'Ostrzeżenie' } elseif ($ui.rbSevInfo.IsChecked) { 'Info' } else { '' }
    if (-not $t -and -not $sev) { $view.Filter = $null; return }
    $view.Filter = [Predicate[object]]({
        param($o)
        if ($sev -and $o.Severity -ne $sev) { return $false }
        if ($t) { return ("$($o.Server) $($o.Category) $($o.Message)".IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) }
        $true
    }.GetNewClosure())
}
#endregion

#region ── Widok serwera ────────────────────────────────────────────────────────
function Add-Chip([string]$Text, [string]$Kind = '') {
    $fg, $bg = switch ($Kind) {
        'warn' { '#FFC46B', '#26FFB547' }
        'crit' { '#FF7A86', '#26FF5C6C' }
        'ok'   { '#5EE3AE', '#2034D399' }
        default { '#C3CAD6', '#1E252F' }
    }
    $b = New-Object System.Windows.Controls.Border
    $b.CornerRadius = New-Object System.Windows.CornerRadius 7
    $b.Padding = New-Object System.Windows.Thickness -ArgumentList 10, 3, 10, 3
    $b.Margin  = New-Object System.Windows.Thickness -ArgumentList 0, 0, 6, 6
    $b.Background = Brush $bg
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = $Text; $tb.FontSize = 12; $tb.Foreground = Brush $fg
    $b.Child = $tb
    [void]$ui.dChips.Children.Add($b)
}
function Get-MetricColor($v) { if ($v -ge 90) { '#FF5C6C' } elseif ($v -ge 75) { '#FFB547' } else { '#34D399' } }

function Get-SectionRows($D, [string]$Key) {
    switch ($Key) {
        'Issues'  { @($D._Issues | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Severity = $_.Severity; Category = $_.Category; Message = $_.Message; Flag = $_.Flag } }) }
        'Changes' { @($D._Changes | Where-Object { $_ }) }
        'System'  {
            if ($D.System) {
                foreach ($p in $D.System.PSObject.Properties) {
                    $v = if ($p.Value -is [bool]) { if ($p.Value) { 'Tak' } else { 'Nie' } } else { "$($p.Value)" }
                    $f = if (($p.Name -eq 'PendingReboot' -and $p.Value) -or ($p.Name -eq 'UptimeDays' -and $p.Value -gt $Config.UptimeWarnDays) -or
                             ($p.Name -eq 'LastHotfixDays' -and $p.Value -gt $Config.PatchWarnDays) -or
                             ($p.Name -eq 'CommitUsedPct' -and "$($p.Value)" -ne '' -and $p.Value -ge $Config.CommitWarnPct) -or
                             ($p.Name -eq 'ResourceExhaustion' -and $p.Value -gt 0) -or
                             ($p.Name -eq 'TimeOffsetSec' -and "$($p.Value)" -ne '' -and [math]::Abs([double]$p.Value) -ge $Config.TimeSkewWarnSec)) { 'warn' } else { '' }
                    [pscustomobject]@{ Property = (Get-Header $p.Name); Value = $v; Flag = $f }
                }
            }
        }
        default   { @($D.$Key | Where-Object { $null -ne $_ }) }
    }
}
function Test-SectionShown($D, [string]$Key) {
    if ($D.Offline) { return ($Key -eq 'Issues') }
    if (@($D.Skipped) -contains $Key) { return $false }                     # pominięta w ustawieniach skanu
    if ($Key -in 'HyperV', 'Checkpoints', 'VMStorage' -and -not $D.System.IsHyperV) { return $false }
    if ($Key -eq 'LocalUsers' -and $D.System.IsDC) { return $false }
    if ($Key -eq 'DomainController' -and -not $D.System.IsDC) { return $false }
    $true
}
function Get-WorstFlag($Rows) {
    $f = @($Rows | ForEach-Object { "$($_.Flag)" })
    if ($f -contains 'crit') { 'crit' } elseif ($f -contains 'warn') { 'warn' } elseif ($f -contains 'info') { 'info' } else { '' }
}

function Show-ServerDetail([string]$Name) {
    $script:CurrentServer = $Name
    $ui.dChips.Children.Clear()
    $ui.btnRescan.IsEnabled = ([bool]$Name) -and (-not $script:Sync)
    $item = if ($Name) { Get-ServerItem $Name } else { $null }
    $d = if ($Name) { $script:Data[$Name] } else { $null }
    $ui.dCpu.Text = '–'; $ui.dRam.Text = '–'; $ui.pCpu.Value = 0; $ui.pRam.Value = 0; $ui.dCrit.Text = '0'; $ui.dWarn.Text = '0'
    if (-not $item) {
        $ui.dName.Text = 'Wybierz serwer z listy po lewej'; $ui.dOS.Text = ''
        $ui.lstSections.ItemsSource = $null; $ui.gridDetail.ItemsSource = $null; $ui.dSectionTitle.Text = ''; $ui.dSectionCount.Text = ''
        return
    }
    $ui.dName.Text = $item.Display
    if (-not $d) {
        $ui.dOS.Text = "$Name – jeszcze nie skanowano. Użyj przycisku Skanuj ponownie."
        $ui.lstSections.ItemsSource = $null; $ui.gridDetail.ItemsSource = $null; $ui.dSectionTitle.Text = ''; $ui.dSectionCount.Text = ''
        return
    }
    $ui.dCrit.Text = "$($item.Crit)"; $ui.dWarn.Text = "$($item.Warn)"
    if ($d.Offline) {
        $ui.dOS.Text = "$Name – brak połączenia"
        Add-Chip "Próba: $($d.ScannedAt)" 'crit'
    } else {
        $s = $d.System
        $ui.dOS.Text = "$($s.OS), build $($s.Build), $($s.DomainRole) – $($s.FQDN)"
        Add-Chip "Uptime $($s.UptimeDays) dni" $(if ($s.UptimeDays -gt $Config.UptimeWarnDays) { 'warn' } else { '' })
        Add-Chip "Ostatni start $($s.LastBoot)"
        $ip = (@($d.Network) | Where-Object { $_.IPv4 } | Select-Object -First 1).IPv4
        if ($ip) { Add-Chip "IP $ip" }
        if ($s.LastHotfixDays -ge 0) { Add-Chip "Aktualizacja $($s.LastHotfixDays) dni temu" $(if ($s.LastHotfixDays -gt $Config.PatchWarnDays) { 'warn' } else { 'ok' }) }
        if ($s.PendingReboot) { Add-Chip 'Wymaga restartu' 'warn' }
        if ($s.IsDC) { Add-Chip 'Kontroler domeny' }
        if ($s.IsHyperV) { Add-Chip "Hyper-V, $(@($d.HyperV).Count) maszyn" }
        if ($s.AV) { Add-Chip "$($s.AV)" }
        if ($s.PSObject.Properties['TimeOffsetSec'] -and "$($s.TimeOffsetSec)" -ne '') { Add-Chip "Czas $(if ([double]$s.TimeOffsetSec -gt 0) { '+' })$($s.TimeOffsetSec) s" $(if ([math]::Abs([double]$s.TimeOffsetSec) -ge $Config.TimeSkewWarnSec) { 'warn' } else { '' }) }
        if (@($d.Skipped | Where-Object { $_ }).Count) { Add-Chip "Pominięte sekcje: $(@($d.Skipped | Where-Object { $_ }).Count)" }
        Add-Chip "$($s.Cores) vCPU, $($s.RamGB) GB RAM"
        Add-Chip "Skan $($d.ScannedAt), $($d.DurationSec) s"
        $ui.dCpu.Text = "$($s.CpuLoad)%"; $ui.pCpu.Value = [double]$s.CpuLoad; $ui.pCpu.Foreground = Brush (Get-MetricColor $s.CpuLoad)
        $ui.dRam.Text = "$($s.RamUsedPct)%"; $ui.pRam.Value = [double]$s.RamUsedPct; $ui.pRam.Foreground = Brush (Get-MetricColor $s.RamUsedPct)
    }

    $nav = New-Object System.Collections.Generic.List[object]
    foreach ($sec in $script:Sections) {
        if (-not (Test-SectionShown $d $sec.Key)) { continue }
        $rows = @(Get-SectionRows $d $sec.Key)
        $bg, $fg = switch (Get-WorstFlag $rows) {
            'crit'  { '#33FF5C6C', '#FF7A86' }
            'warn'  { '#33FFB547', '#FFC46B' }
            default { '#1CFFFFFF', '#8791A5' }
        }
        $nav.Add([pscustomobject]@{ Key = $sec.Key; Header = $sec.Header; Count = $rows.Count; BadgeBg = $bg; BadgeFg = $fg; Rows = $rows })
    }
    $ui.lstSections.ItemsSource = $nav
    $want = if ($script:PendingSection) { $script:PendingSection } else { $script:CurrentSection }
    $script:PendingSection = $null
    $sel = $nav | Where-Object { $_.Key -eq $want } | Select-Object -First 1
    if (-not $sel) { $sel = $nav[0] }
    $ui.lstSections.SelectedItem = $sel
}

function Show-Section {
    $sel = $ui.lstSections.SelectedItem
    if (-not $sel) { return }
    $script:CurrentSection = $sel.Key
    $ui.dSectionTitle.Text = $sel.Header
    $ui.dSectionCount.Text = "$($sel.Count) pozycji"
    $ui.gridDetail.ItemsSource = $null
    $ui.gridDetail.Columns.Clear()
    $rows = @($sel.Rows)
    $ui.gridDetail.ItemsSource = $rows
    $ui.dEmpty.Visibility = if ($rows.Count) { 'Collapsed' } else { 'Visible' }
    Update-DetailFilter
}
function Update-DetailFilter {
    if ($null -eq $ui.gridDetail.ItemsSource) { return }
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridDetail.ItemsSource)
    if (-not $view) { return }
    $t = $ui.txtGridFilter.Text.Trim()
    if (-not $t) { $view.Filter = $null; return }
    $view.Filter = [Predicate[object]]({
        param($o)
        foreach ($p in $o.PSObject.Properties) { if ("$($p.Value)".IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
        $false
    }.GetNewClosure())
}
function Select-Server([string]$Key, [string]$Section) {
    $item = Get-ServerItem $Key
    if (-not $item) { return }
    $ui.txtServerFilter.Text = ''
    $script:PendingSection = $Section
    if ($ui.lstServers.SelectedItem -eq $item) { Show-ServerDetail $Key; $ui.rbServer.IsChecked = $true }
    else { $ui.lstServers.SelectedItem = $item }
    $ui.lstServers.ScrollIntoView($item)
}
#endregion

#region ── Skanowanie ───────────────────────────────────────────────────────────
function Set-ScanUi([bool]$On) {
    $ui.btnScan.Content    = if ($On) { 'Przerwij skan' } else { 'Skanuj wszystkie' }
    $ui.prg.Visibility     = if ($On) { 'Visible' } else { 'Collapsed' }
    $ui.prg.Value          = 0
    $ui.btnAD.IsEnabled    = -not $On
    $ui.btnFile.IsEnabled  = -not $On
    $ui.btnCred.IsEnabled  = -not $On
    $ui.btnSettings.IsEnabled = -not $On
    $ui.btnRescan.IsEnabled = (-not $On) -and [bool]$script:CurrentServer
}

function Start-Scan([string[]]$Targets) {
    if ($script:Sync) { return }
    $Targets = @($Targets | Where-Object { $_ })
    if (-not $Targets.Count) { [void](Show-Msg 'Lista serwerów jest pusta. Dodaj serwery ręcznie, z pliku lub z Active Directory.'); return }
    $days = 0
    if (-not [int]::TryParse($ui.txtDays.Text, [ref]$days) -or $days -lt 1 -or $days -gt 180) { $days = $Config.EventDays; $ui.txtDays.Text = "$days" }

    New-Item -ItemType Directory -Force -Path $Config.SnapshotDir | Out-Null
    $script:SnapDir = Join-Path $Config.SnapshotDir (Get-Date -Format 'yyyyMMdd_HHmmss')
    New-Item -ItemType Directory -Force -Path $script:SnapDir | Out-Null

    foreach ($t in $Targets) { $it = Get-ServerItem $t; if ($it) { $it.Color = '#4C7DF0'; $it.Sub = 'skanowanie…' } }
    Refresh-ServerList

    $script:Sync = [hashtable]::Synchronized(@{
        Queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
        Done = 0; Total = $Targets.Count; Finished = $false; Cancel = $false; Fatal = $null
    })
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $skipList      = [string[]]@($Config.SkipSections | Where-Object { $_ })
    $collectorArgs = @($days, [string[]]$Config.Folders, [int]$Config.MaxEvents, [bool]$Config.IncludeWarnings, $skipList, [int[]]@($Config.ExposedPorts))
    [void]$ps.AddScript($ScanWorker.ToString())
    [void]$ps.AddArgument($script:Sync)
    [void]$ps.AddArgument([string[]]$Targets)
    [void]$ps.AddArgument($Collector.ToString())
    [void]$ps.AddArgument($collectorArgs)
    [void]$ps.AddArgument($script:Cred)
    [void]$ps.AddArgument([int]$Config.ThrottleLimit)
    [void]$ps.AddArgument([int]$Config.ScanTimeoutSec)
    $script:ScanPS     = $ps
    $script:ScanStart  = Get-Date
    $script:ScanHandle = $ps.BeginInvoke()
    Set-ScanUi $true
    $ui.txtStatus.Text = "Skanowanie 0 z $($Targets.Count)…$(if ($skipList.Count) { " (pominięte sekcje: $($skipList.Count))" })"
    $script:Timer.Start()
}

function Receive-ServerResult($R) {
    $name = $R.Name
    $prev = $null
    if ($R.Json) {
        try {
            $prevFile = @(Get-SnapshotFiles $name) | Where-Object { -not $_.StartsWith($script:SnapDir, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            $d = ConvertFrom-ServerJson $R.Json
            if ($d.PSObject.Properties['Fatal']) { throw "kolektor przerwał pracę na serwerze: $($d.Fatal)" }
            $json = $R.Json
            if ($R.PSObject.Properties['ReceivedUtc'] -and $R.ReceivedUtc -and $d.System -and $d.System.PSObject.Properties['CollectedUtc'] -and $d.System.CollectedUtc) {
                $cu  = $d.System.CollectedUtc
                $cu  = if ($cu -is [datetime]) { $cu.ToUniversalTime() } else { [datetime]::Parse("$cu", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
                $off = [math]::Round(($cu - $R.ReceivedUtc).TotalSeconds, 1)
                $d.System | Add-Member -NotePropertyName TimeOffsetSec -NotePropertyValue $off -Force
                # zapisujemy różnicę czasu także w migawce (kultura niezmienna – kropka dziesiętna w JSON)
                $json = ([regex]'"System":\{').Replace($json, '"System":{"TimeOffsetSec":' + $off.ToString([Globalization.CultureInfo]::InvariantCulture) + ',', 1)
            }
            [IO.File]::WriteAllText((Join-Path $script:SnapDir ((Get-SafeName $name) + '.json')), $json, (New-Object System.Text.UTF8Encoding $false))
            if ($prevFile) { $prev = Read-Snapshot $prevFile }
        } catch {
            $d = [pscustomobject]@{ Offline = $true; Error = "$($_.Exception.Message)" }
        }
    } else {
        $d = [pscustomobject]@{ Offline = $true; Error = "$($R.Error)" }
    }
    $d | Add-Member -NotePropertyName ScannedAt -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd HH:mm') -Force
    Register-ServerData $name $d $prev
}

function Complete-Scan {
    $script:Timer.Stop()
    $sync = $script:Sync
    try { [void]$script:ScanPS.EndInvoke($script:ScanHandle) } catch {}
    try { $script:ScanPS.Runspace.Dispose(); $script:ScanPS.Dispose() } catch {}
    $script:ScanPS = $null
    $script:Sync = $null
    Set-ScanUi $false
    $el = [int]((Get-Date) - $script:ScanStart).TotalSeconds
    if ((Test-Path -LiteralPath $script:SnapDir) -and -not (Get-ChildItem -LiteralPath $script:SnapDir)) { Remove-Item -LiteralPath $script:SnapDir -Force }
    Remove-OldSnapshots
    $ui.txtStatus.Text   = "Skan zakończony w $el s, sprawdzono serwerów: $($sync.Total)"
    $ui.txtLastScan.Text = "Ostatni skan: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    Update-Overview
    Show-ServerDetail $script:CurrentServer
    if ($sync.Fatal) { [void](Show-Msg "Skan nie mógł się uruchomić: $($sync.Fatal)" 'Error') }
}

$script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval = [TimeSpan]::FromMilliseconds(400)
$script:Timer.Add_Tick({
    $sync = $script:Sync
    if (-not $sync) { $script:Timer.Stop(); return }
    $r = $null; $got = $false
    while ($sync.Queue.TryDequeue([ref]$r)) { Receive-ServerResult $r; $got = $true }
    if ($sync.Total) { $ui.prg.Value = [double]$sync.Done / $sync.Total * 100 }
    $el = [int]((Get-Date) - $script:ScanStart).TotalSeconds
    $ui.txtStatus.Text = if ($sync.Cancel) { 'Przerywanie skanu…' } else { "Skanowanie $($sync.Done) z $($sync.Total), $el s" }
    if ($got) {
        Refresh-ServerList
        Update-Overview
        if ($script:CurrentServer -and $ui.viewServer.Visibility -eq 'Visible') { Show-ServerDetail $script:CurrentServer }
    }
    if ($sync.Finished -and $sync.Queue.IsEmpty) { Complete-Scan }
})
#endregion

#region ── Raport HTML ──────────────────────────────────────────────────────────
function HtmlEnc($s) { [System.Net.WebUtility]::HtmlEncode("$s") }
function ConvertTo-HtmlTable($Rows) {
    $Rows = @($Rows)
    if (-not $Rows.Count) { return '<p class="muted">Brak pozycji</p>' }
    $cols = @($Rows[0].PSObject.Properties.Name | Where-Object { $_ -ne 'Flag' })
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="wrap"><table><thead><tr>')
    foreach ($c in $cols) { [void]$sb.Append("<th>$(HtmlEnc (Get-Header $c))</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        [void]$sb.Append("<tr class=`"$($r.Flag)`">")
        foreach ($c in $cols) { [void]$sb.Append("<td>$(HtmlEnc $r.$c)</td>") }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    $sb.ToString()
}
function Export-HtmlReport {
    if (-not $script:Data.Count) { [void](Show-Msg 'Brak danych. Najpierw wykonaj skan.'); return }
    New-Item -ItemType Directory -Force -Path $Config.ReportDir | Out-Null
    $file = Join-Path $Config.ReportDir ('Przeglad_serwerow_{0:yyyyMMdd_HHmm}.html' -f (Get-Date))
    $issues = @($script:AllIssues)
    $css = @'
:root{--bg:#0f1318;--panel:#161b22;--line:#242b36;--text:#e4e8ef;--muted:#8791a5;--crit:#ff7a86;--warn:#ffc46b;--info:#8cc0ff;--ok:#4fd1a1}
@media (prefers-color-scheme:light){:root{--bg:#f4f6f9;--panel:#fff;--line:#e2e6ee;--text:#1a1f29;--muted:#667085;--crit:#d92d3f;--warn:#b86e00;--info:#2463c9;--ok:#138a5e}}
*{box-sizing:border-box}body{margin:0;padding:32px;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}h3{font-size:14px;margin:22px 0 8px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:22px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:28px;font-weight:600}
.wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:12.5px}th{text-align:left;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word;max-width:640px}tr:last-child td{border-bottom:0}
tr.crit td{color:var(--crit)}tr.warn td{color:var(--warn)}tr.info td{color:var(--info)}
.pill{display:inline-block;padding:1px 9px;border-radius:9px;font-size:11.5px;font-weight:600;white-space:nowrap}
.p-Krytyczny{color:var(--crit);background:color-mix(in srgb,var(--crit) 16%,transparent)}.p-Ostrzeżenie{color:var(--warn);background:color-mix(in srgb,var(--warn) 16%,transparent)}.p-Info{color:var(--info);background:color-mix(in srgb,var(--info) 16%,transparent)}
details{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:10px 0;padding:0 18px}
details>div{padding-bottom:18px}summary{cursor:pointer;padding:14px 0;font-weight:600;font-size:15px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:10px}
button{font:inherit;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:7px;padding:6px 14px;cursor:pointer;margin-right:6px}
@media print{details{break-inside:avoid}button{display:none}}
'@
    $sb = New-Object System.Text.StringBuilder
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm'
    [void]$sb.Append("<!DOCTYPE html><html lang=`"pl`"><head><meta charset=`"utf-8`"><meta name=`"viewport`" content=`"width=device-width,initial-scale=1`"><title>Przegląd serwerów $now</title><style>$css</style></head><body>")
    [void]$sb.Append("<h1>Przegląd serwerów</h1><div class=`"muted`">Wygenerowano $now przez $(HtmlEnc "$env:USERDOMAIN\$env:USERNAME"), domena $(HtmlEnc $env:USERDNSDOMAIN)</div>")
    $online = @($script:Data.Values | Where-Object { -not $_.Offline }).Count
    $tiles = @(
        @('Serwery', $script:Data.Count, ''), @('Odpowiada', $online, 'var(--ok)'), @('Bez połączenia', ($script:Data.Count - $online), 'var(--crit)'),
        @('Krytyczne', @($issues | Where-Object Severity -eq 'Krytyczny').Count, 'var(--crit)'), @('Ostrzeżenia', @($issues | Where-Object Severity -eq 'Ostrzeżenie').Count, 'var(--warn)')
    )
    [void]$sb.Append('<div class="tiles">')
    foreach ($t in $tiles) { [void]$sb.Append("<div class=`"tile`"><span class=`"muted`">$($t[0])</span><b style=`"color:$($t[2])`">$($t[1])</b></div>") }
    [void]$sb.Append('</div><h2>Wykryte problemy</h2><div class="wrap"><table><thead><tr><th>Poziom</th><th>Serwer</th><th>Kategoria</th><th>Opis</th></tr></thead><tbody>')
    foreach ($i in $issues) {
        [void]$sb.Append("<tr><td><span class=`"pill p-$($i.Severity)`">$(HtmlEnc $i.Severity)</span></td><td>$(HtmlEnc $i.Server)</td><td>$(HtmlEnc $i.Category)</td><td>$(HtmlEnc $i.Message)</td></tr>")
    }
    [void]$sb.Append('</tbody></table></div><h2>Szczegóły serwerów</h2>')
    [void]$sb.Append('<button onclick="document.querySelectorAll(''details'').forEach(d=>d.open=true)">Rozwiń wszystkie</button><button onclick="document.querySelectorAll(''details'').forEach(d=>d.open=false)">Zwiń wszystkie</button>')
    foreach ($it in $script:Servers) {
        $d = $script:Data[$it.Name]
        if (-not $d) { continue }
        $os = if ($d.Offline) { 'brak połączenia' } else { "$($d.System.OS)" }
        [void]$sb.Append("<details><summary><span class=`"dot`" style=`"background:$($it.Color)`"></span>$(HtmlEnc $it.Display) <span class=`"muted`">$(HtmlEnc $os)</span>")
        if ($it.Crit) { [void]$sb.Append(" <span class=`"pill p-Krytyczny`">$($it.Crit)</span>") }
        if ($it.Warn) { [void]$sb.Append(" <span class=`"pill p-Ostrzeżenie`">$($it.Warn)</span>") }
        [void]$sb.Append('</summary><div>')
        if ($d.Offline) { [void]$sb.Append("<p style=`"color:var(--crit)`">$(HtmlEnc $d.Error)</p>") }
        else {
            foreach ($sec in $script:Sections) {
                if (-not (Test-SectionShown $d $sec.Key)) { continue }
                $rows = @(Get-SectionRows $d $sec.Key)
                [void]$sb.Append("<h3>$(HtmlEnc $sec.Header) <span class=`"muted`">($($rows.Count))</span></h3>")
                [void]$sb.Append((ConvertTo-HtmlTable $rows))
            }
        }
        [void]$sb.Append('</div></details>')
    }
    [void]$sb.Append('</body></html>')
    [IO.File]::WriteAllText($file, $sb.ToString(), (New-Object System.Text.UTF8Encoding $true))
    $ui.txtStatus.Text = "Raport zapisano: $file"
    Start-Process $file
}
#endregion

#region ── Okno Ustawienia ─────────────────────────────────────────────────────
$script:SettingsXamlText = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Ustawienia skanu" Width="1040" Height="780" MinWidth="820" MinHeight="560"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" Background="#0F1318" Foreground="#E4E8EF"
        FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="#D5DAE3"/>
      <Setter Property="Margin" Value="0,3"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <Grid Background="Transparent">
              <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <Border x:Name="box" Width="16" Height="16" CornerRadius="4" BorderThickness="1" BorderBrush="#39414F" Background="#1B212A" VerticalAlignment="Top" Margin="0,1,0,0">
                <Path x:Name="mark" Data="M3,8 L6.5,11.5 L13,4" Stroke="White" StrokeThickness="2" Visibility="Collapsed"/>
              </Border>
              <ContentPresenter Grid.Column="1" Margin="9,0,0,0" VerticalAlignment="Center">
                <ContentPresenter.Resources><Style TargetType="TextBlock"><Setter Property="TextWrapping" Value="Wrap"/></Style></ContentPresenter.Resources>
              </ContentPresenter>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="box" Property="Background" Value="#3E6FE0"/>
                <Setter TargetName="box" Property="BorderBrush" Value="#3E6FE0"/>
                <Setter TargetName="mark" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="box" Property="BorderBrush" Value="#4C7DF0"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="MultiText" TargetType="TextBox" BasedOn="{StaticResource {x:Type TextBox}}">
      <Setter Property="AcceptsReturn" Value="True"/>
      <Setter Property="TextWrapping" Value="NoWrap"/>
      <Setter Property="VerticalScrollBarVisibility" Value="Auto"/>
      <Setter Property="HorizontalScrollBarVisibility" Value="Auto"/>
      <Setter Property="VerticalContentAlignment" Value="Top"/>
      <Setter Property="FontFamily" Value="Consolas, Segoe UI"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="7">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#4C7DF0"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid Margin="20,16,20,16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <StackPanel Margin="0,0,0,14">
      <TextBlock Text="Ustawienia skanu" FontSize="18" FontWeight="SemiBold"/>
      <TextBlock x:Name="sSubtitle" Foreground="#8791A5" FontSize="11.5" TextWrapping="Wrap" Margin="0,2,0,0"/>
    </StackPanel>
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="5*"/>
        <ColumnDefinition Width="16"/>
        <ColumnDefinition Width="6*"/>
      </Grid.ColumnDefinitions>
      <Border Style="{StaticResource Card}">
        <DockPanel>
          <DockPanel DockPanel.Dock="Top" Margin="0,0,0,6">
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top">
              <Button x:Name="sAll" Content="Wszystko" Padding="10,4"/>
              <Button x:Name="sNone" Content="Nic" Padding="10,4" Margin="6,0,0,0"/>
            </StackPanel>
            <StackPanel>
              <TextBlock Text="Zakres skanu" FontSize="15" FontWeight="SemiBold"/>
              <TextBlock Text="Odznaczone sekcje nie są zbierane ani porównywane" Foreground="#5E6779" FontSize="11.5" TextWrapping="Wrap"/>
            </StackPanel>
          </DockPanel>
          <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel x:Name="sSections" Margin="0,0,8,0"/></ScrollViewer>
        </DockPanel>
      </Border>
      <Border Grid.Column="2" Style="{StaticResource Card}">
        <DockPanel>
          <StackPanel DockPanel.Dock="Top" Margin="0,0,0,6">
            <TextBlock Text="Parametry i progi" FontSize="15" FontWeight="SemiBold"/>
            <TextBlock Text="Pole „Zdarzenia z ostatnich … dni” w głównym oknie zmienia zakres tylko dla bieżącego skanu" Foreground="#5E6779" FontSize="11.5" TextWrapping="Wrap"/>
          </StackPanel>
          <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel x:Name="sParams" Margin="0,0,10,0"/></ScrollViewer>
        </DockPanel>
      </Border>
    </Grid>
    <DockPanel Grid.Row="2" Margin="0,14,0,0">
      <Button x:Name="sDefaults" Content="Przywróć domyślne" DockPanel.Dock="Left"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="sCancel" Content="Anuluj" IsCancel="True"/>
        <Button x:Name="sSave" Content="Zapisz" Style="{StaticResource PrimaryButton}" Margin="8,0,0,0"/>
      </StackPanel>
    </DockPanel>
  </Grid>
</Window>
'@

function New-SettingsDialog {
    # style głównego okna (karty, przyciski, pola, paski przewijania) kopiujemy do okna ustawień, żeby wyglądało tak samo
    $sx = New-Object System.Xml.XmlDocument
    $sx.LoadXml($script:SettingsXamlText)
    $dst   = @($sx.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'Window.Resources' })[0]
    $src   = @($xaml.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'Window.Resources' })[0]
    $first = $dst.FirstChild
    foreach ($n in @($src.ChildNodes)) { [void]$dst.InsertBefore($sx.ImportNode($n, $true), $first) }
    $dlg = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $sx))
    $c = @{}
    foreach ($nm in 'sSubtitle', 'sSections', 'sParams', 'sAll', 'sNone', 'sDefaults', 'sCancel', 'sSave') { $c[$nm] = $dlg.FindName($nm) }
    $c.sSubtitle.Text = "Domyślnie skanowane jest wszystko. Zmiany zapisują się w $($Config.SettingsFile); wartości domyślne pochodzą z bloku `$Config w skrypcie."
    $checks = New-Object System.Collections.Generic.List[object]
    $inputs = @{}
    foreach ($grp in $script:SectionGroups.Keys) {
        $h = New-Object System.Windows.Controls.TextBlock
        $h.Text = $grp; $h.FontWeight = 'SemiBold'; $h.Foreground = Brush '#8791A5'
        $h.Margin = New-Object System.Windows.Thickness -ArgumentList 0, 12, 0, 4
        [void]$c.sSections.Children.Add($h)
        foreach ($k in $script:SectionGroups[$grp]) {
            $sec = @($script:Sections | Where-Object { $_.Key -eq $k })[0]
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.Content = if ($sec) { $sec.Header } else { $k }
            $cb.Tag = $k
            [void]$c.sSections.Children.Add($cb); $checks.Add($cb)
        }
    }
    foreach ($d in $script:SettingDefs) {
        if ($d.Type -eq 'bool') {
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.Content = $d.Label; $cb.Margin = New-Object System.Windows.Thickness -ArgumentList 0, 6, 0, 6
            [void]$c.sParams.Children.Add($cb); $inputs[$d.Key] = $cb
        } elseif ($d.Type -in 'list', 'intlist') {
            $lb = New-Object System.Windows.Controls.TextBlock
            $lb.Text = $d.Label; $lb.Foreground = Brush '#C3CAD6'; $lb.TextWrapping = 'Wrap'
            $lb.Margin = New-Object System.Windows.Thickness -ArgumentList 0, 14, 0, 4
            $tb = New-Object System.Windows.Controls.TextBox
            $tb.Style = $dlg.FindResource('MultiText'); $tb.Height = 96
            [void]$c.sParams.Children.Add($lb); [void]$c.sParams.Children.Add($tb); $inputs[$d.Key] = $tb
        } else {
            $g = New-Object System.Windows.Controls.Grid
            $g.Margin = New-Object System.Windows.Thickness -ArgumentList 0, 3, 0, 3
            $col2 = New-Object System.Windows.Controls.ColumnDefinition; $col2.Width = New-Object System.Windows.GridLength 90
            [void]$g.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)); [void]$g.ColumnDefinitions.Add($col2)
            $lb = New-Object System.Windows.Controls.TextBlock
            $lb.Text = $d.Label; $lb.Foreground = Brush '#C3CAD6'; $lb.TextWrapping = 'Wrap'; $lb.VerticalAlignment = 'Center'
            $lb.Margin = New-Object System.Windows.Thickness -ArgumentList 0, 0, 12, 0
            $tb = New-Object System.Windows.Controls.TextBox
            $tb.TextAlignment = 'Center'; $tb.Padding = New-Object System.Windows.Thickness -ArgumentList 6, 3, 6, 3
            [System.Windows.Controls.Grid]::SetColumn($tb, 1)
            [void]$g.Children.Add($lb); [void]$g.Children.Add($tb); [void]$c.sParams.Children.Add($g); $inputs[$d.Key] = $tb
        }
    }
    # stan okna trzymamy w zmiennej skryptu – handlery WPF wywołują funkcje skryptu i muszą go widzieć
    $script:SetDlg = @{ Dialog = $dlg; Controls = $c; Checks = $checks; Inputs = $inputs; Saved = $false }
    $c.sAll.Add_Click({ foreach ($cb in $script:SetDlg.Checks) { $cb.IsChecked = $true } })
    $c.sNone.Add_Click({ foreach ($cb in $script:SetDlg.Checks) { $cb.IsChecked = $false } })
    $c.sDefaults.Add_Click({ Set-SettingsDialogValues $script:ConfigDefaults })
    $c.sSave.Add_Click({ Save-SettingsDialog })
    Set-SettingsDialogValues (Get-ConfigSnapshot)
    $dlg
}
function Set-SettingsDialogValues([hashtable]$V) {
    foreach ($cb in $script:SetDlg.Checks) { $cb.IsChecked = (@($V.SkipSections) -notcontains $cb.Tag) }
    foreach ($d in $script:SettingDefs) {
        $ctl = $script:SetDlg.Inputs[$d.Key]
        if ($d.Type -eq 'bool') { $ctl.IsChecked = [bool]$V[$d.Key] }
        elseif ($d.Type -in 'list', 'intlist') { $ctl.Text = (@($V[$d.Key]) -join [Environment]::NewLine) }
        else { $ctl.Text = "$($V[$d.Key])" }
    }
}
function Read-SettingsDialogValues {
    $V = @{}
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($d in $script:SettingDefs) {
        $ctl = $script:SetDlg.Inputs[$d.Key]
        if ($d.Type -eq 'bool') { $V[$d.Key] = [bool]$ctl.IsChecked; continue }
        if ($d.Type -in 'list', 'intlist') {
            $items = @("$($ctl.Text)" -split '\r?\n|;' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($d.Type -eq 'intlist') {
                $wrong = New-Object System.Collections.Generic.List[string]
                foreach ($i in $items) { $n = 0; if (-not [int]::TryParse($i, [ref]$n) -or $n -lt 1 -or $n -gt 65535) { $wrong.Add($i) } }
                if ($wrong.Count) { $bad.Add("$($d.Label): niepoprawne wartości: $($wrong -join ', ')") }
            }
            $V[$d.Key] = $items
            continue
        }
        $n = 0
        if (-not [int]::TryParse("$($ctl.Text)".Trim(), [ref]$n) -or $n -lt $d.Min -or $n -gt $d.Max) { $bad.Add("$($d.Label): podaj liczbę od $($d.Min) do $($d.Max)") }
        else { $V[$d.Key] = $n }
    }
    if ($V.ContainsKey('DiskCritPct') -and $V.ContainsKey('DiskWarnPct') -and $V.DiskCritPct -gt $V.DiskWarnPct) { $bad.Add('Dysk: próg krytyczny nie może być wyższy niż próg ostrzeżenia') }
    if ($V.ContainsKey('TimeSkewWarnSec') -and $V.ContainsKey('TimeSkewCritSec') -and $V.TimeSkewWarnSec -gt $V.TimeSkewCritSec) { $bad.Add('Różnica czasu: próg ostrzeżenia nie może być wyższy niż próg krytyczny') }
    $V.SkipSections = [string[]]@($script:SetDlg.Checks | Where-Object { -not $_.IsChecked } | ForEach-Object { "$($_.Tag)" })
    if ($V.SkipSections.Count -ge $script:SetDlg.Checks.Count) { $bad.Add('Zaznacz co najmniej jedną sekcję do skanowania') }
    [pscustomobject]@{ Values = $V; Errors = $bad.ToArray() }
}
function Save-SettingsDialog {
    $r = Read-SettingsDialogValues
    if ($r.Errors.Count) { [void][System.Windows.MessageBox]::Show($script:SetDlg.Dialog, ($r.Errors -join [Environment]::NewLine), 'Ustawienia', 'OK', 'Warning'); return }
    Set-ConfigFromValues $r.Values
    try { Save-UserSettings } catch { [void][System.Windows.MessageBox]::Show($script:SetDlg.Dialog, "Nie udało się zapisać $($Config.SettingsFile): $($_.Exception.Message)", 'Ustawienia', 'OK', 'Error'); return }
    $script:SetDlg.Saved = $true
    $script:SetDlg.Dialog.Close()
}
function Update-SettingsButton {
    $n = @($Config.SkipSections | Where-Object { $_ }).Count
    # kompaktowy przycisk (zębatka), żeby pasek narzędzi zmieścił się w domyślnej szerokości okna
    $ui.btnSettings.Content = if ($n) { "⚙ $n" } else { '⚙' }
    $ui.btnSettings.ToolTip = if ($n) { "Ustawienia skanu – pomijane sekcje: $n" } else { 'Ustawienia skanu (skanowane są wszystkie sekcje)' }
}
function Show-SettingsDialog {
    try { $dlg = New-SettingsDialog } catch { [void](Show-Msg "Nie udało się otworzyć okna ustawień: $($_.Exception.Message)" 'Error'); return }
    $dlg.Owner = $window
    [void]$dlg.ShowDialog()
    if ($script:SetDlg -and $script:SetDlg.Saved) {
        $ui.txtDays.Text = "$($Config.EventDays)"
        Update-SettingsButton
        $n = @($Config.SkipSections | Where-Object { $_ }).Count
        $ui.txtStatus.Text = if ($n) { "Zapisano ustawienia – przy następnym skanie pomijane będą sekcje: $n" } else { 'Zapisano ustawienia – skanowane są wszystkie sekcje' }
    }
    $script:SetDlg = $null
}
#endregion

#region ── Zdarzenia interfejsu ─────────────────────────────────────────────────
$onAutoColumn = {
    param($sender, $e)
    if ($e.PropertyName -in 'Flag', 'Key', 'Rows') { $e.Cancel = $true; return }
    $e.Column.Header = Get-Header $e.PropertyName
    $e.Column.MaxWidth = 900
    if ($e.Column -is [System.Windows.Controls.DataGridTextColumn]) {
        $st = New-Object System.Windows.Style ([System.Windows.Controls.TextBlock])
        $st.Setters.Add((New-Object System.Windows.Setter -ArgumentList ([System.Windows.Controls.TextBlock]::TextTrimmingProperty), ([System.Windows.TextTrimming]::CharacterEllipsis)))
        $st.Setters.Add((New-Object System.Windows.Setter -ArgumentList ([System.Windows.FrameworkElement]::ToolTipProperty), (New-Object System.Windows.Data.Binding $e.PropertyName)))
        $e.Column.ElementStyle = $st
    }
}
$ui.gridDetail.Add_AutoGeneratingColumn($onAutoColumn)
$ui.gridServers.Add_AutoGeneratingColumn($onAutoColumn)

$ui.rbOverview.Add_Checked({ $ui.viewOverview.Visibility = 'Visible'; $ui.viewServer.Visibility = 'Collapsed' })
$ui.rbServer.Add_Checked({
    $ui.viewOverview.Visibility = 'Collapsed'; $ui.viewServer.Visibility = 'Visible'
    Show-ServerDetail $script:CurrentServer
})
foreach ($rb in 'rbSevAll', 'rbSevCrit', 'rbSevWarn', 'rbSevInfo') { $ui[$rb].Add_Checked({ Update-IssueFilter }) }
$ui.txtIssueFilter.Add_TextChanged({ Update-IssueFilter })
$ui.txtGridFilter.Add_TextChanged({ Update-DetailFilter })

$ui.txtServerFilter.Add_TextChanged({
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:Servers)
    $t = $ui.txtServerFilter.Text.Trim()
    if (-not $t) { $view.Filter = $null }
    else { $view.Filter = [Predicate[object]]({ param($o) "$($o.Name)".IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0 }.GetNewClosure()) }
})

$ui.lstServers.Add_SelectionChanged({
    if ($script:Refreshing) { return }
    $sel = $ui.lstServers.SelectedItem
    if ($sel) {
        if ($ui.rbServer.IsChecked) { Show-ServerDetail $sel.Name }
        else { $script:CurrentServer = $sel.Name; $ui.rbServer.IsChecked = $true }
    }
})
$ui.lstSections.Add_SelectionChanged({ Show-Section })

function Format-RowDetail($Row) {
    if (-not $Row) { return '' }
    $skip = 'Flag', 'Key', 'Rows', 'SevColor', 'SevBg', 'Rank', 'ServerKey', 'Section'
    $lines = @($Row.PSObject.Properties | Where-Object { $skip -notcontains $_.Name } | ForEach-Object { "{0}: {1}" -f (Get-Header $_.Name), $_.Value })
    $lines -join [Environment]::NewLine
}
$ui.gridDetail.Add_SelectionChanged({ $ui.dRowDetail.Text = Format-RowDetail $ui.gridDetail.SelectedItem })
$ui.gridIssues.Add_SelectionChanged({ $ui.dIssueDetail.Text = Format-RowDetail $ui.gridIssues.SelectedItem })

$ui.lstServers.Add_KeyDown({
    param($s, $e)
    if ($e.Key -eq 'Delete' -and $ui.lstServers.SelectedItem -and -not $script:Sync) {
        $it = $ui.lstServers.SelectedItem
        [void]$script:Servers.Remove($it)
        $script:Data.Remove($it.Name)
        Save-ServerList; Update-Overview
        if ($script:CurrentServer -eq $it.Name) { Show-ServerDetail $null }
    }
})

# Menu kontekstowe listy serwerów
$cm = New-Object System.Windows.Controls.ContextMenu
$menu = [ordered]@{
    'Skanuj ten serwer'      = { Start-Scan @($args[0]) }
    'Połącz przez RDP'       = { Start-Process mstsc.exe -ArgumentList "/v:$($args[0])" }
    'Zarządzanie komputerem' = { Start-Process compmgmt.msc -ArgumentList "/computer:\\$($args[0])" }
    'Podgląd zdarzeń'        = { Start-Process eventvwr.exe -ArgumentList $args[0] }
    'Usługi'                 = { Start-Process services.msc -ArgumentList "/computer:\\$($args[0])" }
    'Otwórz udział C$'       = { Start-Process explorer.exe -ArgumentList "\\$($args[0])\C$" }
}
foreach ($label in $menu.Keys) {
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header = $label
    $mi.Tag = $menu[$label]
    $mi.Add_Click({
        param($s, $e)
        $sel = $ui.lstServers.SelectedItem
        if ($sel) { & $s.Tag $sel.Name }
    })
    [void]$cm.Items.Add($mi)
}
$ui.lstServers.ContextMenu = $cm

$addHandler = {
    $names = @($ui.txtAdd.Text -split '[,;\s]+' | Where-Object { $_ })
    foreach ($n in $names) { Add-ServerEntry $n }
    if ($names.Count) { Save-ServerList; Update-Overview; $ui.txtAdd.Text = '' }
}
$ui.btnAdd.Add_Click($addHandler)
$ui.txtAdd.Add_KeyDown({ param($s, $e); if ($e.Key -eq 'Return') { & $addHandler } })

$ui.btnAD.Add_Click({
    try { $found = @(Get-ServersFromAD) } catch { [void](Show-Msg "Nie udało się odpytać AD: $($_.Exception.Message)" 'Error'); return }
    if (-not $found.Count) { [void](Show-Msg 'Nie znaleziono aktywnych kont serwerów w AD.'); return }
    $new = @($found | Where-Object { -not (Get-ServerItem $_.Name) })
    $ans = Show-Msg "W AD jest $($found.Count) aktywnych serwerów (logowanie w ostatnich 60 dniach), z czego $($new.Count) nie ma jeszcze na liście.`n`nDodać brakujące?" 'Question' 'YesNo'
    if ("$ans" -eq 'Yes') {
        foreach ($f in ($new | Sort-Object Name)) { Add-ServerEntry $f.Name $f.OS }
        Save-ServerList; Update-Overview
        $ui.txtStatus.Text = "Dodano $($new.Count) serwerów z AD"
    }
})

$ui.btnFile.Add_Click({
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'Lista serwerów (*.txt;*.csv)|*.txt;*.csv|Wszystkie pliki|*.*'
    if ($dlg.ShowDialog($window) -eq $true) {
        $before = $script:Servers.Count
        Import-ServerFile $dlg.FileName
        Save-ServerList; Update-Overview
        $ui.txtStatus.Text = "Dodano $($script:Servers.Count - $before) serwerów z pliku"
    }
})

$ui.btnCred.Add_Click({
    $c = $null
    try { $c = Get-Credential -Message 'Konto z uprawnieniami administratora na serwerach (Anuluj = bieżące konto)' } catch {}
    $script:Cred = $c
    $ui.btnCred.Content = if ($c) { "Konto: $($c.UserName)" } else { 'Konto: bieżące' }
})

$ui.btnScan.Add_Click({
    if ($script:Sync) { $script:Sync.Cancel = $true; $ui.txtStatus.Text = 'Przerywanie skanu…'; return }
    Start-Scan @($script:Servers | ForEach-Object { $_.Name })
})
$ui.btnRescan.Add_Click({ if ($script:CurrentServer) { Start-Scan @($script:CurrentServer) } })
$ui.btnExport.Add_Click({ Export-HtmlReport })
$ui.btnSettings.Add_Click({ Show-SettingsDialog })

$ui.gridIssues.Add_MouseDoubleClick({
    $i = $ui.gridIssues.SelectedItem
    if ($i) { Select-Server $i.ServerKey $i.Section }
})
$ui.gridServers.Add_MouseDoubleClick({
    $r = $ui.gridServers.SelectedItem
    if ($r) { Select-Server $r.Key 'Issues' }
})

$ui.btnCsv.Add_Click({
    $sel = $ui.lstSections.SelectedItem
    if (-not $sel -or -not $sel.Count) { return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = "$(Get-DisplayName $script:CurrentServer)_$($sel.Key)_$(Get-Date -Format yyyyMMdd).csv"
    if ($dlg.ShowDialog($window) -eq $true) {
        $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridDetail.ItemsSource)
        @($view) | Select-Object * -ExcludeProperty Flag | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Delimiter ';' -Encoding UTF8
        $ui.txtStatus.Text = "Zapisano: $($dlg.FileName)"
    }
})

$window.Add_Loaded({
    if (Test-Path -LiteralPath $Config.ServerListFile) { Import-ServerFile $Config.ServerListFile }
    $ui.txtServerCount.Text = "$($script:Servers.Count)"
    Import-LastSnapshots
    Refresh-ServerList
    Update-Overview
    if (-not $script:Servers.Count) { $ui.txtStatus.Text = 'Dodaj serwery: Pobierz z AD, Wczytaj listę albo wpisz nazwę w polu po lewej' }
    else { $ui.txtStatus.Text = "Wczytano $($script:Servers.Count) serwerów z $($Config.ServerListFile)" }
    Update-SettingsButton
    if ($script:SettingsWarning) { $ui.txtStatus.Text = $script:SettingsWarning }
})
$window.Add_Closing({ if ($script:Sync) { $script:Sync.Cancel = $true } })
#endregion

[void]$window.ShowDialog()
if ($script:ScanPS) { try { $script:ScanPS.Stop(); $script:ScanPS.Dispose() } catch {} }
