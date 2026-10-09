<#
.SYNOPSIS
    Przegląd serwerów – zbiorczy audyt stanu serwerów Windows w domenie z GUI (WPF).

.DESCRIPTION
    Łączy się równolegle (WinRM / Invoke-Command, pula wątków z limitem czasu na każdy serwer) ze wszystkimi
    serwerami z listy i zbiera:
      - system: uptime, oczekujący restart, ostatnia aktualizacja, CPU/RAM, role, WSUS, wirtualizacja (host Hyper-V gościa)
      - dyski, adresację IP, porty nasłuchujące, aktywne połączenia (z procesem i usługą)
      - usługi (nie-Microsoft, zatrzymane automatyczne, konta usług, niecytowane ścieżki)
      - harmonogram zadań (poza \Microsoft\) z wynikiem ostatniego uruchomienia
      - błędy i zdarzenia krytyczne z System/Application, historię restartów i przestoje (wyłączenie → start)
      - zdarzenia bezpieczeństwa (nieudane logowania, zmiany kont i grup, czyszczenie logów, nowe usługi)
      - oprogramowanie, aktualizacje KB, grupy uprzywilejowane, konta lokalne, sesje RDP
      - udziały, autostart, certyfikaty, zawartość wskazanych folderów
      - Hyper-V: pojemność hosta, maszyny wirtualne (system gościa, adresy IP), checkpointy, dyski VM, klaster
      - podstawowy hardening (SMBv1, NLA, WDigest, NTLM, Defender, zapora, LLMNR, autologon...)
    Każdy skan zapisuje migawkę (JSON, domyślnie skompresowaną). Kolejny skan porównuje się z poprzednim i pokazuje,
    co NOWEGO pojawiło się na serwerze (usługi, zadania, porty, admini, autostart, oprogramowanie).

    Niedostępne serwery są diagnozowane ze stacji (DNS, ping, porty WinRM/RPC/SMB/RDP, konto komputera w AD,
    klasyfikacja błędu WinRM, stan maszyny wirtualnej na hoście Hyper-V), a każdy wynik trafia do dziennika
    dostępności. Dziennik operacji (panel na dole okna, Ctrl+L) zapisuje się do Logs\ServerReview_RRRRMMDD.log.
    Program można zablokować PIN-em (przycisk z kłódką, Ctrl+Shift+L, automatycznie po bezczynności).
    Maszyny z Linuksem nie są skanowane – są rozpoznawane na hostach Hyper-V i pomijane.

.PARAMETER ServerListFile
    Własny plik z listą serwerów (domyślnie servers.txt obok skryptu).

.PARAMETER Scan
    Tryb bez okna (np. zadanie Harmonogramu zadań): skanuje wszystkie serwery z listy, zapisuje migawki, dziennik
    i raport HTML, po czym kończy pracę z kodem 0 (wszystkie serwery odpowiedziały), 1 (część serwerów bez
    połączenia) albo 2 (skan się nie odbył). PIN nie jest wymagany.

.PARAMETER ReportMode
    Z -Scan: rodzaj raportu HTML – Summary (problemy i pozycje wymagające uwagi, domyślnie) albo Full (wszystkie sekcje).

.PARAMETER NoReport
    Z -Scan: bez raportu HTML.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\ServerReview.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ServerReview.ps1 -Scan -ReportMode Summary

.NOTES
    Wymagania:
      - Windows PowerShell 5.1 na stacji, z której uruchamiasz (WPF)
      - WinRM na serwerach (domyślnie włączony na Windows Server 2012+), port 5985
      - konto z uprawnieniami administratora lokalnego na serwerach (odczyt dziennika Security)
    Plik musi być zapisany jako UTF-8 z BOM (polskie znaki w Windows PowerShell 5.1).

    Copyright (C) 2026 Borys Kaleta
    SPDX-License-Identifier: GPL-3.0-or-later

    Ten program jest wolnym oprogramowaniem: możesz go rozpowszechniać i/lub modyfikować
    na warunkach licencji GNU General Public License opublikowanej przez Free Software Foundation,
    w wersji 3 tej licencji lub (według twojego wyboru) dowolnej późniejszej wersji.
    Program jest rozpowszechniany BEZ JAKIEJKOLWIEK GWARANCJI, nawet domyślnej gwarancji
    PRZYDATNOŚCI HANDLOWEJ albo PRZYDATNOŚCI DO OKREŚLONYCH ZASTOSOWAŃ. Pełny tekst licencji:
    plik LICENSE albo <https://www.gnu.org/licenses/>.

.LINK
    https://github.com/borubarczyk/ServerReview
#>
[CmdletBinding()]
param(
    [string]$ServerListFile,
    [switch]$Scan,
    [ValidateSet('Summary', 'Full')][string]$ReportMode = 'Summary',
    [switch]$NoReport
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
    ServerTimeoutSec       = 300      # limit czasu zbierania danych z JEDNEGO serwera (liczony od chwili, gdy jego skan ruszył)
    ConnectTimeoutSec      = 30       # limit nawiązania połączenia WinRM
    ScanTimeoutSec         = 3600     # limit czasu całego skanu (zabezpieczenie)
    Preflight              = $true    # szybki test portu WinRM 5985 przed skanem – wyłączony serwer nie zajmuje wątku przez pełny limit połączenia
    RetryFailed            = $true    # po skanie jedna ponowna próba dla serwerów z błędem, który może być chwilowy (restart, WinRM jeszcze nie wstał)
    SnapshotsToKeep        = 30
    CompressSnapshots      = $true    # migawki zapisywane jako .json.gz (ok. 10x mniej miejsca przy dużej liczbie serwerów)
    # Diagnostyka niedostępnych serwerów (ze stacji): sprawdzane porty TCP i limit czasu pojedynczej próby
    DiagPorts              = @(5985, 5986, 135, 445, 3389)
    DiagTimeoutMs          = 2000
    # Hyper-V: pamięć przydzielona działającym maszynom względem RAM hosta i stosunek vCPU do procesorów logicznych
    HostRamWarnPct         = 90
    VcpuRatioWarn          = 6
    HvHostMinFreeGB        = 8        # host Hyper-V: zajęty RAM to normalny stan (pamięć maszyn), liczy się zapas wolnej pamięci
    VmOffInfoDays          = 30       # maszyna wyłączona dłużej = prawdopodobnie wycofana
    # Active Directory: przycisk „Pobierz z AD” (pusta ścieżka = cała domena) i diagnoza kont komputerów
    AdSearchBase           = ''
    AdInactiveDays         = 60
    # Dziennik operacji (Logs\ServerReview_RRRRMMDD.log) i dziennik dostępności (Logs\Availability_RRRRMM.csv)
    LogRetentionDays       = 90
    # Blokada programu po bezczynności [min] (działa, gdy ustawiono PIN; 0 = wyłączona)
    LockIdleMinutes        = 10
    # Wyciszone problemy: @{ Server = 'SRV01' albo '*'; Key = klucz problemu; Text = przykładowa treść; Added; By }
    IgnoredIssues          = @()
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
    LogDir                 = Join-Path $Base 'Logs'
    SettingsFile           = Join-Path $Base 'settings.json'   # zapis z okna Ustawienia (nadpisuje wartości powyżej)
}
if ($ServerListFile) { $Config.ServerListFile = $ServerListFile }
#endregion

#region ── Start: wersja PowerShell i tryb STA ───────────────────────────────────
$script:AppVersion = '2.0'
# WPF wymaga wątku STA; skrypt jest pisany pod Windows PowerShell 5.1 – z PowerShell 7 (Core) też przełączamy się na powershell.exe.
# Tryb bez okna (-Scan) nie potrzebuje STA, ale z PowerShell 7 też przechodzi na 5.1 (czeka na wynik i oddaje kod wyjścia).
$isCore = $PSVersionTable.PSEdition -eq 'Core'
$isSta  = [Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
if ($isCore -or (-not $Scan -and -not $isSta)) {
    if (-not $PSCommandPath) { throw 'Uruchom skrypt jako plik: powershell.exe -STA -File .\ServerReview.ps1' }
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($ServerListFile) { $argList += @('-ServerListFile', "`"$ServerListFile`"") }   # nie gub parametrów przy ponownym uruchomieniu
    # Start-Process (inaczej niż zwykłe wywołanie) przekazuje ścieżki modułów PowerShell 7 do 5.1 – moduły systemowe z PS 7
    # nie ładują się wtedy w 5.1 (np. Get-Credential); czyścimy je tylko na czas uruchomienia procesu potomnego
    $pmp = $env:PSModulePath
    if ($isCore) { $env:PSModulePath = $null }
    $p = $null
    try {
        if ($Scan) {
            $argList += @('-Scan', '-ReportMode', $ReportMode)
            if ($NoReport) { $argList += '-NoReport' }
            $p = Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru -NoNewWindow
        } else { Start-Process -FilePath $exe -ArgumentList $argList }
    } finally { if ($isCore) { $env:PSModulePath = $pmp } }
    if ($Scan) { exit $p.ExitCode }
    return
}
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.Windows.Forms   # pozycja kursora (blokada po bezczynności)
# Folder danych musi być zapisywalny (np. skrypt na udziale tylko do odczytu) – inaczej dane trafiają do %LOCALAPPDATA%\ServerReview
$script:BaseFallback = ''
try {
    New-Item -ItemType Directory -Force -Path $Base -ErrorAction Stop | Out-Null
    $probe = Join-Path $Base ('.sr_write_test_{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText($probe, 'x'); [IO.File]::Delete($probe)
} catch {
    $newBase = Join-Path $env:LOCALAPPDATA 'ServerReview'
    New-Item -ItemType Directory -Force -Path $newBase | Out-Null
    foreach ($k in 'SnapshotDir', 'ReportDir', 'LogDir', 'SettingsFile') { $Config[$k] = $Config[$k].Replace($Base, $newBase) }
    # lista serwerów i ustawienia: kopia przy pierwszym uruchomieniu, dalej zapisywane w nowym miejscu
    $oldList = $Config.ServerListFile
    if (-not $ServerListFile) {
        $Config.ServerListFile = Join-Path $newBase 'servers.txt'
        if ((Test-Path -LiteralPath $oldList) -and -not (Test-Path -LiteralPath $Config.ServerListFile)) { Copy-Item -LiteralPath $oldList -Destination $Config.ServerListFile -ErrorAction SilentlyContinue }
    }
    $oldSettings = Join-Path $Base 'settings.json'
    if ((Test-Path -LiteralPath $oldSettings) -and -not (Test-Path -LiteralPath $Config.SettingsFile)) { Copy-Item -LiteralPath $oldSettings -Destination $Config.SettingsFile -ErrorAction SilentlyContinue }
    $script:BaseFallback = "Folder $Base jest tylko do odczytu – dane programu zapisywane są w $newBase"
    $Base = $newBase
}
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
    if (Get-Service ClusSvc -ErrorAction SilentlyContinue) { Import-Module FailoverClusters -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }

    $ErrorActionPreference = 'Stop'
    $ProgressPreference    = 'SilentlyContinue'
    $sw    = [Diagnostics.Stopwatch]::StartNew()
    $now   = Get-Date
    $since = $now.AddDays(-$Days)
    $errs  = New-Object System.Collections.Generic.List[string]
    $timings = @{}   # czas zbierania sekcji [s] – pokazuje, które sekcje spowalniają skan
    $failedKeys = New-Object System.Collections.Generic.List[string]   # sekcje, których nie udało się zebrać (stacja nie porównuje ich ze skanem poprzednim)
    try {

    # $Key = klucz sekcji (jak w danych wynikowych); sekcje z listy $SkipSections są pomijane
    function Want([string]$Key) { -not $Key -or $SkipSections -notcontains $Key }
    function S([string]$Key, [string]$Section, [scriptblock]$Block) {
        if (-not (Want $Key)) { return }
        $t0 = $sw.Elapsed.TotalSeconds
        try { & $Block } catch { if ($Key) { $failedKeys.Add($Key) }; $errs.Add("$Section`: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber): $("$($_.InvocationInfo.Line)".Trim())]") }
        finally { $timings[$Section] = [math]::Round($sw.Elapsed.TotalSeconds - $t0, 1) }
    }
    function D($dt) { if ($dt) { try { ([datetime]$dt).ToString('yyyy-MM-dd HH:mm') } catch { "$dt" } } else { '' } }
    function Short([string]$s, [int]$n) { $s = "$s" -replace '\s+', ' '; if ($s.Length -gt $n) { $s.Substring(0, $n) + '...' } else { $s.Trim() } }
    # Hasła podane w linii poleceń (usługi, zadania, autostart, WMI) nie trafiają do migawek, raportów ani CSV
    function Hide-Secret([string]$s) {
        if (-not $s) { return $s }
        $s = [regex]::Replace($s, '(?i)((?:^|\s)[-/](?:p|pw|pwd|pass|passwd|password|secret|token|apikey)(?::|=|\s+))(?!\d)("[^"]*"|\S+)', '$1***')
        [regex]::Replace($s, '(?i)((?:password|passwd|pwd|secret|token|apikey)\s*=\s*)("[^"]*"|[^;\s"]+)', '$1***')
    }

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
        $sys.RamFreeGB     = [math]::Round($os.FreePhysicalMemory / 1MB, 2)   # FreePhysicalMemory w KB
        $sys.Domain        = $cs.Domain
        $sys.DomainRole    = $roles[[int]$cs.DomainRole]
        $sys.IsDC          = ([int]$cs.DomainRole -ge 4)
        $sys.DomainRoleId  = [int]$cs.DomainRole
        $sys.BuildNumber   = [int]$os.BuildNumber
        # Pamięć wirtualna (commit): limit = RAM + pliki stronicowania
        $sys.CommitLimitGB = [math]::Round($os.TotalVirtualMemorySize / 1MB, 1)
        $sys.CommitUsedPct = if ($os.TotalVirtualMemorySize) { [int](100 - ($os.FreeVirtualMemory / $os.TotalVirtualMemorySize * 100)) } else { $null }
        $sys.PageFileAuto  = [bool]$cs.AutomaticManagedPagefile
        # Wirtualizacja (model komputera); host Hyper-V sam w sobie nie jest maszyną wirtualną
        $mm = "$($cs.Manufacturer) $($cs.Model)"
        $sys.Hypervisor = if ($mm -match 'Microsoft Corporation Virtual Machine') { 'Hyper-V' } elseif ($mm -match 'VMware') { 'VMware' }
                          elseif ($mm -match 'QEMU|KVM|Bochs|Nutanix|OpenStack|Red Hat') { 'KVM' } elseif ($mm -match 'Xen|HVM domU') { 'Xen' }
                          elseif ($mm -match 'VirtualBox|innotek') { 'VirtualBox' } elseif ($mm -match 'Amazon EC2|Google Compute') { 'Chmura' } else { '' }
        $sys.IsVirtual = [bool]$sys.Hypervisor
    } catch { $errs.Add("System: $($_.Exception.Message)") }
    # Gość Hyper-V: host i nazwa maszyny z usług integracji (wymiana KVP host → gość); aktualne także po migracji na żywo
    $sys.HvHost = ''; $sys.HvVmName = ''; $sys.HvVmId = ''
    try {
        $gp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' -ErrorAction Stop
        $sys.HvHost   = if ($gp.PhysicalHostNameFullyQualified) { "$($gp.PhysicalHostNameFullyQualified)" } else { "$($gp.PhysicalHostName)" }
        $sys.HvVmName = "$($gp.VirtualMachineName)"
        $sys.HvVmId   = "$($gp.VirtualMachineId)".Trim('{}').ToUpper()
        if (-not $sys.Hypervisor) { $sys.Hypervisor = 'Hyper-V'; $sys.IsVirtual = $true }
    } catch {}
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
    $timings['System'] = [math]::Round($sw.Elapsed.TotalSeconds, 1)

    # ── Aktualizacje ──
    $hfAll = @(S '' 'Aktualizacje' {
        Get-HotFix | ForEach-Object {
            # Surowa wartość WMI (M/d/yyyy albo FILETIME szesnastkowo) parsowana niezależnie od języka – w PS 4.0 właściwość
            # InstalledOn parsuje datę w kulturze stacji przekazanej przez WinRM (pl-PL: dzień i miesiąc zamienione)
            $dt = $null; $raw = ''
            try { $raw = "$($_.psbase.Properties['InstalledOn'].Value)" } catch {}
            if ($raw -match '^\d{1,2}/\d{1,2}/\d{4}$') { try { $dt = [datetime]::ParseExact($raw, 'M/d/yyyy', [Globalization.CultureInfo]::InvariantCulture) } catch {} }
            elseif ($raw -match '^[0-9A-Fa-f]{16}$') { try { $dt = [datetime]::FromFileTime([Convert]::ToInt64($raw, 16)) } catch {} }
            if (-not $dt) { try { $dt = $_.InstalledOn } catch {} }
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
    $t0 = $sw.Elapsed.TotalSeconds
    try { if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { $features = @(Get-WindowsFeature) } } catch {}
    $timings['Role i funkcje'] = [math]::Round($sw.Elapsed.TotalSeconds - $t0, 1)
    $sys.Roles = (@($features | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object { $_.DisplayName }) -join ', ')
    $sys.IsHyperV  = [bool](Get-Service vmms -ErrorAction SilentlyContinue)
    try { $sys.TimeZone = [TimeZoneInfo]::Local.Id } catch { $sys.TimeZone = '' }   # Get-TimeZone jest dopiero w PS 5.1
    $sys.PSVersion = $PSVersionTable.PSVersion.ToString()

    # ── Konfiguracja bezpieczeństwa ──
    $hard = New-Object System.Collections.Generic.List[object]
    function Add-Check($check, $value, $status) { $hard.Add([pscustomobject]@{ Check = $check; Value = "$value"; Status = $status }) }
    $t0 = $sw.Elapsed.TotalSeconds
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
    $timings['Konfiguracja bezpieczeństwa'] = [math]::Round($sw.Elapsed.TotalSeconds - $t0, 1)
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
        # Wolumeny zamontowane w folderach (bez litery dysku). Wolumeny CSV klastra raportuje tylko ich właściciel (sekcja Hyper-V)
        Get-CimInstance Win32_Volume -Filter 'DriveType=3' | Where-Object {
            $_.Name -and $_.Capacity -gt 0 -and $_.Name -notmatch '^[A-Za-z]:\\$' -and $_.Name -notlike '\\?\*' -and "$($_.FileSystem)" -ne 'CSVFS'
        } | ForEach-Object {
            [pscustomobject]@{
                Drive = $_.Name.TrimEnd('\'); Label = $_.Label
                SizeGB = [math]::Round($_.Capacity / 1GB, 1); FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
                FreePct = [math]::Round($_.FreeSpace / $_.Capacity * 100, 1)
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
    # Agregacja przez hashtabelę (O(n)) – Group-Object w PowerShell 4/5.1 bardzo zwalnia przy tysiącach połączeń (DC, serwery plików, RDS)
    $connections = @(S 'Connections' 'Połączenia' {
        $agg = @{}
        foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
            $ra = "$($c.RemoteAddress)" -replace '^::ffff:', ''
            if ($ra -match '^(127\.|::1$|0\.0\.0\.0)') { continue }
            $in = $listenPorts.ContainsKey([int]$c.LocalPort)
            $port = if ($in) { [int]$c.LocalPort } else { [int]$c.RemotePort }
            $key = "$in|$ra|$port|$($c.OwningProcess)"
            $e = $agg[$key]
            if ($e) { $e.Count++ } else { $agg[$key] = @{ In = $in; Remote = $ra; Port = $port; P = [int]$c.OwningProcess; Count = 1 } }
        }
        foreach ($e in @($agg.Values | Sort-Object { $_.Count } -Descending | Select-Object -First 400)) {
            [pscustomobject]@{
                Direction = $(if ($e.In) { 'Przychodzące' } else { 'Wychodzące' }); Remote = $e.Remote
                RemotePort = $(if ($e.In) { $null } else { $e.Port }); LocalPort = $(if ($e.In) { $e.Port } else { $null })
                Network = $(if ($e.Remote -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|fe80:|f[cd][0-9a-f]{2}:)') { 'Prywatna' } else { 'Publiczna' })
                Process = (PName $e.P); Service = (PSvc $e.P); Count = $e.Count
            }
        }
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
                    Vendor = $vendor; Microsoft = $(if ($isMs) { 'Tak' } else { 'Nie' }); Unquoted = $(if ($unquoted) { 'Tak' } else { '' }); Path = (Hide-Secret $raw)
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
                NextRun = $next; Author = $t.Author; Action = (Hide-Secret $acts)
            }
        }
    })

    # ── Zdarzenia System / Application ──
    $levels = if ($IncludeWarnings) { 1, 2, 3 } else { 1, 2 }
    $truncated = New-Object System.Collections.Generic.List[string]   # dzienniki, w których osiągnięto limit pobieranych zdarzeń
    $events = @(S 'Events' 'Zdarzenia' {
        $evLogs = @('System', 'Application')
        if ($sys.IsHyperV) { foreach ($l in 'Microsoft-Windows-Hyper-V-VMMS-Admin', 'Microsoft-Windows-Hyper-V-Worker-Admin') { try { if (Get-WinEvent -ListLog $l -ErrorAction Stop) { $evLogs += $l } } catch {} } }
        # osobny limit dla każdego dziennika – zalew błędów w System (np. DCOM 10016) nie ukryje błędów Application i Hyper-V
        $ev = @(foreach ($l in $evLogs) {
            $part = @(Get-WinEvent -FilterHashtable @{ LogName = $l; Level = $levels; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
            if ($part.Count -ge $MaxEvents) { $truncated.Add("$l (od $(D $part[-1].TimeCreated))") }
            $part
        })
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

    # ── Przestoje: okna wyłączenie → start z dziennika System (dane zdarzeń są niezależne od języka systemu) ──
    #   Kernel-General 12/13 – start / zamknięcie systemu (czas w EventData), EventLog 6005/6006 – start / zatrzymanie dziennika,
    #   EventLog 6008 – poprzednie zamknięcie było nieoczekiwane (czas w danych binarnych: SYSTEMTIME lokalny, potem UTC),
    #   Kernel-Power 41 – restart bez poprawnego zamknięcia, User32 1074 – kto i dlaczego zainicjował wyłączenie lub restart
    $downtime = @(S 'Downtime' 'Przestoje' {
        # Dane zdarzenia przez ChildNodes: pola bez atrybutu Name (np. 6008) adapter XML PowerShella zwraca jako zwykłe napisy
        $xd = {
            param($e)
            $h = @{ _bin = '' }
            try {
                $ed = ([xml]$e.ToXml()).Event.EventData
                if ($ed -is [System.Xml.XmlElement]) {
                    $i = 0
                    foreach ($dn in @($ed.ChildNodes)) {
                        if ($dn.LocalName -eq 'Data') { $n = $dn.GetAttribute('Name'); if (-not $n) { $n = "_$i" }; $h[$n] = $dn.InnerText; $i++ }
                        elseif ($dn.LocalName -eq 'Binary') { $h['_bin'] = $dn.InnerText }
                    }
                }
            } catch {}
            $h
        }
        # czas w EventData ma do 9 cyfr ułamka sekundy – .NET przyjmuje najwyżej 7
        $parseTime = { param($t) if ("$t") { try { ([datetime]::Parse(("$t" -replace '(\.\d{7})\d+', '$1'), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime() } catch { $null } } else { $null } }
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 12, 13, 41, 1074, 6005, 6006, 6008; StartTime = $since.AddDays(-2) } -MaxEvents 3000 -ErrorAction SilentlyContinue | Sort-Object TimeCreated)
        $boots = New-Object System.Collections.Generic.List[object]
        $stops = New-Object System.Collections.Generic.List[object]
        $crash = New-Object System.Collections.Generic.List[object]
        $init  = New-Object System.Collections.Generic.List[object]
        foreach ($e in $ev) {
            $p = "$($e.ProviderName)"
            if ($e.Id -eq 12 -and $p -eq 'Microsoft-Windows-Kernel-General') {
                $d = & $xd $e; $t = & $parseTime $d['StartTime']; if (-not $t) { $t = $e.TimeCreated }
                $boots.Add(@{ T = $t; Src = 'KG' })
            } elseif ($e.Id -eq 6005 -and $p -eq 'EventLog') {
                $boots.Add(@{ T = $e.TimeCreated; Src = 'EL' })
            } elseif ($e.Id -eq 13 -and $p -eq 'Microsoft-Windows-Kernel-General') {
                $d = & $xd $e; $t = & $parseTime $d['StopTime']; if (-not $t) { $t = $e.TimeCreated }
                $stops.Add(@{ T = $t; Kind = 'clean' })
            } elseif ($e.Id -eq 6006 -and $p -eq 'EventLog') {
                $stops.Add(@{ T = $e.TimeCreated; Kind = 'clean' })
            } elseif ($e.Id -eq 6008 -and $p -eq 'EventLog') {
                $d = & $xd $e; $t = $null; $b = "$($d['_bin'])" -replace '\s', ''
                if ($b.Length -ge 64) {
                    try {
                        $by = New-Object byte[] 32
                        for ($i = 0; $i -lt 32; $i++) { $by[$i] = [Convert]::ToByte($b.Substring($i * 2, 2), 16) }
                        $t = (New-Object DateTime -ArgumentList ([BitConverter]::ToUInt16($by, 16)), ([BitConverter]::ToUInt16($by, 18)), ([BitConverter]::ToUInt16($by, 22)),
                              ([BitConverter]::ToUInt16($by, 24)), ([BitConverter]::ToUInt16($by, 26)), ([BitConverter]::ToUInt16($by, 28)), ([DateTimeKind]::Utc)).ToLocalTime()
                    } catch { $t = $null }
                }
                if (-not $t) { try { $t = [datetime]::Parse((("$($d['_1']) $($d['_0'])") -replace '[‎‏]', '').Trim()) } catch { $t = $null } }
                if ($t -and ($t -gt $e.TimeCreated -or $t -lt $e.TimeCreated.AddDays(-400))) { $t = $null }
                $crash.Add(@{ T = $e.TimeCreated; Prev = $t; Kind = '6008'; Code = '' })
                if ($t) { $stops.Add(@{ T = $t; Kind = 'unexpected' }) }
            } elseif ($e.Id -eq 41 -and $p -eq 'Microsoft-Windows-Kernel-Power') {
                $d = & $xd $e
                $crash.Add(@{ T = $e.TimeCreated; Prev = $null; Kind = '41'; Code = "$($d['BugcheckCode'])" })
            } elseif ($e.Id -eq 1074 -and $p -match 'User32') {
                $d = & $xd $e
                $proc = "$($d['param1'])" -replace '\s*\(.*\)\s*$', ''
                $init.Add(@{ T = $e.TimeCreated; Who = (("$($proc.Split('\')[-1]) – $($d['param7'])").Trim(' –')); Why = ((@("$($d['param5'])", "$($d['param3'])", "$($d['param6'])") | Where-Object { $_.Trim() }) -join '; ') })
            }
        }
        # Starty: Kernel-General 12, a gdy go brak (starsze systemy) – 6005 (nie dubluj tego samego startu)
        $kg = @($boots | Where-Object { $_.Src -eq 'KG' })
        $bootList = @($kg) + @($boots | Where-Object { $_.Src -eq 'EL' } | Where-Object { $b = $_; -not ($kg | Where-Object { [math]::Abs(($_.T - $b.T).TotalMinutes) -lt 10 }) })
        $bootList = @($bootList | Sort-Object { $_.T })
        $prevBoot = $null
        foreach ($b in $bootList) {
            $lo = if ($prevBoot) { $prevBoot.T } else { [datetime]::MinValue }
            $prevBoot = $b
            if ($b.T -lt $since) { continue }
            $s = @($stops | Where-Object { $_.T -le $b.T -and $_.T -gt $lo } | Sort-Object { $_.T })
            $s = if ($s.Count) { $s[-1] } else { $null }
            $cr = @($crash | Where-Object { $_.T -ge $b.T.AddMinutes(-2) -and $_.T -le $b.T.AddMinutes(20) })
            $code = @($cr | Where-Object { $_.Code -and $_.Code -ne '0' } | ForEach-Object { $_.Code })[0]
            if (-not $s) { $p6008 = @($cr | Where-Object { $_.Prev })[0]; if ($p6008) { $s = @{ T = $p6008.Prev; Kind = 'unexpected' } } }
            $n = 0L
            if ($code -and [int64]::TryParse("$code", [ref]$n)) { $code = '0x{0:X}' -f $n }   # BugcheckCode jest dziesiętny (209 = 0xD1)
            $type = if ($code) { "Awaria systemu (BSOD, kod $code)" } elseif ($cr.Count -or ($s -and $s.Kind -eq 'unexpected')) { 'Nieoczekiwane wyłączenie' }
                    elseif ($s) { 'Planowe' } else { 'Start systemu (brak danych o zamknięciu)' }
            $who = $null
            if ($s) { $who = @($init | Where-Object { $_.T -le $s.T.AddMinutes(2) -and $_.T -ge $s.T.AddMinutes(-60) } | Sort-Object { $_.T })[-1] }
            [pscustomobject]@{
                Down = $(if ($s) { D $s.T } else { '' }); Up = $(D $b.T)
                DowntimeMin = $(if ($s) { [math]::Round(($b.T - $s.T).TotalMinutes, 1) } else { $null })
                Type = $type; Initiator = $(if ($who) { $who.Who } else { '' }); Reason = $(if ($who) { Short $who.Why 200 } else { '' })
            }
        }
    })
    $downtime = @($downtime | Sort-Object Up -Descending)

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
        # rzadkie, ważne zdarzenia osobno – atak na hasła (tysiące 4625/4771) nie może wypchnąć z limitu np. wyczyszczenia dziennika (1102)
        $list += @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4740, 4720, 4726, 4722, 4724, 4728, 4732, 4756, 1102, 4698, 4697; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
        $noisy = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625, 4771; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
        if ($noisy.Count -ge $MaxEvents) { $truncated.Add("Security 4625/4771 (od $(D $noisy[-1].TimeCreated))") }
        $list += $noisy
        $list += @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045, 104; StartTime = $since } -MaxEvents 300 -ErrorAction SilentlyContinue |
                   Where-Object { $_.Id -eq 7045 -or $_.ProviderName -eq 'Microsoft-Windows-Eventlog' })
        $fails = New-Object System.Collections.Generic.List[object]; $rows = New-Object System.Collections.Generic.List[object]
        foreach ($e in $list) {
            $d = EvData $e
            if ($e.Id -eq 4625) {
                $fails.Add([pscustomobject]@{ Id = 4625; Account = "$($d.TargetDomainName)\$($d.TargetUserName)"; Source = ("$($d.IpAddress) $($d.WorkstationName)").Trim(' -'); T = $e.TimeCreated; Detail = "typ logowania $($d.LogonType), status $($d.SubStatus)" })
                continue
            }
            if ($e.Id -eq 4771) {
                $fails.Add([pscustomobject]@{ Id = 4771; Account = "$($d.TargetUserName)"; Source = ("$($d.IpAddress)" -replace '^::ffff:', ''); T = $e.TimeCreated; Detail = "status $($d.Status)" })
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
            $rows.Add([pscustomobject]@{ Time = $(D $e.TimeCreated); Id = $e.Id; Event = $secNames[$e.Id]; Account = $acc; By = $by; Source = $src; Count = 1; Detail = $det })
        }
        $grp = @($fails | Group-Object Id, Account, Source | ForEach-Object {
            $g = @($_.Group | Sort-Object T -Descending)
            [pscustomobject]@{ Time = $(D $g[0].T); Id = $g[0].Id; Event = $secNames[$g[0].Id]; Account = $g[0].Account; By = ''; Source = $g[0].Source; Count = $g.Count; Detail = "$($g[0].Detail); pierwsze: $(D $g[-1].T)" }
        })
        foreach ($x in $grp) { $rows.Add($x) }
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
    $software = @($software | Sort-Object Name, Version, Arch -Unique)   # bez Arch wersje x86 i x64 zlewały się w jeden wiersz

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
            } catch { $failedKeys.Add('Admins'); $errs.Add("Grupy ($sid): $($_.Exception.Message)") }
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
                if ($skip -notcontains $prop.Name) { [pscustomobject]@{ Location = ($k -replace '^HKLM:\\', 'HKLM\'); Name = $prop.Name; Command = (Hide-Secret "$($prop.Value)") } }
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
            # Wszerz, do 3 poziomów, najwyżej 20 000 plików: zaniedbany C:\Windows\Temp potrafi mieć setki tysięcy plików
            # (pełne wyliczenie przekraczało limit pamięci sesji WinRM i cały serwer wyglądał na niedostępny)
            $cap = 20000; $count = 0; $total = [int64]0; $execCount = 0; $capped = $false
            $top = New-Object System.Collections.Generic.List[object]
            $queue = New-Object System.Collections.Generic.Queue[object]
            $queue.Enqueue(@((New-Object IO.DirectoryInfo $p), 0))
            while ($queue.Count -and -not $capped) {
                $di, $lvl = $queue.Dequeue()
                $fi = @(); try { $fi = @($di.GetFiles()) } catch { }
                foreach ($x in $fi) {
                    $count++; $total += $x.Length
                    if ($execExt -contains $x.Extension.ToLower()) { $execCount++ }
                    $top.Add($x)
                    if ($top.Count -ge 400) { $keep = @($top | Sort-Object LastWriteTime -Descending | Select-Object -First 50); $top.Clear(); foreach ($k in $keep) { $top.Add($k) } }
                    if ($count -ge $cap) { $capped = $true; break }
                }
                if ($lvl -lt 3) { $sub = @(); try { $sub = @($di.GetDirectories()) } catch { }; foreach ($sd in $sub) { $queue.Enqueue(@($sd, ($lvl + 1))) } }
            }
            [pscustomobject]@{ Folder = $p; File = "[podsumowanie] plików: $count$(if ($capped) { '+ (przerwano liczenie)' }), wykonywalnych/skryptów: $execCount"; SizeKB = [math]::Round($total / 1KB); Modified = ''; Executable = $(if ($execCount) { "$execCount" } else { '' }) }
            $root = $p.TrimEnd('\').Length
            $top | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | ForEach-Object {
                [pscustomobject]@{
                    Folder = $p; File = $_.FullName.Substring($root).TrimStart('\'); SizeKB = [math]::Round($_.Length / 1KB, 1)
                    Modified = $(D $_.LastWriteTime); Executable = $(if ($execExt -contains $_.Extension.ToLower()) { 'Tak' } else { '' })
                }
            }
        }
    })

    # ── Hyper-V ──
    # Get-VM, dyski i informacje VHD zbierane RAZ (Get-VHD otwiera plik dysku – przy kilkudziesięciu maszynach to najwolniejsza część skanu hosta)
    $hyperv = @(); $checkpoints = @(); $vmStorage = @(); $clusterRows = @()
    if ($sys.IsHyperV -and ((Want 'HyperV') -or (Want 'Checkpoints') -or (Want 'VMStorage'))) {
        $t0 = $sw.Elapsed.TotalSeconds
        $vms = @(); $hdAll = @(); $snaps = @(); $vhdCache = @{}; $kvp = @{}; $nics = @{}; $since2 = @{}
        $sys.HvVmms = "$((Get-Service vmms -ErrorAction SilentlyContinue).Status)"
        if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { $errs.Add('Hyper-V: brak modułu PowerShell Hyper-V na hoście (Install-WindowsFeature Hyper-V-PowerShell)') }
        else { try { $vms = @(Get-VM -ErrorAction Stop) } catch { $errs.Add("Hyper-V: $($_.Exception.Message)") } }
        if ($vms.Count) {
            try { $hdAll = @(Get-VMHardDiskDrive -VM $vms -ErrorAction Stop) } catch { $errs.Add("Hyper-V (dyski): $($_.Exception.Message)") }
            try { $snaps = @(Get-VMSnapshot -VM $vms -ErrorAction Stop) } catch {}
            try { foreach ($n in @(Get-VMNetworkAdapter -VM $vms -ErrorAction Stop)) { $k = "$($n.VMId)".ToUpper(); if (-not $nics.ContainsKey($k)) { $nics[$k] = @() }; $nics[$k] += $n } } catch {}
            # Od kiedy maszyna jest w obecnym stanie (np. wyłączona od 40 dni = prawdopodobnie wycofana)
            try { foreach ($cs2 in @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -ErrorAction Stop)) { if ($cs2.TimeOfLastStateChange) { $since2["$($cs2.Name)".ToUpper()] = $cs2.TimeOfLastStateChange } } } catch {}
            # Wymiana KVP (usługi integracji): system gościa, FQDN i adresy IP – jedna kwerenda dla wszystkich maszyn
            try {
                foreach ($kc in @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_KvpExchangeComponent -ErrorAction Stop)) {
                    $h = @{}
                    foreach ($item in @($kc.GuestIntrinsicExchangeItems)) {
                        try {
                            $x = [xml]$item
                            $nm = @($x.INSTANCE.PROPERTY | Where-Object { $_.NAME -eq 'Name' })[0].VALUE
                            $dt = @($x.INSTANCE.PROPERTY | Where-Object { $_.NAME -eq 'Data' })[0].VALUE
                            if ($nm) { $h["$nm"] = "$dt" }
                        } catch {}
                    }
                    $kvp["$($kc.SystemName)".ToUpper()] = $h
                }
            } catch {}
        }
        # Dyski na udziałach SMB pomijamy (Get-VHD przez WinRM nie ma dostępu do udziału – podwójny przeskok), dyski fizyczne (pass-through) też
        function VhdInfo([string]$p) {
            if (-not $p -or $p.StartsWith('\\')) { return $null }
            if (-not $vhdCache.ContainsKey($p)) { $v = $null; try { $v = Get-VHD -Path $p -ErrorAction Stop } catch {}; $vhdCache[$p] = $v }
            $vhdCache[$p]
        }
        # Łańcuch dysków różnicowych (checkpointy): suma rozmiarów plików i głębokość łańcucha
        function VhdChain([string]$p) {
            $size = [double]0; $depth = 0; $known = $false
            while ($p -and $depth -lt 64) { $v = VhdInfo $p; if (-not $v) { break }; $size += [double]$v.FileSize; $known = $true; $depth++; $p = "$($v.ParentPath)" }
            @{ Size = $size; Depth = $depth; Known = $known }
        }
        $hdByVm = @{}; foreach ($hd in $hdAll) { $k = "$($hd.VMId)".ToUpper(); if (-not $hdByVm.ContainsKey($k)) { $hdByVm[$k] = @() }; $hdByVm[$k] += $hd }
        $snByVm = @{}; foreach ($sn in $snaps) { $k = "$($sn.VMId)".ToUpper(); $snByVm[$k] = 1 + [int]$snByVm[$k] }

        # Pojemność hosta (wartości liczbowe w System – progi ocenia stacja). Obciążenie CPU hosta liczy hiperwizor
        # (Win32_Processor w partycji nadrzędnej widzi tylko system hosta, nie maszyny); pierwszy odczyt licznika bywa zerowy.
        try {
            $hq = "SELECT PercentTotalRunTime FROM Win32_PerfFormattedData_HvStats_HyperVHypervisorLogicalProcessor WHERE Name='_Total'"
            [void](Get-CimInstance -Query $hq -ErrorAction Stop); Start-Sleep -Milliseconds 1000
            $sys.HvCpuLoad = [int](@(Get-CimInstance -Query $hq -ErrorAction Stop)[0].PercentTotalRunTime)
        } catch {}
        try {
            $vh = Get-VMHost -ErrorAction Stop
            $sys.HvLogicalCpus  = [int]$vh.LogicalProcessorCount
            $sys.HvNumaSpanning = [bool]$vh.NumaSpanningEnabled
            $sys.HvVhdPath      = "$($vh.VirtualHardDiskPath)"
        } catch {}
        # repliki (Hyper-V Replica) są z założenia wyłączone – nie liczą się do pojemności
        $prim = @($vms | Where-Object { "$($_.ReplicationMode)" -notmatch 'Replica' })
        $run = @($prim | Where-Object { "$($_.State)" -like 'Running*' })
        $sys.HvVmTotal       = $prim.Count
        $sys.HvVmRunning     = $run.Count
        $sys.HvVmReplicas    = $vms.Count - $prim.Count
        $sys.HvVcpuRunning   = [int](@($run | ForEach-Object { [int]$_.ProcessorCount }) | Measure-Object -Sum).Sum
        $sys.HvVcpuTotal     = [int](@($prim | ForEach-Object { [int]$_.ProcessorCount }) | Measure-Object -Sum).Sum
        $sys.HvRamAssignedGB = [math]::Round([double](@($run | ForEach-Object { [double]$_.MemoryAssigned }) | Measure-Object -Sum).Sum / 1GB, 1)
        # RAM startowy maszyn, które działają albo same startują z hostem – czy wszystkie wstaną po restarcie hosta
        $sys.HvRamStartupGB  = [math]::Round([double](@($prim | Where-Object { "$($_.State)" -like 'Running*' -or "$($_.AutomaticStartAction)" -ne 'Nothing' } | ForEach-Object { [double]$_.MemoryStartup }) | Measure-Object -Sum).Sum / 1GB, 1)

        # Klaster pracy awaryjnej: nazwa, węzły; wolumeny CSV raportuje tylko węzeł-właściciel (bez powtórzeń z każdego węzła)
        $sys.HvCluster = ''; $sys.HvClusterNodes = ''; $sys.HvClusterNodeCount = 0
        try { $sys.HvCluster = "$((Get-ItemProperty 'HKLM:\Cluster' -ErrorAction Stop).ClusterName)" } catch {}
        if ((Get-Command Get-ClusterNode -ErrorAction SilentlyContinue) -and "$((Get-Service ClusSvc -ErrorAction SilentlyContinue).Status)" -eq 'Running') {
            try {
                $sys.HvCluster = "$((Get-Cluster -ErrorAction Stop).Name)"
                $cnodes = @(Get-ClusterNode -ErrorAction Stop)
                $sys.HvClusterNodes = (@($cnodes | ForEach-Object { "$($_.Name) ($($_.State))" }) -join ', ')
                $sys.HvClusterNodeCount = $cnodes.Count
                # Sekcja Klaster: ten sam obraz z każdego węzła – stacja ocenia ją raz na klaster (węzeł reprezentujący)
                if (Want 'Cluster') {
                    $t0c = $sw.Elapsed.TotalSeconds
                    try {
                        foreach ($n in $cnodes) { $clusterRows += [pscustomobject]@{ Type = 'Węzeł'; Name = "$($n.Name)"; State = "$($n.State)"; Owner = ''; Detail = $(if ($n.PSObject.Properties['DrainStatus']) { "opróżnianie: $($n.DrainStatus)" } else { '' }) } }
                        foreach ($csv in @(Get-ClusterSharedVolume -ErrorAction Stop)) {
                            $vi = @($csv.SharedVolumeInfo)[0]; $pt = if ($vi) { $vi.Partition } else { $null }
                            $clusterRows += [pscustomobject]@{ Type = 'CSV'; Name = "$($csv.Name) $(if ($vi) { $vi.FriendlyVolumeName })".Trim(); State = "$($csv.State)"; Owner = "$($csv.OwnerNode.Name)"
                                Detail = $(if ($pt -and $pt.Size) { "wolne $([math]::Round($pt.FreeSpace / 1GB, 1)) z $([math]::Round($pt.Size / 1GB, 1)) GB ($([math]::Round($pt.FreeSpace / $pt.Size * 100, 1))%)$(if ($vi.MaintenanceMode) { ', tryb konserwacji' })" } else { '' }) }
                        }
                        foreach ($g in @(Get-ClusterGroup -ErrorAction Stop | Where-Object { "$($_.GroupType)" -eq 'VirtualMachine' -and "$($_.State)" -ne 'Online' })) {
                            $clusterRows += [pscustomobject]@{ Type = 'Rola VM'; Name = "$($g.Name)"; State = "$($g.State)"; Owner = "$($g.OwnerNode.Name)"; Detail = '' }
                        }
                        try { $q = Get-ClusterQuorum -ErrorAction Stop; if ($q.QuorumResource) { $clusterRows += [pscustomobject]@{ Type = 'Kworum'; Name = "$($q.QuorumResource.Name)"; State = "$($q.QuorumResource.State)"; Owner = "$($q.QuorumResource.OwnerNode.Name)"; Detail = "$($q.QuorumType)" } } } catch {}
                    } catch { $failedKeys.Add('Cluster'); $errs.Add("Klaster (sekcja): $($_.Exception.Message)") }
                    $timings['Klaster'] = [math]::Round($sw.Elapsed.TotalSeconds - $t0c, 1)
                }
                if (Want 'Disks') {
                    foreach ($csv in @(Get-ClusterSharedVolume -ErrorAction Stop)) {
                        if ("$($csv.OwnerNode.Name)" -ne $env:COMPUTERNAME) { continue }
                        foreach ($vi in @($csv.SharedVolumeInfo)) {
                            $pt = $vi.Partition
                            if (-not $pt -or -not $pt.Size) { continue }
                            $disks += [pscustomobject]@{
                                Drive = "$($vi.FriendlyVolumeName)"; Label = "CSV: $($csv.Name) ($($csv.State))"
                                SizeGB = [math]::Round($pt.Size / 1GB, 1); FreeGB = [math]::Round($pt.FreeSpace / 1GB, 1)
                                FreePct = [math]::Round($pt.FreeSpace / $pt.Size * 100, 1)
                            }
                        }
                    }
                }
            } catch { $errs.Add("Klaster: $($_.Exception.Message)") }
        }

        $hyperv = @(S 'HyperV' 'Hyper-V' {
            foreach ($vm in $vms) {
                $id   = "$($vm.VMId)".ToUpper()
                $g    = $kvp[$id]; if (-not $g) { $g = @{} }
                $os   = "$($g['OSName'])".Trim()
                $size = 0; $known = $false; $depth = 0
                foreach ($hd in @($hdByVm[$id])) { if ($hd -and $hd.Path -and $null -eq $hd.DiskNumber) { $ch = VhdChain $hd.Path; if ($ch.Known) { $size += $ch.Size; $known = $true; $depth = [Math]::Max($depth, $ch.Depth) } } }
                $na   = @($nics[$id] | Where-Object { $_ })
                $ips  = @($na | ForEach-Object { @($_.IPAddresses) } | Where-Object { $_ -and $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notmatch '^169\.254\.' })
                if (-not $ips.Count -and $g['NetworkAddressIPv4']) { $ips = @("$($g['NetworkAddressIPv4'])" -split ';' | Where-Object { $_ }) }
                [pscustomobject]@{
                    Name = $vm.Name; State = "$($vm.State)"; Status = "$($vm.Status)"; Heartbeat = "$($vm.Heartbeat)"; UptimeDays = [math]::Round($vm.Uptime.TotalDays, 1)
                    StateSince = $(if ($since2.ContainsKey($id)) { D $since2[$id] } else { '' })
                    CPU = $vm.ProcessorCount; CpuUsage = $vm.CPUUsage; MemGB = [math]::Round($vm.MemoryAssigned / 1GB, 1); MemStartupGB = [math]::Round($vm.MemoryStartup / 1GB, 1)
                    MemMaxGB = $(if ($vm.DynamicMemoryEnabled) { [math]::Round($vm.MemoryMaximum / 1GB, 1) } else { $null }); MemDemandGB = [math]::Round($vm.MemoryDemand / 1GB, 1)
                    DynamicMem = $(if ($vm.DynamicMemoryEnabled) { 'Tak' } else { 'Nie' }); Gen = $vm.Generation; Version = "$($vm.Version)"
                    Replication = "$($vm.ReplicationHealth)"; ReplicationMode = "$($vm.ReplicationMode)"
                    Checkpoints = [int]$snByVm[$id]; CheckpointType = $(if ($vm.PSObject.Properties['CheckpointType']) { "$($vm.CheckpointType)" } else { '' })
                    AutoStart = "$($vm.AutomaticStartAction)"; AutoStop = "$($vm.AutomaticStopAction)"; IntegrationServices = "$($vm.IntegrationServicesState)"
                    IntegrationVersion = $(if ($g['IntegrationServicesVersion']) { "$($g['IntegrationServicesVersion'])" } else { "$($vm.IntegrationServicesVersion)" })
                    GuestOS = ("$os $($g['OSVersion'])").Trim(); GuestFQDN = "$($g['FullyQualifiedDomainName'])"; GuestIP = ($ips -join ', ')
                    Linux = $(if ($os -and $os -notmatch 'Windows') { 'Tak' } else { '' })
                    Clustered = $(if ($vm.PSObject.Properties['IsClustered'] -and $vm.IsClustered) { 'Tak' } else { '' })
                    Switch = (@($na | ForEach-Object { if ($_.SwitchName) { "$($_.SwitchName)" } else { '(odłączona)' } } | Sort-Object -Unique) -join ', ')
                    DisksGB = $(if ($known) { [math]::Round($size / 1GB, 1) } else { $null }); ChainDepth = $depth; Path = $vm.Path; Id = $id
                }
            }
        })
        $checkpoints = @(S 'Checkpoints' 'Checkpointy' {
            foreach ($sn in $snaps) {
                [pscustomobject]@{ VM = $sn.VMName; Name = $sn.Name; Created = $(D $sn.CreationTime); AgeDays = [math]::Round(($now - $sn.CreationTime).TotalDays, 1); Type = "$($sn.SnapshotType)"; Parent = "$($sn.ParentSnapshotName)" }
            }
        })
        $checkpoints = @($checkpoints | Sort-Object AgeDays -Descending)
        # Dyski VM: ile mogą jeszcze urosnąć dyski dynamiczne/różnicowe względem wolnego miejsca na wolumenie (także CSV)
        $vmStorage = @(S 'VMStorage' 'Hyper-V: dyski VM' {
            $vols = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' | Where-Object { $_.Name } | Sort-Object { $_.Name.Length } -Descending)
            foreach ($hd in $hdAll) {
                if (-not $hd.Path -or $null -ne $hd.DiskNumber) { continue }   # dysk fizyczny (pass-through)
                $v    = VhdInfo $hd.Path
                $vol  = $vols | Where-Object { $hd.Path.StartsWith($_.Name, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
                $type = if ($v) { "$($v.VhdType)" } elseif ($hd.Path.StartsWith('\\')) { 'udział SMB' } else { 'nieznany' }
                [pscustomobject]@{
                    VM = $hd.VMName; Disk = $hd.Path; Type = $type
                    CurrentGB = $(if ($v) { [math]::Round($v.FileSize / 1GB, 1) } else { $null })
                    MaxGB     = $(if ($v) { [math]::Round($v.Size / 1GB, 1) } else { $null })
                    GrowthGB  = $(if ($v -and $type -ne 'Fixed') { [math]::Round([math]::Max([double]0, [double]($v.Size - $v.FileSize)) / 1GB, 1) } else { 0 })
                    Volume    = $(if ($vol) { $vol.Name } elseif ($hd.Path -match '^(\\\\[^\\]+\\[^\\]+)') { $Matches[1] } else { '' })
                    VolumeFreeGB = $(if ($vol) { [math]::Round($vol.FreeSpace / 1GB, 1) } else { $null })
                    OnSystemDrive = $(if ($hd.Path.StartsWith("$env:SystemDrive\", [StringComparison]::OrdinalIgnoreCase)) { 'Tak' } else { '' })
                }
            }
        })
        $timings['Hyper-V (razem)'] = [math]::Round($sw.Elapsed.TotalSeconds - $t0, 1)
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
                 Where-Object { ($_.ProviderName -match '^(disk|Ntfs|Microsoft-Windows-Ntfs)$' -or ($_.Id -eq 129 -and $_.ProviderName -ne 'Microsoft-Windows-Time-Service')) -and -not ($_.Id -eq 98 -and $_.Level -ge 4) })
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
                'CommandLineEventConsumer'  { Hide-Secret ("$($c.CommandLineTemplate) $($c.ExecutablePath)".Trim()) }
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
        Downtime       = $downtime
        Cluster        = [object[]]@($clusterRows)
        Timings        = [object[]]@($timings.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { [pscustomobject]@{ Section = $_.Key; Sec = $_.Value } })
        Skipped        = [string[]]@($SkipSections | Where-Object { $_ })
        Failed         = [string[]]@($failedKeys | Select-Object -Unique)
        Truncated      = [string[]]$truncated.ToArray()
        Errors         = $errList
        Days           = $Days
        DurationSec    = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        CollectorVersion = 2   # zmiana formatu wierszy porównywanych sekcji = nowy numer (stacja nie porównuje migawek różnych wersji)
    } | ConvertTo-Json -Depth 4 -Compress
    # Czas serwera PO serializacji – stacja liczy różnicę zegarów bez czasu budowania JSON (przy dużych serwerach to sekundy)
    '@@SRTIME@@' + [DateTime]::UtcNow.ToString('o')
    } catch {
        $ii = $_.InvocationInfo
        [pscustomobject]@{ Fatal = "$($_.Exception.Message) [linia $($ii.ScriptLineNumber): $("$($ii.Line)".Trim())]" } | ConvertTo-Json -Compress
    }
}
#endregion

#region ── Funkcje wykonywane w wątkach tła (skan, diagnostyka, wczytywanie migawek) ─
# Funkcje z tego regionu działają zarówno w wątku okna, jak i w pulach wątków tła – ich treść jest wklejana do
# skryptu wątku ($script:WorkerScript), więc mogą korzystać tylko z siebie nawzajem i z parametrów (bez $script:/$Config/$ui).

function Read-SnapshotText([string]$Path) {
    # Migawki: .json (starsze) albo .json.gz (skompresowane)
    if ($Path.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase)) {
        $fs = [IO.File]::OpenRead($Path)
        try {
            $gz = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Decompress)
            $sr = New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8)
            try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
        } finally { $fs.Dispose() }
    }
    [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
}

function Write-SnapshotText([string]$Path, [string]$Text) {
    # Zapis przez plik tymczasowy: wczytywanie migawek nigdy nie trafi na plik zapisany do połowy
    $bytes = (New-Object Text.UTF8Encoding $false).GetBytes($Text)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))   # folder skanu mógł zniknąć (porządki innej instancji)
    $tmp = "$Path.tmp"
    $fs = [IO.File]::Create($tmp)
    try {
        if ($Path.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase)) {
            $gz = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionLevel]::Optimal)
            try { $gz.Write($bytes, 0, $bytes.Length) } finally { $gz.Dispose() }
        } else { $fs.Write($bytes, 0, $bytes.Length) }
    } finally { $fs.Dispose() }
    if ([IO.File]::Exists($Path)) { [IO.File]::Delete($Path) }
    [IO.File]::Move($tmp, $Path)
}

function ConvertFrom-ServerJson([string]$Json, [string[]]$ArrayKeys) {
    # Sekcje tablicowe zawsze jako tablice (także puste) + kolumna Flag do kolorowania wierszy
    $d = $Json | ConvertFrom-Json
    $present = [string[]]@($d.PSObject.Properties | ForEach-Object { $_.Name })   # sekcje faktycznie obecne w danych (starsze migawki nie mają nowych sekcji)
    foreach ($k in $ArrayKeys) {
        $rows = @()
        if ($d.PSObject.Properties[$k]) { $rows = @($d.$k | Where-Object { $null -ne $_ }) }
        foreach ($r in $rows) {
            # PSNoteProperty zamiast Add-Member – kilkukrotnie szybciej przy tysiącach wierszy
            if ($r -is [System.Management.Automation.PSCustomObject] -and -not $r.PSObject.Properties['Flag']) { $r.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new('Flag', '')) }
        }
        $d | Add-Member -NotePropertyName $k -NotePropertyValue $rows -Force
    }
    $d | Add-Member -NotePropertyName _Present -NotePropertyValue $present -Force
    $d
}

function Get-SnapshotSummary([string]$Path) {
    # Skrót ostatniej udanej migawki (system, adres IP, host Hyper-V) bez parsowania całego pliku – dla serwerów bez połączenia
    $t = Read-SnapshotText $Path
    $sys = $null
    $m = [regex]::Match($t, '"System":(\{[^{}]*\})')
    if ($m.Success) { try { $sys = $m.Groups[1].Value | ConvertFrom-Json } catch {} }
    $ip = [regex]::Match($t, '"IPv4":"(\d[^"/]*)')
    [pscustomobject]@{
        ScannedAt = ([IO.File]::GetLastWriteTime($Path)).ToString('yyyy-MM-dd HH:mm')
        System    = $sys
        IPv4      = $(if ($ip.Success) { $ip.Groups[1].Value } else { '' })
    }
}

function Get-WinRmErrorInfo {
    <#
        Klasyfikacja błędu połączenia WinRM. Najpierw kody (HRESULT / kod błędu WinRM / FullyQualifiedErrorId) – są niezależne
        od języka systemu; dopiero potem słowa kluczowe komunikatu (polskie i angielskie).
    #>
    param([string]$Message, [string]$ErrorId, [string]$Code)
    $m  = "$Message"
    $id = "$ErrorId"
    $codes = New-Object System.Collections.Generic.List[string]
    if ($Code) { $codes.Add($Code.ToUpperInvariant().Replace('0X', '0x')) }
    foreach ($x in [regex]::Matches($m, '0x[0-9A-Fa-f]{8}')) { $codes.Add($x.Value.ToUpperInvariant().Replace('0X', '0x')) }
    $has = { param([string[]]$List) foreach ($c in $List) { if ($codes.Contains($c)) { return $true } }; $false }
    $r = @{ Class = 'Unknown'; Code = $(if ($codes.Count) { $codes[0] } else { '' }); Cause = 'Połączenie WinRM nie powiodło się'; Remedy = 'Sprawdź komunikat błędu i stan WinRM na serwerze: Test-WSMan <serwer>, Get-Service WinRM.' }
    if ($id -match '^SrTimeout') {
        $r.Class = 'Timeout'; $r.Cause = 'Przekroczono limit czasu skanu jednego serwera – serwer odpowiadał, ale zbieranie danych trwało za długo'
        $r.Remedy = 'Zwiększ „Limit czasu jednego serwera” w ustawieniach albo odznacz najwolniejsze sekcje (Czas zbierania sekcji w szczegółach serwera).'
    }
    elseif ($id -match '^CollectorFatal') {
        $r.Class = 'Remote'; $r.Cause = 'Kolektor przerwał pracę na serwerze'; $r.Remedy = 'Szczegóły błędu poniżej. Pozostałe serwery nie są tym dotknięte; zgłoś błąd z treścią komunikatu.'
    }
    elseif ($id -match '^LogonFailure' -or (& $has '0x8009030C', '0x8007052E', '0x0000052E') -or $m -match 'user name or password is incorrect|nazwa użytkownika lub hasło') {
        $r.Class = 'Auth'; $r.Cause = 'Błędne poświadczenia (login lub hasło)'; $r.Remedy = 'Sprawdź konto wybrane przyciskiem „Konto” (blokada konta, wygasłe hasło).'
    }
    elseif ($id -match '^AccessDenied' -or (& $has '0x80070005', '0x00000005') -or $m -match 'Access is denied|Odmowa dostępu') {
        $r.Class = 'Auth'; $r.Cause = 'Odmowa dostępu – konto nie ma uprawnień do zdalnego PowerShell na serwerze'
        $r.Remedy = 'Konto musi należeć do lokalnych Administratorów serwera (lub Remote Management Users). Dla kont lokalnych potrzebne jest LocalAccountTokenFilterPolicy = 1.'
    }
    elseif (& $has '0x80090322') {
        $r.Class = 'Kerberos'; $r.Cause = 'Błąd Kerberos: niewłaściwa nazwa usługi (SPN) – zduplikowany SPN HTTP/<serwer>, alias DNS (CNAME) albo nieaktualny wpis DNS wskazujący inny komputer'
        $r.Remedy = 'setspn -Q HTTP/<serwer> (duplikaty usuń), łącz się po nazwie z rekordu A, sprawdź rekord PTR (wiersz „DNS odwrotny”).'
    }
    elseif (& $has '0x80090311') {
        $r.Class = 'Kerberos'; $r.Cause = 'Kerberos: brak dostępnego kontrolera domeny albo relacji zaufania z domeną serwera'
        $r.Remedy = 'Sprawdź łączność stacji z kontrolerem domeny i zaufanie między domenami; dla serwera spoza domeny użyj TrustedHosts i jawnego konta.'
    }
    elseif (& $has '0x80090324') {
        $r.Class = 'Kerberos'; $r.Cause = 'Kerberos: różnica czasu między stacją a serwerem przekracza tolerancję (domyślnie 5 minut)'
        $r.Remedy = 'Sprawdź synchronizację czasu (w32tm /query /status) na serwerze i na stacji.'
    }
    elseif (& $has '0x8009030E', '0x80090303') {
        $r.Class = 'Kerberos'; $r.Cause = 'Kerberos: brak biletu dla serwera (nieznany serwer docelowy, inna domena bez zaufania albo konto lokalne stacji)'
        $r.Remedy = 'Uruchom program na koncie domenowym albo podaj konto przyciskiem „Konto”; dla serwera spoza domeny – TrustedHosts.'
    }
    # po kodach Kerberos/logowania: angielski komunikat błędu Kerberos też wspomina TrustedHosts
    elseif ($id -match 'CannotUseIPAddress' -or $m -match 'TrustedHosts') {
        $r.Class = 'TrustedHosts'; $r.Cause = 'Połączenie po adresie IP wymaga wpisu w TrustedHosts i jawnego konta (Kerberos nie działa z adresem IP)'
        $r.Remedy = 'Dodaj serwer po nazwie DNS albo: Set-Item WSMan:\localhost\Client\TrustedHosts -Value <IP> -Concatenate i wybierz konto przyciskiem „Konto”.'
    }
    elseif ($id -match '^ComputerNotFound' -or $m -match 'cannot be resolved|could not be resolved|nie można rozpoznać|nie można rozwiązać|No such host is known|Ten host nie jest znany') {
        $r.Class = 'Dns'; $r.Cause = 'Nazwa serwera nie jest rozwiązywana w DNS'; $r.Remedy = 'Sprawdź pisownię i rekord A w DNS. Jeśli serwer wycofano – usuń go z listy.'
    }
    elseif ($m -match 'concurrent shells|maximum number of .*shells|MaxShellsPerUser|MaxConcurrentUsers|jednoczesnych powłok|maksymalną liczbę') {
        $r.Class = 'Limit'; $r.Cause = 'Przekroczony limit jednoczesnych powłok WinRM dla konta (MaxShellsPerUser / MaxConcurrentUsers)'
        $r.Remedy = 'Zamknij zalegające sesje albo zwiększ limit: winrm set winrm/config/winrs @{MaxShellsPerUser="30"}.'
    }
    elseif ($m -match 'did not return a proper response|MaxMemoryPerShellMB|OutOfMemory|out of memory|za mało pamięci|brak pamięci') {
        $r.Class = 'Remote'; $r.Cause = 'Proces WinRM na serwerze przerwał pracę (najczęściej limit pamięci powłoki MaxMemoryPerShellMB)'
        $r.Remedy = 'Zwiększ limit: winrm set winrm/config/winrs @{MaxMemoryPerShellMB="2048"} albo odznacz duże sekcje (Oprogramowanie, Połączenia, Zdarzenia).'
    }
    elseif ($m -match 'MaxEnvelopeSize|exceeded allowed maximum|przekroczył.*maksymaln') {
        $r.Class = 'Remote'; $r.Cause = 'Przekroczony limit rozmiaru danych WinRM'; $r.Remedy = 'Odznacz największe sekcje albo zwiększ MaxEnvelopeSizekb na serwerze.'
    }
    elseif ($m -match 'HTTP status code (of )?(\d{3})|kod stanu HTTP (\d{3})') {
        $n = if ($Matches[2]) { $Matches[2] } else { $Matches[3] }
        $r.Class = 'WinRM'; $r.Cause = "Usługa WinRM odpowiedziała kodem HTTP $n"
        $r.Remedy = $(if ($n -eq '403') { 'Żądanie odrzucone – sprawdź uprawnienia WinRM (RootSDDL) i czy po drodze nie ma serwera proxy.' } else { 'Usługa WinRM na serwerze jest przeciążona lub w błędzie – zrestartuj usługę WinRM (Restart-Service WinRM).' })
    }
    elseif ($id -match '^(CannotConnect|WinRMOperationTimeout)' -or (& $has '0x80338012', '0x80338126', '0x80338029', '0x803381B9') -or
            $m -match 'cannot connect to the destination|firewall exception|computer is accessible over the network|nie może połączyć|zapor') {
        $r.Class = 'Network'; $r.Cause = 'Brak połączenia z usługą WinRM'
        $r.Remedy = 'Sprawdź, czy serwer działa, czy port 5985 jest otwarty i czy usługa WinRM działa (wyniki prób poniżej).'
    }
    [pscustomobject]$r
}

function Get-AdComputerInfo([string]$Name) {
    # Konto komputera w AD (bieżąca domena stacji): istnieje? włączone? kiedy ostatnio logowało się do domeny?
    $r = [ordered]@{ Found = $false; Enabled = $null; LastLogonDays = $null; PwdAgeDays = $null; OS = ''; DN = ''; Error = '' }
    if ($Name -match '^\d{1,3}(\.\d{1,3}){3}$' -or $Name.Contains(':')) { $r.Error = 'adres IP'; return [pscustomobject]$r }
    try {
        $esc = { param($v) ($v -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29') }
        $short = $Name.Split('.')[0]
        $ds = New-Object System.DirectoryServices.DirectorySearcher
        $ds.Filter = "(&(objectCategory=computer)(|(sAMAccountName=$(& $esc $short)`$)(dNSHostName=$(& $esc $Name))))"
        $ds.ClientTimeout = [TimeSpan]::FromSeconds(8)
        $ds.ServerTimeLimit = [TimeSpan]::FromSeconds(8)
        [void]$ds.PropertiesToLoad.AddRange([string[]]@('useraccountcontrol', 'lastlogontimestamp', 'pwdlastset', 'operatingsystem', 'distinguishedname'))
        $hit = $ds.FindOne()
        if ($hit) {
            $p = $hit.Properties
            $r.Found = $true
            $r.Enabled = -not ([int64]$p['useraccountcontrol'][0] -band 2)
            if ($p['lastlogontimestamp'].Count) { $r.LastLogonDays = [int]((Get-Date) - [datetime]::FromFileTime([int64]$p['lastlogontimestamp'][0])).TotalDays }
            # hasło konta komputera zmienia się samo co 30 dni – starsze znaczy: maszyna długo wyłączona albo zerwany kanał zabezpieczeń
            if ($p['pwdlastset'].Count -and [int64]$p['pwdlastset'][0] -gt 0) { $r.PwdAgeDays = [int]((Get-Date) - [datetime]::FromFileTime([int64]$p['pwdlastset'][0])).TotalDays }
            if ($p['operatingsystem'].Count) { $r.OS = "$($p['operatingsystem'][0])" }
            $r.DN = "$($p['distinguishedname'][0])"
        }
    } catch { $r.Error = $_.Exception.Message }
    [pscustomobject]$r
}

function Get-HttpSpnOwners([string]$Name) {
    # Kerberos 0x80090322: najczęściej SPN HTTP/<serwer> zarejestrowany na innym koncie (pula aplikacji IIS, konto usługi SSRS) –
    # kontroler domeny szyfruje bilet kluczem tamtego konta i WinRM go odrzuca. Szukamy w katalogu globalnym (cały las).
    $short = $Name.Split('.')[0]
    $esc = { param($v) ($v -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29') }
    $spns = @("HTTP/$Name", "HTTP/$short", "HTTP/$($Name):5985", "HTTP/$($short):5985") | Select-Object -Unique
    $root = $null
    try { $root = New-Object System.DirectoryServices.DirectoryEntry ('GC://' + [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name) } catch { }
    $ds = if ($root) { New-Object System.DirectoryServices.DirectorySearcher($root) } else { New-Object System.DirectoryServices.DirectorySearcher }
    $ds.Filter = '(|' + (($spns | ForEach-Object { "(servicePrincipalName=$(& $esc $_))" }) -join '') + ')'
    $ds.ClientTimeout = [TimeSpan]::FromSeconds(8)
    $ds.ServerTimeLimit = [TimeSpan]::FromSeconds(8)
    [void]$ds.PropertiesToLoad.AddRange([string[]]@('samaccountname', 'serviceprincipalname'))
    $out = New-Object System.Collections.Generic.List[object]
    $res = $ds.FindAll()
    try {
        foreach ($h in $res) {
            $sam = "$($h.Properties['samaccountname'][0])"
            if ($sam -eq "$short`$") { continue }   # konto samego komputera – tak ma być
            $own = @($h.Properties['serviceprincipalname'] | Where-Object { $spns -contains "$_" })
            $out.Add([pscustomobject]@{ Account = $sam; Spn = ($own -join ', ') })
        }
    } finally { $res.Dispose() }
    [object[]]$out.ToArray()
}

function Test-WinRmPort([string]$Target, [int]$TimeoutMs, [int]$Port = 5985) {
    # Szybki test portu WinRM przed skanem: open | refused | timeout | unknown (unknown = nie wiadomo, skanujemy normalnie)
    $addrs = @()
    $ipa = $null
    if ([Net.IPAddress]::TryParse($Target, [ref]$ipa)) { $addrs = @($ipa) }
    else {
        try {
            $ar = [Net.Dns]::BeginGetHostAddresses($Target, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne(3000)) { return 'unknown' }
            $addrs = @([Net.Dns]::EndGetHostAddresses($ar) | Where-Object { -not $_.IsIPv6LinkLocal })
        } catch { return 'unknown' }
    }
    if (-not $addrs.Count) { return 'unknown' }
    $tries = @(foreach ($a in @($addrs | Select-Object -First 4)) {
        $cl = New-Object Net.Sockets.TcpClient($a.AddressFamily)
        $t = $null
        try { $t = $cl.ConnectAsync($a, $Port) } catch { }
        @{ Client = $cl; Task = $t }
    })
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    try {
        while ($true) {
            $pending = 0
            foreach ($x in $tries) {
                if (-not $x.Task) { continue }
                if (-not $x.Task.IsCompleted) { $pending++ }
                elseif ("$($x.Task.Status)" -eq 'RanToCompletion' -and $x.Client.Connected) { return 'open' }   # wystarczy jeden adres
            }
            if (-not $pending -or [DateTime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Milliseconds 50
        }
        $refused = $false; $tested = $false
        foreach ($x in $tries) {
            if (-not $x.Task) { continue }
            $tested = $true
            if ($x.Task.IsFaulted) {
                $se = $x.Task.Exception.InnerException
                if ($se -is [Net.Sockets.SocketException] -and "$($se.SocketErrorCode)" -eq 'ConnectionRefused') { $refused = $true }
            }
        }
        if (-not $tested) { return 'unknown' }
        if ($refused) { return 'refused' }
        return 'timeout'
    } finally { foreach ($x in $tries) { try { $x.Client.Close() } catch { } } }
}

function Invoke-ConnectionDiagnostics {
    <#
        Diagnostyka niedostępnego serwera ze stacji: DNS (A i PTR), ping, porty TCP (równolegle, z limitem czasu),
        TrustedHosts dla adresów IP, konto komputera w AD i klasyfikacja błędu WinRM. Trwa zwykle 2–4 s.
        Wynik: przyczyna i zalecenie (po polsku) + lista sprawdzeń do sekcji „Diagnoza połączenia”.
    #>
    param(
        [string]$Target, [string]$ErrorText = '', [string]$ErrorId = '', [string]$ErrorCode = '',
        [int[]]$Ports = @(5985, 5986, 135, 445, 3389), [int]$TimeoutMs = 2000, [bool]$CheckAd = $true
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $Ports = [int[]]@(@(5985) + @($Ports | Where-Object { $_ -and $_ -ne 5985 }))   # 5985 zawsze – od niego zależy wniosek
    $checks = New-Object System.Collections.Generic.List[object]
    $add = { param($c, $res, $st) $checks.Add([pscustomobject]@{ Check = $c; Value = "$res"; Status = $st }) }
    $portNames = @{ 5985 = 'WinRM HTTP'; 5986 = 'WinRM HTTPS'; 135 = 'RPC'; 445 = 'SMB'; 3389 = 'RDP'; 22 = 'SSH'; 80 = 'HTTP'; 443 = 'HTTPS' }
    $cls = Get-WinRmErrorInfo -Message $ErrorText -ErrorId $ErrorId -Code $ErrorCode
    if ($ErrorText) { & $add 'Błąd połączenia' (($ErrorText -replace '\s+', ' ').Trim()) 'Błąd' }

    # ── Nazwa i DNS ──
    $isIp = ($Target -match '^\d{1,3}(\.\d{1,3}){3}$' -or $Target.Contains(':'))
    $ips = @(); $dnsOk = $true; $ptr = ''
    if ($isIp) {
        $ips = @($Target)
        & $add 'Nazwa' 'adres IP – Kerberos niedostępny, potrzebny wpis TrustedHosts i jawne konto' 'Info'
    } else {
        try {
            $ar = [Net.Dns]::BeginGetHostAddresses($Target, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne([Math]::Max(3000, $TimeoutMs * 2))) {
                $addrs = @([Net.Dns]::EndGetHostAddresses($ar))
                $ips = @($addrs | Where-Object { "$($_.AddressFamily)" -eq 'InterNetwork' } | ForEach-Object { $_.ToString() })
                if (-not $ips.Count) { $ips = @($addrs | ForEach-Object { $_.ToString() }) }
            } else { & $add 'DNS' 'brak odpowiedzi serwera DNS w limicie czasu' 'Błąd' }
        } catch {
            $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            & $add 'DNS' "nie można rozwiązać nazwy: $msg" 'Błąd'
        }
        if ($ips.Count) { & $add 'DNS' ($ips -join ', ') 'OK' } else { $dnsOk = $false }
        if ($ips.Count) {
            # PTR wskazujący inny komputer = nieaktualny wpis DNS (adres przejęty przez inną maszynę) – częsta przyczyna błędów Kerberos
            try {
                $ar2 = [Net.Dns]::BeginGetHostEntry($ips[0], $null, $null)
                if ($ar2.AsyncWaitHandle.WaitOne($TimeoutMs)) { $ptr = "$([Net.Dns]::EndGetHostEntry($ar2).HostName)" }
            } catch {}
            if ($ptr -and $ptr -ne $ips[0]) {
                $same = $ptr.Split('.')[0] -eq $Target.Split('.')[0]
                & $add 'DNS odwrotny (PTR)' "$($ips[0]) → $ptr" $(if ($same) { 'OK' } else { 'Uwaga' })
            } else { $ptr = ''; & $add 'DNS odwrotny (PTR)' "brak rekordu PTR dla $($ips[0])" 'Info' }
        }
    }

    # ── Ping i porty TCP (równolegle) ──
    $ip = if ($ips.Count) { $ips[0] } else { $null }
    $pingOk = $false; $state = @{}
    if ($ip) {
        $pinger = $null; $pingTask = $null; $tcp = @()
        try { $pinger = New-Object Net.NetworkInformation.Ping; $pingTask = $pinger.SendPingAsync($ip, $TimeoutMs) } catch {}
        foreach ($port in $Ports) {
            $cl = New-Object Net.Sockets.TcpClient
            $task = $null; try { $task = $cl.ConnectAsync($ip, [int]$port) } catch {}
            $tcp += , @{ Port = [int]$port; Client = $cl; Task = $task }
        }
        $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs + 250)
        foreach ($tk in @(@($pingTask) + @($tcp | ForEach-Object { $_.Task }) | Where-Object { $_ })) {
            $left = [int][Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            try { [void]$tk.Wait($left) } catch {}
        }
        if ($pingTask -and "$($pingTask.Status)" -eq 'RanToCompletion' -and "$($pingTask.Result.Status)" -eq 'Success') {
            $pingOk = $true; & $add 'Ping (ICMP)' "odpowiada ($($pingTask.Result.RoundtripTime) ms)" 'OK'
        } else { & $add 'Ping (ICMP)' 'brak odpowiedzi (ICMP bywa blokowany przez zaporę – samo w sobie nie przesądza)' 'Uwaga' }
        foreach ($x in $tcp) {
            $st = 'timeout'
            if (-not $x.Task) { $st = 'error' }
            elseif ("$($x.Task.Status)" -eq 'RanToCompletion' -and $x.Client.Connected) { $st = 'open' }
            elseif ($x.Task.IsFaulted) {
                $se = $x.Task.Exception.InnerException
                $st = if ($se -is [Net.Sockets.SocketException] -and "$($se.SocketErrorCode)" -eq 'ConnectionRefused') { 'refused' } else { 'unreach' }
            }
            $state[$x.Port] = $st
            try { $x.Client.Close() } catch {}
            $label = "TCP $($x.Port)$(if ($portNames.ContainsKey($x.Port)) { " ($($portNames[$x.Port]))" })"
            switch ($st) {
                'open'    { & $add $label 'otwarty' $(if ($x.Port -eq 5985) { 'OK' } else { 'Info' }) }
                'refused' { & $add $label 'zamknięty – host odrzuca połączenie (działa, ale nic nie nasłuchuje)' $(if ($x.Port -eq 5985) { 'Błąd' } else { 'Info' }) }
                'unreach' { & $add $label 'host lub sieć nieosiągalne' 'Błąd' }
                'error'   { & $add $label 'nie udało się wykonać próby' 'Info' }
                default   { & $add $label 'brak odpowiedzi w limicie czasu (filtrowany przez zaporę albo host wyłączony)' $(if ($x.Port -eq 5985) { 'Błąd' } else { 'Uwaga' }) }
            }
        }
        if ($pinger) { try { $pinger.Dispose() } catch {} }
    }

    # ── TrustedHosts (połączenia po adresie IP) ──
    if ($isIp) {
        $th = ''
        try { $th = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client' -ErrorAction Stop).trusted_hosts)" } catch {}
        try { $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -ErrorAction Stop; if ($pol.TrustedHosts -eq 1 -and $pol.TrustedHostsList) { $th = "$th,$($pol.TrustedHostsList)" } } catch {}
        $inTh = $false
        foreach ($e in ($th -split ',')) { $e = $e.Trim(); if ($e -and ($e -eq '*' -or $Target -like $e)) { $inTh = $true } }
        & $add 'TrustedHosts (stacja)' $(if ($inTh) { "zawiera $Target" } elseif ($th.Trim(',')) { "brak $Target (lista: $($th.Trim(',')))" } else { 'lista pusta' }) $(if ($inTh) { 'OK' } else { 'Uwaga' })
    }

    # ── Konto komputera w AD ──
    $ad = $null
    if ($CheckAd -and -not $isIp) {
        $ad = Get-AdComputerInfo $Target
        if ($ad.Error) { & $add 'Konto komputera w AD' "nie sprawdzono: $($ad.Error)" 'Info' }
        elseif (-not $ad.Found) { & $add 'Konto komputera w AD' 'nie znaleziono w domenie stacji (serwer spoza domeny albo usunięty)' 'Uwaga' }
        else {
            $txt = "$(if ($ad.Enabled) { 'włączone' } else { 'WYŁĄCZONE' })$(if ($null -ne $ad.LastLogonDays) { ", ostatnie logowanie do domeny ≈ $($ad.LastLogonDays) dni temu" })$(if ($null -ne $ad.PwdAgeDays) { ", hasło konta zmienione $($ad.PwdAgeDays) dni temu" }), $($ad.OS)"
            & $add 'Konto komputera w AD' $txt $(if (-not $ad.Enabled -or $ad.LastLogonDays -gt 30 -or $ad.PwdAgeDays -gt 60) { 'Uwaga' } else { 'OK' })
        }
    }

    # ── Zduplikowany SPN HTTP/<serwer> (Kerberos 0x80090322) ──
    $spnOwners = @()
    if (-not $isIp -and ("$ErrorText $ErrorCode" -match '0x80090322')) {
        try {
            $spnOwners = @(Get-HttpSpnOwners $Target)
            if ($spnOwners.Count) { foreach ($o in $spnOwners) { & $add 'Zduplikowany SPN' "$($o.Spn) zarejestrowany na koncie $($o.Account)" 'Błąd' } }
            else { & $add 'SPN HTTP/' 'brak SPN HTTP/ serwera na innych kontach' 'OK' }
        } catch { & $add 'SPN HTTP/' "nie sprawdzono: $($_.Exception.Message)" 'Info' }
    }

    # ── Wniosek: najpierw sieć (czy serwer w ogóle żyje), potem WinRM, potem uwierzytelnianie ──
    $w = $state[5985]
    $alive = $pingOk -or @($state.Values | Where-Object { $_ -in 'open', 'refused' }).Count -gt 0
    $cause = $cls.Cause; $remedy = $cls.Remedy; $class = $cls.Class
    if ($class -in 'Timeout', 'Remote' -and $ErrorId -match '^(SrTimeout|CollectorFatal)' -and $alive) { }
    elseif (-not $isIp -and -not $dnsOk) {
        $class = 'Dns'; $cause = 'Nazwa serwera nie jest rozwiązywana w DNS'
        $remedy = 'Sprawdź pisownię i rekord A w DNS. Jeśli serwer wycofano – usuń go z listy.'
    }
    elseif ($ip -and -not $alive) {
        $class = 'Offline'; $cause = 'Serwer nie odpowiada w sieci – prawdopodobnie wyłączony, odłączony od sieci albo całkowicie blokowany przez zaporę'
        $remedy = 'Sprawdź, czy serwer działa (konsola, iLO/iDRAC, host Hyper-V) i czy jest osiągalny z tej stacji (routing, VLAN, zapora sieciowa).'
    }
    elseif ($w -eq 'refused') {
        $class = 'WinRM'; $cause = 'Serwer działa, ale port WinRM 5985 jest zamknięty – usługa WinRM zatrzymana albo brak listenera HTTP'
        $remedy = 'Na serwerze: Enable-PSRemoting -Force (albo winrm quickconfig); sprawdź usługę: Get-Service WinRM.'
    }
    elseif ($w -in 'timeout', 'unreach') {
        $class = 'Firewall'; $cause = 'Serwer odpowiada, ale WinRM (TCP 5985) jest blokowany – zapora na serwerze albo w sieci'
        $remedy = 'Włącz regułę zapory „Windows Remote Management (HTTP-In)” dla profilu Domena albo odblokuj 5985 na zaporze sieciowej.'
    }
    elseif ($w -eq 'open' -and -not $ErrorText) {
        # diagnoza na żądanie działającego serwera – bez błędu połączenia do wyjaśnienia
        $class = 'OK'; $cause = 'WinRM jest osiągalny ze stacji (port 5985 otwarty)'; $remedy = ''
    }
    elseif ($w -eq 'open' -and $class -in 'Network', 'Unknown', 'Dns') {
        $class = 'WinRM'; $cause = 'WinRM nasłuchuje (port 5985 otwarty), ale sesja nie powstała'
        $remedy = 'Szczegóły w wierszu „Błąd połączenia”. Na serwerze: Test-WSMan, dziennik Microsoft-Windows-WinRM/Operational.'
    }
    if ($spnOwners.Count -and $alive) {
        $o = $spnOwners[0]
        $class = 'Kerberos'; $cause = "Kerberos: SPN $($o.Spn) jest zarejestrowany na koncie $($o.Account) – kontroler domeny szyfruje bilet kluczem tego konta, więc WinRM na serwerze go odrzuca"
        $remedy = "Usuń zduplikowany SPN: setspn -D $(@($o.Spn -split ', ')[0]) $($o.Account) (jeśli usługa na tym koncie potrzebuje SPN HTTP, przenieś ją na inny port lub nazwę)."
    }
    $notes = New-Object System.Collections.Generic.List[string]
    if ($ad -and $ad.Found -and -not $ad.Enabled) { $notes.Add('konto komputera w AD jest wyłączone – serwer prawdopodobnie wycofany') }
    elseif ($ad -and $ad.Found -and $ad.LastLogonDays -gt 30) { $notes.Add("konto komputera nie logowało się do domeny od ok. $($ad.LastLogonDays) dni") }
    elseif ($ad -and $ad.Found -and $ad.PwdAgeDays -gt 60) { $notes.Add("hasło konta komputera nie zmieniło się od $($ad.PwdAgeDays) dni – możliwy zerwany kanał zabezpieczeń (Test-ComputerSecureChannel)") }
    elseif ($ad -and -not $ad.Found -and -not $ad.Error) { $notes.Add('brak konta komputera w AD') }
    if ($ad -and $ad.OS -and $ad.OS -notmatch 'Windows') { $notes.Add("system wg AD: $($ad.OS) – nie jest skanowany") }
    $portTxt = (@($state.Keys | Sort-Object | ForEach-Object { "$_ $(switch ($state[$_]) { 'open' { 'otwarty' } 'refused' { 'zamknięty' } 'unreach' { 'nieosiągalny' } 'error' { '?' } default { 'brak odp.' } })" }) -join ', ')
    [pscustomobject]@{
        Class = $class; Cause = $cause; Remedy = $remedy; Code = $cls.Code; Notes = ($notes -join '; ')
        Ip = "$ip"; Ptr = $ptr; Ping = $pingOk; Ports = $portTxt; Port5985 = "$($state[5985])"
        AdFound = $(if ($ad) { $ad.Found } else { $null }); AdEnabled = $(if ($ad) { $ad.Enabled } else { $null })
        AdLastLogonDays = $(if ($ad) { $ad.LastLogonDays } else { $null }); AdOS = $(if ($ad) { $ad.OS } else { '' })
        Checks = [object[]]$checks.ToArray(); DurationSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
}

# Treść wątku tła. Tryby: Scan (kolektor + zapis migawki + diagnostyka po błędzie), Diag (sama diagnostyka), Load (migawki z dysku)
# (param() musi być pierwszą instrukcją skryptu – funkcje są wstawiane za nim, patrz $script:WorkerScript)
$script:WorkerParams = 'param([string]$Mode, [string]$Target, [hashtable]$Opt, $Sync)'
$script:WorkerBody = @'
$ProgressPreference = 'SilentlyContinue'
$res = [ordered]@{
    Mode = $Mode; Name = $Target; Ok = $false; Data = $null; Prev = $null; Last = $null; Error = ''; ErrorId = ''; ErrorCode = ''
    Diag = $null; SnapFile = ''; SnapError = ''; LatestFile = ''; PrevFile = ''; ScannedAt = ''; DurationSec = 0; ReceivedUtc = $null
}
$sw = [Diagnostics.Stopwatch]::StartNew()
try { $Sync.Started[$Target] = [DateTime]::UtcNow } catch {}
try {
    if ($Mode -eq 'Scan') {
        $json = $null
        $skip = $false
        if ($Opt.Preflight) {
            # Szybki test portu 5985 (dwie próby po ≤ 3 s – pojedynczy pakiet SYN bywa gubiony): wyłączony serwer nie zajmuje wątku
            # przez pełny limit połączenia WinRM. Gdy diagnostyka zastanie port już otwarty – zwykły skan.
            $tmo = [Math]::Min(3000, [int]$Opt.ConnectTimeoutSec * 1000)
            $pf = Test-WinRmPort $Target $tmo
            if ($pf -eq 'timeout') { $pf = Test-WinRmPort $Target $tmo }
            if ($pf -eq 'timeout' -or $pf -eq 'refused') {
                $res.Error = $(if ($pf -eq 'refused') { 'Port WinRM 5985 odrzuca połączenie (wstępny test portu).' } else { 'Port WinRM 5985 nie odpowiada (wstępny test portu, dwie próby).' })
                $res.ErrorId = 'SrPreflight'
                try { $res.Diag = Invoke-ConnectionDiagnostics -Target $Target -ErrorText $res.Error -ErrorId $res.ErrorId -Ports $Opt.DiagPorts -TimeoutMs $Opt.DiagTimeoutMs -CheckAd $true } catch { }
                if ($res.Diag -and $res.Diag.Port5985 -eq 'open') { $res.Error = ''; $res.ErrorId = ''; $res.Diag = $null }
                else { $skip = $true }
            }
        }
        if (-not $skip) { try {
            $so = New-PSSessionOption -OpenTimeout ([int]$Opt.ConnectTimeoutSec * 1000)
            # Kolektor jest kompilowany na serwerze w try: błąd składni na starszym PowerShell (np. 4.0 na 2012 R2) daje czytelny
            # błąd kolektora z wersją PowerShell, a nie „brak połączenia”
            $boot = {
                param([string]$Text, [object[]]$CArgs)
                $sb = $null
                try { $sb = [scriptblock]::Create($Text) }
                catch { return ('{"Fatal":' + (ConvertTo-Json ("kolektor nie kompiluje się w PowerShell $($PSVersionTable.PSVersion): $($_.Exception.Message)") -Compress) + '}') }
                & $sb @CArgs
            }
            $ic = @{ ComputerName = $Target; ScriptBlock = $boot; ArgumentList = @($Opt.CollectorText, [object[]]$Opt.CollectorArgs); SessionOption = $so; ErrorAction = 'Stop' }
            if ($Opt.Credential) { $ic.Credential = $Opt.Credential }
            $out = @(Invoke-Command @ic)
            $res.ReceivedUtc = [DateTime]::UtcNow
            $strs = @($out | Where-Object { $_ -is [string] })
            $json = $strs | Where-Object { $_.StartsWith('{') } | Select-Object -Last 1
            $mark = $strs | Where-Object { $_.StartsWith('@@SRTIME@@') } | Select-Object -Last 1
            if (-not $json) { $res.Error = 'Serwer nie zwrócił danych.'; $res.ErrorId = 'NoData' }
        } catch {
            $res.Error = "$($_.Exception.Message)"
            $res.ErrorId = "$($_.FullyQualifiedErrorId)"
            $ex = $_.Exception
            if ($ex -and $ex.PSObject.Properties['ErrorCode'] -and $ex.ErrorCode) { try { $res.ErrorCode = '0x{0:X8}' -f [int]$ex.ErrorCode } catch {} }
        } }
        if ($json) {
            $d = $null
            try { $d = ConvertFrom-ServerJson $json $Opt.ArrayKeys } catch { $res.Error = "Nie udało się odczytać danych z serwera: $($_.Exception.Message)"; $res.ErrorId = 'ParseError' }
            if (-not $d) { }
            elseif ($d.PSObject.Properties['Fatal']) {
                $res.Error = "Kolektor przerwał pracę na serwerze: $($d.Fatal)"; $res.ErrorId = 'CollectorFatal'
            } else {
                # Różnica czasu serwera względem stacji (moment zebrania danych vs moment odbioru); zapisywana także w migawce
                if ($d.System -and (($d.System.PSObject.Properties['CollectedUtc'] -and $d.System.CollectedUtc) -or $mark)) {
                    try {
                        $cu  = if ($mark) { $mark.Substring(10) } else { $d.System.CollectedUtc }
                        $cu  = if ($cu -is [datetime]) { $cu.ToUniversalTime() } else { [datetime]::Parse("$cu", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
                        $off = [math]::Round(($cu - $res.ReceivedUtc).TotalSeconds, 1)
                        $d.System | Add-Member -NotePropertyName TimeOffsetSec -NotePropertyValue $off -Force
                        $json = ([regex]'"System":\{').Replace($json, '"System":{"TimeOffsetSec":' + $off.ToString([Globalization.CultureInfo]::InvariantCulture) + ',', 1)
                    } catch {}
                }
                $file = Join-Path $Opt.SnapDir ($Opt.SafeName + $(if ($Opt.Compress) { '.json.gz' } else { '.json' }))
                # błąd zapisu na stacji (pełny dysk, brak uprawnień) nie oznacza niedostępności serwera – dane zostają w pamięci
                try { Write-SnapshotText $file $json; $res.SnapFile = $file } catch { $res.SnapError = "$($_.Exception.Message)" }
                $res.Data = $d
                $res.Ok = $true
                $res.PrevFile = "$($Opt.PrevFile)"
                if ($Opt.PrevFile) { try { $res.Prev = ConvertFrom-ServerJson (Read-SnapshotText $Opt.PrevFile) $Opt.ArrayKeys } catch {} }
            }
        }
        if (-not $res.Ok -and $res.ErrorId -in 'CollectorFatal', 'ParseError', 'NoData') {
            # serwer odpowiada, ale danych nie ma – diagnostyka sieci nic tu nie wniesie
            $ci = Get-WinRmErrorInfo -Message $res.Error -ErrorId 'CollectorFatal'
            $res.Diag = [pscustomobject]@{ Class = 'Remote'; Cause = "Serwer odpowiada, ale nie udało się zebrać danych: $(($res.Error -replace '\s+', ' ').Trim())"; Remedy = $ci.Remedy; Code = ''; Notes = ''; Ip = ''; Ptr = ''; Ping = $null; Ports = ''; AdFound = $null; AdEnabled = $null; AdLastLogonDays = $null; AdOS = ''; Checks = @(); DurationSec = 0 }
        }
        elseif (-not $res.Ok -and -not $res.Diag) {
            try { $res.Diag = Invoke-ConnectionDiagnostics -Target $Target -ErrorText $res.Error -ErrorId $res.ErrorId -ErrorCode $res.ErrorCode -Ports $Opt.DiagPorts -TimeoutMs $Opt.DiagTimeoutMs -CheckAd $true } catch {}
        }
        if (-not $res.Ok) {
            if ($Opt.LastOnlineFile) { try { $res.Last = Get-SnapshotSummary $Opt.LastOnlineFile } catch {} }
            # Znacznik niedostępności w folderze skanu – po ponownym uruchomieniu programu serwer pokaże się jako niedostępny
            try {
                $mk = [ordered]@{ Offline = $true; Error = $res.Error; ErrorId = $res.ErrorId; ErrorCode = $res.ErrorCode; Diag = $res.Diag; ScannedUtc = [DateTime]::UtcNow.ToString('o'); Days = $Opt.Days }
                $file = Join-Path $Opt.SnapDir ($Opt.SafeName + '.offline.json')
                Write-SnapshotText $file ([pscustomobject]$mk | ConvertTo-Json -Depth 5 -Compress)
                $res.SnapFile = $file
            } catch {}
        }
    }
    elseif ($Mode -eq 'Diag') {
        $res.Diag = Invoke-ConnectionDiagnostics -Target $Target -ErrorText $Opt.ErrorText -ErrorId $Opt.ErrorId -ErrorCode $Opt.ErrorCode -Ports $Opt.DiagPorts -TimeoutMs $Opt.DiagTimeoutMs -CheckAd $true
        $res.Ok = $true
    }
    elseif ($Mode -eq 'Load') {
        # Opt.Files: migawki serwera od najnowszej (@{ Path; Offline }). Uszkodzony plik (np. przerwany zapis) jest pomijany.
        $files = @($Opt.Files)
        $i = 0
        for (; $i -lt $files.Count; $i++) {
            try { $res.Data = ConvertFrom-ServerJson (Read-SnapshotText $files[$i].Path) $Opt.ArrayKeys; break }
            catch { $res.Error += "Pominięto uszkodzoną migawkę $($files[$i].Path): $($_.Exception.Message). " }
        }
        if ($res.Data) {
            $res.LatestFile = $files[$i].Path
            $res.ScannedAt = ([IO.File]::GetLastWriteTime($files[$i].Path)).ToString('yyyy-MM-dd HH:mm')
            $isOff = $res.Data.PSObject.Properties['Offline'] -and $res.Data.Offline
            for ($j = $i + 1; $j -lt $files.Count; $j++) {
                if ($files[$j].Offline) { continue }
                try {
                    if ($isOff) { $res.Last = Get-SnapshotSummary $files[$j].Path }
                    else { $res.Prev = ConvertFrom-ServerJson (Read-SnapshotText $files[$j].Path) $Opt.ArrayKeys; $res.PrevFile = $files[$j].Path }
                    break
                } catch { }
            }
            $res.Ok = $true
        }
    }
} catch {
    if (-not $res.Error) { $res.Error = "$($_.Exception.Message)" }
}
$res.DurationSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
[pscustomobject]$res
'@
$script:WorkerFunctionNames = 'Read-SnapshotText', 'Write-SnapshotText', 'ConvertFrom-ServerJson', 'Get-SnapshotSummary', 'Get-WinRmErrorInfo', 'Get-AdComputerInfo', 'Get-HttpSpnOwners', 'Test-WinRmPort', 'Invoke-ConnectionDiagnostics'
# Pełna definicja funkcji z drzewa składni (razem z deklaracją parametrów)
$script:WorkerScript = $script:WorkerParams + "`n" + ((@($script:WorkerFunctionNames | ForEach-Object { (Get-Item "function:$_").ScriptBlock.Ast.Extent.Text })) -join "`n`n") + "`n" + $script:WorkerBody
#endregion

#region ── Definicje sekcji, nagłówków, ważności ─────────────────────────────────
$script:Sections = @(
    @{ Key = 'Issues';         Header = 'Problemy' }
    @{ Key = 'Diagnostics';    Header = 'Diagnoza połączenia'; Computed = $true }
    @{ Key = 'History';        Header = 'Historia skanów i dostępność'; Computed = $true }
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
    @{ Key = 'Downtime';       Header = 'Przestoje (wyłączenie → start)' }
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
    @{ Key = 'HvHost';         Header = 'Hyper-V: host i pojemność'; Computed = $true }
    @{ Key = 'Cluster';        Header = 'Klaster Hyper-V' }
    @{ Key = 'HyperV';         Header = 'Hyper-V: maszyny' }
    @{ Key = 'Checkpoints';    Header = 'Hyper-V: checkpointy' }
    @{ Key = 'VMStorage';      Header = 'Hyper-V: dyski VM' }
    @{ Key = 'Timings';        Header = 'Czas zbierania sekcji' }
)
# Sekcje tablicowe z kolektora (Computed = budowane na stacji z innych danych)
$script:ArrayKeys = @($script:Sections | Where-Object { $_.Key -notin 'Issues', 'Changes', 'System' -and -not $_.Computed } | ForEach-Object { $_.Key })

$script:SevMeta = @{
    'Krytyczny'   = @{ Rank = 0; Color = '#FF6B78'; Bg = '#2EFF5C6C'; Flag = 'crit' }
    'Ostrzeżenie' = @{ Rank = 1; Color = '#FFC15E'; Bg = '#2EFFB547'; Flag = 'warn' }
    'Info'        = @{ Rank = 2; Color = '#7DB5FF'; Bg = '#2E60A5FA'; Flag = 'info' }
}

# Co porównujemy między skanami (klucz identyfikujący pozycję)
$script:DiffDefs = [ordered]@{
    Services   = @{ Label = 'usługi';          KeyFn = { param($r) "$($r.Name) [$($r.Account)]" }; Filter = { $_.Microsoft -eq 'Nie' }; Sev = 'Ostrzeżenie' }
    Tasks      = @{ Label = 'zadania';         KeyFn = { param($r) "$($r.Path)" };                  Filter = $null; Sev = 'Ostrzeżenie' }
    # porty dynamiczne RPC (TCP 49152+) zmieniają się po każdym restarcie – porównujemy proces i usługę, nie numer portu
    Listening  = @{ Label = 'porty';           KeyFn = { param($r) if ("$($r.Proto)" -eq 'TCP' -and [int]$r.Port -ge 49152) { "TCP/dynamiczny $($r.Process) [$($r.Service)]" } else { "$($r.Proto)/$($r.Port) $($r.Process)" } }; Filter = $null; Sev = 'Ostrzeżenie' }
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
    Model = 'Model'; CPUName = 'Procesor'; Cores = 'Procesory logiczne'; CpuLoad = 'Obciążenie CPU [%]'; RamGB = 'RAM [GB]'; RamUsedPct = 'Użycie RAM [%]'; RamFreeGB = 'Wolny RAM [GB]'
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
    Down = 'Wyłączenie'; Up = 'Start'; DowntimeMin = 'Przestój [min]'; Initiator = 'Zainicjował'; Reason = 'Przyczyna'; Sec = 'Czas [s]'
    CpuUsage = 'CPU [%]'; MemStartupGB = 'RAM startowy [GB]'; ReplicationMode = 'Tryb replikacji'; Checkpoints = 'Checkpointy'; CheckpointType = 'Typ checkpointów'
    AutoStop = 'Przy wyłączeniu hosta'; IntegrationVersion = 'Wersja usług integracji'; GuestOS = 'System gościa'; GuestFQDN = 'Nazwa gościa (FQDN)'
    GuestIP = 'Adresy IP gościa'; Linux = 'Linux'; Clustered = 'W klastrze'; Switch = 'Przełącznik wirtualny'
    Hypervisor = 'Platforma wirtualizacji'; IsVirtual = 'Maszyna wirtualna'; HvHost = 'Host Hyper-V'; HvVmName = 'Nazwa maszyny na hoście'
    HvLogicalCpus = 'Procesory logiczne hosta'; HvNumaSpanning = 'NUMA spanning'; HvVhdPath = 'Domyślna ścieżka dysków VM'; HvVmTotal = 'Maszyny wirtualne'
    HvVmRunning = 'Maszyny działające'; HvVcpuRunning = 'vCPU działających maszyn'; HvVcpuTotal = 'vCPU wszystkich maszyn'
    HvRamAssignedGB = 'RAM przydzielony maszynom [GB]'; HvRamStartupGB = 'RAM startowy wszystkich maszyn [GB]'; HvCluster = 'Klaster'; HvClusterNodes = 'Węzły klastra'
    DurationSec = 'Czas [s]'; Class = 'Rodzaj'; Kind = 'Typ'; Host = 'Host'; Availability = 'Dostępność'; OnList = 'Na liście'; GuestStatus = 'Stan gościa'
    VCpuRatio = 'vCPU : CPU'; RamPct = 'RAM przydzielony [%]'; Vms = 'Maszyny'; Nodes = 'Węzły'; Hosts = 'Hosty'; DisksGBTotal = 'Dyski VM [GB]'
    LastOk = 'Ostatni udany skan'; Seen = 'Skany'; OkPct = 'Udane [%]'; Note = 'Uwagi'
    Owner = 'Właściciel'; Parent = 'Checkpoint nadrzędny'; StateSince = 'W tym stanie od'; MemMaxGB = 'RAM maks. [GB]'; MemDemandGB = 'RAM zapotrzebowanie [GB]'
    AutoStart = 'Przy starcie hosta'; ChainDepth = 'Głębokość łańcucha dysków'; OnSystemDrive = 'Na dysku systemowym hosta'; HvVmms = 'Usługa zarządzania Hyper-V'
    HvCpuLoad = 'Obciążenie CPU hiperwizora [%]'; HvVmReplicas = 'Repliki (Hyper-V Replica)'; HvClusterNodeCount = 'Liczba węzłów klastra'; HvVmId = 'Identyfikator maszyny'
    Truncated = 'Limit zdarzeń osiągnięty'
}
#endregion

#region ── Funkcje pomocnicze ───────────────────────────────────────────────────
$script:BrushConv = New-Object System.Windows.Media.BrushConverter
$script:BrushCache = @{}
function Brush([string]$Hex) {
    $b = $script:BrushCache[$Hex]
    if (-not $b) { $b = $script:BrushConv.ConvertFromString($Hex); if ($b.CanFreeze) { $b.Freeze() }; $script:BrushCache[$Hex] = $b }
    $b
}
function Get-Header([string]$Name) { if ($script:Headers.ContainsKey($Name)) { $script:Headers[$Name] } else { $Name } }
function Test-IpAddress([string]$Name) { $Name -match '^\d{1,3}(\.\d{1,3}){3}$' -or $Name.Contains(':') }
function Get-DisplayName([string]$Name) {
    if (-not $Name) { return '' }
    if (Test-IpAddress $Name) { return $Name }   # adres IP: obcięcie do kropki dawało np. "10"
    $Name.Split('.')[0].ToUpper()
}
function Get-SafeName([string]$Name) { $Name -replace '[\\/:*?"<>|]', '_' }
function Get-ShortText([string]$s, [int]$n) { $s = "$s" -replace '\s+', ' '; if ($s.Length -gt $n) { $s.Substring(0, $n) + '…' } else { $s.Trim() } }
function Join-Short($Items, [int]$Max) {
    $a = @($Items | Where-Object { $_ })
    $t = (@($a | Select-Object -First $Max)) -join ', '
    if ($a.Count -gt $Max) { $t += " (+$($a.Count - $Max))" }
    $t
}
function Protect-CsvCell($Value) {
    # Wartości pochodzą z audytowanych serwerów (nazwy plików, akcje zadań) – bez tego Excel wykonałby formułę/DDE z komórki
    # liczby w formacie stacji (12,5 w polskim Excelu, nie data 12 maja); liczby ujemne nie są formułą
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal] -or $Value -is [int] -or $Value -is [long]) { return $Value.ToString([Globalization.CultureInfo]::CurrentCulture) }
    $s = "$Value"
    if ($s -match '^[=+\-@\t\r]') { "'" + $s } else { $s }
}
function Export-RowsToCsv($Rows, [string]$Path) {
    # Eksport z polskimi nagłówkami, w kolejności kolumn, z ochroną przed wstrzyknięciem formuł; separator ';', UTF-8 z BOM (Excel)
    $Rows = @($Rows | Where-Object { $null -ne $_ })
    $skip = 'Flag', 'Key', 'Rows', 'SevColor', 'SevBg', 'Rank', 'ServerKey', 'Section', 'IssueKey', '_Search', 'Ignored'
    $out = foreach ($r in $Rows) {
        $h = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) { if ($skip -notcontains $p.Name -and $p.Name -notlike '_*') { $h[(Get-Header $p.Name)] = Protect-CsvCell $p.Value } }   # '_*' – pola wewnętrzne, niewidoczne w tabelach
        [pscustomobject]$h
    }
    @($out) | Export-Csv -LiteralPath $Path -NoTypeInformation -Delimiter ';' -Encoding UTF8
}

function New-Issue($ServerKey, $Severity, $Category, $Message, $Section) {
    $m = $script:SevMeta[$Severity]
    $srv = Get-DisplayName $ServerKey
    [pscustomobject]@{
        Severity = $Severity; Server = $srv; Category = $Category; Message = $Message
        ServerKey = $ServerKey; Section = $Section; Rank = $m.Rank; SevColor = $m.Color; SevBg = $m.Bg; Flag = $m.Flag
        IssueKey = (Get-IssueKey $Category $Section $Message); Ignored = $false
        _Search = ("$srv $Category $Message").ToLowerInvariant()
    }
}
function Get-IssueKey([string]$Category, [string]$Section, [string]$Message) {
    # Stały klucz problemu do wyciszania: wartości (wolne %, dni, liczniki, daty, adresy) zastąpione '#', żeby reguła działała
    # przy kolejnych skanach. Cyfry będące częścią nazwy (SRV01, APP-02, KB5034441, 0x80090322) i numery po „ID”, „port”, „kod”
    # zostają – wyciszenie jednej maszyny, zdarzenia albo portu nie może wyciszać innych.
    $m = ("$Message" -replace '(?<![\p{L}\d_])(?<!\p{L}-)(?<!(?:ID|Id|port|portu|kod|KB) )\d+(?:[.,:]\d+)*(?![\p{L}\d_])', '#' -replace '\s+', ' ').Trim()
    "$Category|$Section|$m"
}
#endregion

#region ── Dziennik operacji i dziennik dostępności ────────────────────────────
# Dziennik operacji: lista w panelu na dole okna (ostatnie 3000 wpisów) + plik Logs\ServerReview_RRRRMMDD.log.
# Dziennik dostępności: Logs\Availability_RRRRMM.csv – każdy wynik skanu każdego serwera (status, czas, przyczyna niedostępności).
$script:LogItems  = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
$script:LogUnread = 0
$script:Headless  = $false
$script:LogFailed = $false
function Write-Log {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [string]$Module = 'Program'
    )
    $now = Get-Date
    if (-not $script:Headless) {
        try {
            $items = $script:LogItems
            if ($items.Count -ge 3000) { for ($i = 0; $i -lt 500; $i++) { $items.RemoveAt(0) } }
            $entry = [pscustomobject]@{ Time = $now.ToString('HH:mm:ss'); Level = $Level; Module = $Module; Message = $Message; _Search = ("$Module $Message").ToLowerInvariant() }
            $items.Add($entry)
            if ($ui -and $ui['logList'] -and $ui.logPanel.Visibility -eq 'Visible') { $ui.logList.ScrollIntoView($entry) }
            elseif ($Level -in 'WARN', 'ERROR') { $script:LogUnread++; Update-LogBadge }
        } catch { }
    } else {
        $color = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Gray' } }
        Write-Host ('{0:HH:mm:ss} [{1}] [{2}] {3}' -f $now, $Level, $Module, $Message) -ForegroundColor $color
    }
    try {
        if (-not (Test-Path -LiteralPath $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null }
        $file = Join-Path $Config.LogDir ('ServerReview_{0:yyyyMMdd}.log' -f $now)
        $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] [{2}] {3}' -f $now, $Level, $Module, ($Message -replace '\r?\n', ' | ')
        [IO.File]::AppendAllText($file, $line + [Environment]::NewLine, (New-Object Text.UTF8Encoding $false))
    } catch { $script:LogFailed = $true }
}
function Update-LogBadge {
    if (-not $ui -or -not $ui['logBadge']) { return }
    if ($script:LogUnread -gt 0) { $ui.logBadgeText.Text = [string][Math]::Min(99, $script:LogUnread); $ui.logBadge.Visibility = 'Visible' }
    else { $ui.logBadge.Visibility = 'Collapsed' }
}
function Get-LogFile { Join-Path $Config.LogDir ('ServerReview_{0:yyyyMMdd}.log' -f (Get-Date)) }

function ConvertTo-CsvSafe([string]$s) { ("$s" -replace '[\r\n]+', ' ' -replace ';', ',').Trim() }
function Add-AvailabilityRecord {
    # Jeden wiersz na wynik skanu serwera (także udany) – podstawa historii dostępności
    param([string]$Name, [string]$Status, $DurationSec, [int]$Crit = 0, [int]$Warn = 0, [string]$Class = '', [string]$Detail = '')
    $now = Get-Date
    try {
        if (-not (Test-Path -LiteralPath $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null }
        $file = Join-Path $Config.LogDir ('Availability_{0:yyyyMM}.csv' -f $now)
        $dur = if ("$DurationSec" -ne '') { ([double]$DurationSec).ToString('0.0', [Globalization.CultureInfo]::InvariantCulture) } else { '' }
        $line = (@(('{0:yyyy-MM-dd HH:mm:ss}' -f $now), $Name, $Status, $dur, $Crit, $Warn, $Class, (ConvertTo-CsvSafe $Detail)) | ForEach-Object { ConvertTo-CsvSafe "$_" }) -join ';'
        if (-not (Test-Path -LiteralPath $file)) {
            [IO.File]::WriteAllText($file, 'Czas;Serwer;Status;CzasSkanu;Krytyczne;Ostrzezenia;Rodzaj;Szczegoly' + [Environment]::NewLine, (New-Object Text.UTF8Encoding $true))
        }
        [IO.File]::AppendAllText($file, $line + [Environment]::NewLine, (New-Object Text.UTF8Encoding $false))
    } catch { Write-Log "Nie zapisano dziennika dostępności: $($_.Exception.Message)" 'WARN' 'Dziennik' }
    # Statystyka 30 dni (kolumna „Dostępność” w tabeli stanu serwerów)
    if ($script:AvailStats) {
        $k = $Name.ToLowerInvariant()
        $st = $script:AvailStats[$k]
        if (-not $st) { $st = @{ Seen = 0; Ok = 0; LastOk = ''; LastFail = ''; FailSince = '' }; $script:AvailStats[$k] = $st }
        $st.Seen++
        $t = '{0:yyyy-MM-dd HH:mm}' -f $now
        if ($Status -eq 'OK') { $st.Ok++; $st.LastOk = $t; $st.FailSince = '' }
        elseif ($Status -eq 'Brak połączenia') { $st.LastFail = $t; if (-not $st.FailSince) { $st.FailSince = $t } }
    }
    $script:HistoryCache.Remove($Name.ToLowerInvariant())
}
function Read-AvailabilityLines([int]$Months) {
    # Wiersze z ostatnich N plików miesięcznych (od najstarszego)
    $files = @()
    for ($i = $Months - 1; $i -ge 0; $i--) {
        $f = Join-Path $Config.LogDir ('Availability_{0:yyyyMM}.csv' -f (Get-Date).AddMonths(-$i))
        if (Test-Path -LiteralPath $f) { $files += $f }
    }
    foreach ($f in $files) {
        try { foreach ($l in [IO.File]::ReadLines($f, [Text.Encoding]::UTF8)) { if ($l -and -not $l.StartsWith('Czas;')) { $l } } } catch { }
    }
}
$script:HistoryCache = @{}
function Get-AvailabilityHistory([string]$Name) {
    # Historia skanów serwera (3 ostatnie miesiące, od najnowszych) – sekcja „Historia skanów i dostępność”
    $k = $Name.ToLowerInvariant()
    if ($script:HistoryCache.ContainsKey($k)) { return $script:HistoryCache[$k] }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($l in (Read-AvailabilityLines 3)) {
        $c = $l.Split(';')
        if ($c.Count -lt 8 -or -not [string]::Equals($c[1], $Name, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $flag = switch ($c[2]) { 'OK' { '' } 'Brak połączenia' { 'crit' } 'Limit czasu' { 'warn' } default { 'info' } }
        $rows.Add([pscustomobject]@{ Time = $c[0]; Status = $c[2]; DurationSec = $c[3]; Crit = $c[4]; Warn = $c[5]; Class = $c[6]; Detail = $c[7]; Flag = $flag })
    }
    $rows.Reverse()
    $res = [object[]]$rows.ToArray()
    $script:HistoryCache[$k] = $res
    $res
}
$script:AvailStats = $null
function Initialize-AvailabilityStats {
    # Jedno przejście po dzienniku z 3 miesięcy; potem aktualizowane przy każdym wyniku (Add-AvailabilityRecord)
    $stats = @{}
    $cut = (Get-Date).AddDays(-30).ToString('yyyy-MM-dd HH:mm:ss')
    foreach ($l in (Read-AvailabilityLines 3)) {
        $c = $l.Split(';')
        if ($c.Count -lt 8) { continue }
        $k = $c[1].ToLowerInvariant()
        $st = $stats[$k]
        if (-not $st) { $st = @{ Seen = 0; Ok = 0; LastOk = ''; LastFail = ''; FailSince = '' }; $stats[$k] = $st }
        # procent dostępności z 30 dni; „bez połączenia od” i „ostatni udany” z całego okresu dziennika (dłuższe awarie)
        if ([string]::CompareOrdinal($c[0], $cut) -ge 0) { $st.Seen++; if ($c[2] -eq 'OK') { $st.Ok++ } }
        $t = $c[0].Substring(0, [Math]::Min(16, $c[0].Length))
        if ($c[2] -eq 'OK') { $st.LastOk = $t; $st.FailSince = '' }
        elseif ($c[2] -eq 'Brak połączenia') { $st.LastFail = $t; if (-not $st.FailSince) { $st.FailSince = $t } }
    }
    $script:AvailStats = $stats
}
function Remove-OldLogs {
    $days = [int]$Config.LogRetentionDays
    if ($days -lt 1 -or -not (Test-Path -LiteralPath $Config.LogDir)) { return }
    $cut = (Get-Date).AddDays(-$days)
    $cutMonth = $cut.ToString('yyyyMM')
    foreach ($f in @(Get-ChildItem -LiteralPath $Config.LogDir -File -ErrorAction SilentlyContinue)) {
        try {
            if ($f.Name -match '^ServerReview_(\d{8})\.log$' -and $Matches[1] -lt $cut.ToString('yyyyMMdd')) { Remove-Item -LiteralPath $f.FullName -Force }
            elseif ($f.Name -match '^Availability_(\d{6})\.csv$' -and $Matches[1] -lt $cutMonth) { Remove-Item -LiteralPath $f.FullName -Force }
        } catch { Write-Log "Nie usunięto starego dziennika $($f.Name): $($_.Exception.Message)" 'WARN' 'Dziennik' }
    }
}
#endregion

#region ── Migawki: indeks plików, wczytywanie, porządki ───────────────────────
# Snapshots\RRRRMMDD_GGMMSS\<serwer>.json.gz (albo .json – starsze), <serwer>.offline.json – znacznik nieudanej próby.
# Indeks budowany raz (jedno przejście po folderach) i uzupełniany przy zapisie – bez przeszukiwania dysku dla każdego serwera.
$script:SnapIndex = @{}
function Get-SnapshotKey([string]$Name) { (Get-SafeName $Name).ToLowerInvariant() }
function Update-SnapshotIndex {
    $idx = @{}
    if (Test-Path -LiteralPath $Config.SnapshotDir) {
        foreach ($dir in @([IO.Directory]::GetDirectories($Config.SnapshotDir) | Sort-Object -Descending)) {
            $dn = [IO.Path]::GetFileName($dir)
            foreach ($f in [IO.Directory]::GetFiles($dir)) {
                $fn = [IO.Path]::GetFileName($f)
                if ($fn -notmatch '^(.+?)(\.offline)?\.json(\.gz)?$') { continue }
                $k = $Matches[1].ToLowerInvariant()
                if (-not $idx.ContainsKey($k)) { $idx[$k] = New-Object System.Collections.Generic.List[object] }
                $idx[$k].Add(@{ Path = $f; Dir = $dn; Offline = [bool]$Matches[2] })
            }
        }
    }
    $script:SnapIndex = $idx
}
function Add-SnapshotIndexEntry([string]$Name, [string]$Path, [bool]$Offline) {
    $k = Get-SnapshotKey $Name
    if (-not $script:SnapIndex.ContainsKey($k)) { $script:SnapIndex[$k] = New-Object System.Collections.Generic.List[object] }
    $dn = [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($Path))
    $list = $script:SnapIndex[$k]
    for ($i = $list.Count - 1; $i -ge 0; $i--) { if ($list[$i].Dir -eq $dn) { $list.RemoveAt($i) } }
    $list.Insert(0, @{ Path = $Path; Dir = $dn; Offline = $Offline })
}
function Get-SnapshotEntries([string]$Name) {
    $l = $script:SnapIndex[(Get-SnapshotKey $Name)]
    if ($l) { @($l) } else { @() }
}
function Get-LastOnlineSnapshot([string]$Name, [string]$ExcludeDir = '') {
    foreach ($e in (Get-SnapshotEntries $Name)) { if (-not $e.Offline -and $e.Dir -ne $ExcludeDir -and (Test-Path -LiteralPath $e.Path)) { return $e.Path } }
    ''
}
function Read-Snapshot([string]$Path) {
    try { ConvertFrom-ServerJson (Read-SnapshotText $Path) $script:ArrayKeys } catch { Write-Log "Nie udało się odczytać migawki $Path`: $($_.Exception.Message)" 'WARN' 'Migawki'; $null }
}
function Remove-OldSnapshots {
    # Limit liczymy dla KAŻDEGO serwera osobno (pojedyncze ponowne skany tworzą własne foldery). Błąd jednego pliku nie przerywa porządków.
    $keep = [int]$Config.SnapshotsToKeep
    $removed = 0
    foreach ($k in @($script:SnapIndex.Keys)) {
        $list = $script:SnapIndex[$k]
        # ostatnia udana migawka zostaje zawsze – długo niedostępny serwer nie traci ostatnich znanych danych (znaczniki niedostępności też się liczą do limitu)
        $lastOn = $null; foreach ($x in $list) { if (-not $x.Offline) { $lastOn = $x; break } }
        $i = $list.Count - 1
        while ($list.Count -gt $keep -and $i -ge 0) {
            $e = $list[$i]
            if ([object]::ReferenceEquals($e, $lastOn)) { $i--; continue }
            try { if (Test-Path -LiteralPath $e.Path) { Remove-Item -LiteralPath $e.Path -Force }; $removed++ }
            catch { Write-Log "Nie usunięto starej migawki $($e.Path): $($_.Exception.Message)" 'WARN' 'Migawki' }
            $list.RemoveAt($i)
            $i--
        }
    }
    if (Test-Path -LiteralPath $Config.SnapshotDir) {
        foreach ($dir in @([IO.Directory]::GetDirectories($Config.SnapshotDir))) {
            # tylko stare puste foldery – świeży może należeć do skanu, który jeszcze nic nie zapisał (np. drugiej instancji)
            try { if (([DateTime]::Now - [IO.Directory]::GetCreationTime($dir)).TotalSeconds -gt [int]$Config.ScanTimeoutSec -and -not [IO.Directory]::EnumerateFileSystemEntries($dir).GetEnumerator().MoveNext()) { [IO.Directory]::Delete($dir) } } catch { }
        }
    }
    if ($removed) { Write-Log "Usunięto stare migawki: $removed (limit $keep na serwer)" 'INFO' 'Migawki' }
}
function Test-WritableFolder([string]$Path) {
    try {
        New-Item -ItemType Directory -Force -Path $Path -ErrorAction Stop | Out-Null
        $t = Join-Path $Path ('.sr_write_test_{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($t, 'x'); [IO.File]::Delete($t)
        $true
    } catch { $false }
}
#endregion

#region ── Ustawienia użytkownika (okno Ustawienia, plik settings.json) ─────────
# Wartości domyślne są w bloku $Config na górze pliku. settings.json (obok skryptu) nadpisuje tylko pozycje z poniższej listy,
# a dodatkowo przechowuje wyciszone problemy, stan okna (Ui) i skrót PIN-u blokady (Lock).
$script:SettingDefs = @(
    @{ Group = 'Skan'; Key = 'EventDays';              Type = 'int';  Min = 1;   Max = 180;     Label = 'Zakres zdarzeń [dni]' }
    @{ Group = 'Skan'; Key = 'MaxEvents';              Type = 'int';  Min = 100; Max = 100000;  Label = 'Limit pobieranych zdarzeń (osobno dla każdego dziennika i rodzaju)' }
    @{ Group = 'Skan'; Key = 'IncludeWarnings';        Type = 'bool';                           Label = 'Uwzględniaj ostrzeżenia z dzienników System/Application (dużo szumu)' }
    @{ Group = 'Skan'; Key = 'ThrottleLimit';          Type = 'int';  Min = 1;   Max = 100;     Label = 'Ile serwerów skanować równolegle' }
    @{ Group = 'Skan'; Key = 'ServerTimeoutSec';       Type = 'int';  Min = 60;  Max = 7200;    Label = 'Limit czasu jednego serwera [s]' }
    @{ Group = 'Skan'; Key = 'ConnectTimeoutSec';      Type = 'int';  Min = 5;   Max = 300;     Label = 'Limit nawiązania połączenia WinRM [s]' }
    @{ Group = 'Skan'; Key = 'ScanTimeoutSec';         Type = 'int';  Min = 300; Max = 86400;   Label = 'Limit czasu całego skanu [s]' }
    @{ Group = 'Skan'; Key = 'Preflight';              Type = 'bool';                           Label = 'Szybki test portu WinRM 5985 przed skanem (wyłączone serwery są rozpoznawane w kilka sekund)' }
    @{ Group = 'Skan'; Key = 'RetryFailed';            Type = 'bool';                           Label = 'Po skanie ponów raz serwery z błędem, który może być chwilowy (restart, przeciążony WinRM)' }
    @{ Group = 'Progi: system i dyski'; Key = 'DiskWarnPct';       Type = 'int'; Min = 1; Max = 99;     Label = 'Dysk: ostrzeżenie poniżej [% wolnego]' }
    @{ Group = 'Progi: system i dyski'; Key = 'DiskCritPct';       Type = 'int'; Min = 1; Max = 99;     Label = 'Dysk: krytyczne poniżej [% wolnego]' }
    @{ Group = 'Progi: system i dyski'; Key = 'RamWarnPct';        Type = 'int'; Min = 1; Max = 100;    Label = 'RAM: ostrzeżenie od [%]' }
    @{ Group = 'Progi: system i dyski'; Key = 'CommitWarnPct';     Type = 'int'; Min = 1; Max = 100;    Label = 'Pamięć wirtualna (commit): ostrzeżenie od [%]' }
    @{ Group = 'Progi: system i dyski'; Key = 'UptimeWarnDays';    Type = 'int'; Min = 1; Max = 3650;   Label = 'Uptime: ostrzeżenie powyżej [dni]' }
    @{ Group = 'Progi: system i dyski'; Key = 'PatchWarnDays';     Type = 'int'; Min = 1; Max = 3650;   Label = 'Aktualizacje: ostrzeżenie po [dniach]' }
    @{ Group = 'Progi: system i dyski'; Key = 'SupportWarnDays';   Type = 'int'; Min = 1; Max = 3650;   Label = 'Koniec wsparcia systemu: uprzedzaj [dni] wcześniej' }
    @{ Group = 'Progi: system i dyski'; Key = 'TimeSkewWarnSec';   Type = 'int'; Min = 1; Max = 86400;  Label = 'Różnica czasu: ostrzeżenie od [s]' }
    @{ Group = 'Progi: system i dyski'; Key = 'TimeSkewCritSec';   Type = 'int'; Min = 1; Max = 86400;  Label = 'Różnica czasu: krytyczne od [s]' }
    @{ Group = 'Progi: system i dyski'; Key = 'DiskWearWarnPct';   Type = 'int'; Min = 1; Max = 100;    Label = 'Zużycie SSD: ostrzeżenie od [%]' }
    @{ Group = 'Progi: system i dyski'; Key = 'DiskRetryWarn';     Type = 'int'; Min = 1; Max = 100000; Label = 'Ponowienia/resety I/O dysku: ostrzeżenie od [liczba]' }
    @{ Group = 'Progi: system i dyski'; Key = 'BugCheckCritCount'; Type = 'int'; Min = 1; Max = 1000;   Label = 'BSOD: krytyczne od [liczba w okresie]' }
    @{ Group = 'Progi: bezpieczeństwo'; Key = 'CertWarnDays';       Type = 'int'; Min = 1; Max = 3650;    Label = 'Certyfikaty: ostrzeżenie na [dni] przed wygaśnięciem' }
    @{ Group = 'Progi: bezpieczeństwo'; Key = 'FailedLogonWarn';    Type = 'int'; Min = 1; Max = 1000000; Label = 'Nieudane logowania: ostrzeżenie od [liczba]' }
    @{ Group = 'Progi: bezpieczeństwo'; Key = 'RecentSoftwareDays'; Type = 'int'; Min = 1; Max = 3650;    Label = 'Nowe oprogramowanie: z ostatnich [dni]' }
    @{ Group = 'Hyper-V'; Key = 'CheckpointWarnDays'; Type = 'int'; Min = 1;  Max = 3650; Label = 'Checkpoint: ostrzeżenie po [dniach]' }
    @{ Group = 'Hyper-V'; Key = 'HostRamWarnPct';     Type = 'int'; Min = 30; Max = 300;  Label = 'Host: RAM przydzielony działającym maszynom – ostrzeżenie od [% RAM hosta]' }
    @{ Group = 'Hyper-V'; Key = 'VcpuRatioWarn';      Type = 'int'; Min = 1;  Max = 64;   Label = 'Host: vCPU działających maszyn na procesor logiczny – ostrzeżenie powyżej' }
    @{ Group = 'Hyper-V'; Key = 'HvHostMinFreeGB';    Type = 'int'; Min = 1;  Max = 512;  Label = 'Host: ostrzeżenie, gdy wolnej pamięci zostaje mniej niż [GB] (zamiast progu RAM %)' }
    @{ Group = 'Hyper-V'; Key = 'VmOffInfoDays';      Type = 'int'; Min = 1;  Max = 3650; Label = 'Maszyna wyłączona dłużej niż [dni] = prawdopodobnie wycofana (informacja zamiast ostrzeżenia)' }
    @{ Group = 'Diagnostyka i Active Directory'; Key = 'DiagTimeoutMs';  Type = 'int';  Min = 200; Max = 15000; Label = 'Diagnoza niedostępności: limit próby DNS/ping/portu [ms]' }
    @{ Group = 'Diagnostyka i Active Directory'; Key = 'DiagPorts';      Type = 'intlist';                      Label = 'Diagnoza niedostępności: sprawdzane porty TCP (jeden na linię)' }
    @{ Group = 'Diagnostyka i Active Directory'; Key = 'AdSearchBase';   Type = 'string';                       Label = '„Pobierz z AD”: jednostka organizacyjna (DN), puste = cała domena' }
    @{ Group = 'Diagnostyka i Active Directory'; Key = 'AdInactiveDays'; Type = 'int';  Min = 1;   Max = 3650;  Label = '„Pobierz z AD”: pomijaj konta nieaktywne dłużej niż [dni]' }
    @{ Group = 'Dane, dziennik i blokada'; Key = 'SnapshotsToKeep';   Type = 'int';  Min = 1; Max = 10000; Label = 'Ile migawek (skanów) każdego serwera przechowywać' }
    @{ Group = 'Dane, dziennik i blokada'; Key = 'CompressSnapshots'; Type = 'bool';                       Label = 'Kompresuj migawki (.json.gz – ok. 10x mniej miejsca)' }
    @{ Group = 'Dane, dziennik i blokada'; Key = 'LogRetentionDays';  Type = 'int';  Min = 7; Max = 3650;  Label = 'Przechowuj dziennik operacji i dostępności [dni]' }
    @{ Group = 'Dane, dziennik i blokada'; Key = 'LockIdleMinutes';   Type = 'int';  Min = 0; Max = 240;   Label = 'Blokada programu po bezczynności [min] (0 = wyłączona; wymaga PIN-u)' }
    @{ Group = 'Listy'; Key = 'Folders';                Type = 'list';    Label = 'Foldery sprawdzane na serwerach (jeden na linię, zmienne środowiskowe dozwolone)' }
    @{ Group = 'Listy'; Key = 'IgnoredStoppedServices'; Type = 'list';    Label = 'Usługi automatyczne, których zatrzymanie jest OK (jedna na linię, wildcardy *)' }
    @{ Group = 'Listy'; Key = 'ExposedPorts';           Type = 'intlist'; Label = 'Porty wrażliwe dla sekcji Ekspozycja (jeden na linię)' }
    @{ Group = 'Listy'; Key = 'IgnoredWmiConsumers';    Type = 'list';    Label = 'Subskrypcje WMI traktowane jako systemowe (jedna na linię)' }
)
$script:SectionGroups = [ordered]@{
    'System i stabilność'  = @('Disks', 'DiskHealth', 'Crashes', 'Events', 'Restarts', 'Downtime', 'EventLogs', 'Updates', 'Software')
    'Bezpieczeństwo'       = @('Hardening', 'SecurityEvents', 'AuditPolicy', 'Exposure', 'Persistence', 'Admins', 'LocalUsers', 'Certificates', 'Shares', 'Autostart')
    'Usługi, sieć i pliki' = @('Services', 'Tasks', 'Network', 'Listening', 'Connections', 'Sessions', 'Folders')
    'Role serwera'         = @('DomainController', 'HyperV', 'Checkpoints', 'VMStorage', 'Cluster')
}
# Stan okna i blokady – zapisywane razem z ustawieniami, ale nie są „ustawieniami skanu”
$script:UiState = [ordered]@{ WindowWidth = 1540; WindowHeight = 940; WindowMaximized = $false; LogVisible = $false; LogHeight = 200 }
$script:LockCfg = [ordered]@{ Hash = ''; Salt = ''; Length = 0; RequireAtStart = $true }

function ConvertTo-Hashtable($Object) {
    $h = @{}
    if ($null -eq $Object) { return $h }
    if ($Object -is [System.Collections.IDictionary]) { foreach ($k in $Object.Keys) { $h["$k"] = $Object[$k] }; return $h }
    foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = $p.Value }
    $h
}
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
            elseif ($d.Type -eq 'string') { $Config[$d.Key] = "$v".Trim() }
            elseif ($d.Type -eq 'list') { $Config[$d.Key] = [string[]]@(@($v) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
            elseif ($d.Type -eq 'intlist') { $Config[$d.Key] = [int[]]@(@($v) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | ForEach-Object { [int]$_ }) }
            else { $n = [int]$v; if ($n -ge $d.Min -and $n -le $d.Max) { $Config[$d.Key] = $n } }
        } catch {}
    }
    if ($Values.ContainsKey('SkipSections')) { $Config.SkipSections = [string[]]@(@($Values.SkipSections) | Where-Object { $script:ArrayKeys -contains $_ }) }
    # Limit jednego serwera musi przekraczać limit połączenia (inaczej limit czasu przerywa samo łączenie)
    if ($Config.ServerTimeoutSec -le $Config.ConnectTimeoutSec) { $Config.ServerTimeoutSec = $Config.ConnectTimeoutSec + 60 }
}
function ConvertTo-IgnoreRules($List) {
    @(foreach ($r in @($List)) {
        if ($null -eq $r) { continue }
        $h = ConvertTo-Hashtable $r
        if (-not "$($h['Key'])") { continue }
        [pscustomobject]@{ Server = $(if ("$($h['Server'])") { "$($h['Server'])" } else { '*' }); Key = "$($h['Key'])"; Text = "$($h['Text'])"; Added = "$($h['Added'])"; By = "$($h['By'])" }
    })
}
function Update-IgnoreSet {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Config.IgnoredIssues)) { if ($r) { [void]$set.Add("$($r.Server)|$($r.Key)") } }
    $script:IgnoreSet = $set
}
function Test-IssueIgnored([string]$ServerKey, [string]$IssueKey) {
    $script:IgnoreSet.Contains("$ServerKey|$IssueKey") -or $script:IgnoreSet.Contains("*|$IssueKey")
}
function Import-UserSettings {
    $script:SettingsWarning = $null
    if (-not (Test-Path -LiteralPath $Config.SettingsFile)) { Update-IgnoreSet; return }
    try {
        $j = [IO.File]::ReadAllText($Config.SettingsFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
        $h = ConvertTo-Hashtable $j
        Set-ConfigFromValues $h
        if ($h.ContainsKey('IgnoredIssues')) { $Config.IgnoredIssues = @(ConvertTo-IgnoreRules $h.IgnoredIssues) }
        if ($h.ContainsKey('Ui')) {
            $u = ConvertTo-Hashtable $h.Ui
            foreach ($k in @($script:UiState.Keys)) { if ($u.ContainsKey($k) -and $null -ne $u[$k]) { $script:UiState[$k] = $u[$k] } }
            try { $script:UiState.WindowWidth = [Math]::Max(1180, [int]$script:UiState.WindowWidth); $script:UiState.WindowHeight = [Math]::Max(680, [int]$script:UiState.WindowHeight) } catch { $script:UiState.WindowWidth = 1540; $script:UiState.WindowHeight = 940 }
            try { $script:UiState.LogHeight = [Math]::Min(700, [Math]::Max(90, [int]$script:UiState.LogHeight)) } catch { $script:UiState.LogHeight = 200 }
            $script:UiState.WindowMaximized = [bool]$script:UiState.WindowMaximized
            $script:UiState.LogVisible = [bool]$script:UiState.LogVisible
        }
        if ($h.ContainsKey('Lock')) {
            $l = ConvertTo-Hashtable $h.Lock
            $script:LockCfg.Hash = "$($l['Hash'])"; $script:LockCfg.Salt = "$($l['Salt'])"
            try { $script:LockCfg.Length = [int]$l['Length'] } catch { $script:LockCfg.Length = 0 }
            if ($l.ContainsKey('RequireAtStart')) { $script:LockCfg.RequireAtStart = [bool]$l['RequireAtStart'] }
            if ($script:LockCfg.Length -lt 4 -or $script:LockCfg.Length -gt 8 -or -not $script:LockCfg.Salt) { $script:LockCfg.Hash = '' }
        }
    }
    catch { $script:SettingsWarning = "Nie udało się wczytać ustawień z $($Config.SettingsFile): $($_.Exception.Message). Użyto wartości domyślnych." }
    Update-IgnoreSet
}
function Save-UserSettings {
    $o = [ordered]@{ Saved = (Get-Date -Format 's'); Version = $script:AppVersion }
    foreach ($d in $script:SettingDefs) { $o[$d.Key] = $Config[$d.Key] }
    $o.SkipSections  = [string[]]@($Config.SkipSections | Where-Object { $_ })
    $o.IgnoredIssues = @($Config.IgnoredIssues)
    $o.Ui            = [pscustomobject]$script:UiState
    $o.Lock          = [pscustomobject]$script:LockCfg
    $json = [pscustomobject]$o | ConvertTo-Json -Depth 4
    $tmp = "$($Config.SettingsFile).tmp"
    [IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding $false))
    if (Test-Path -LiteralPath $Config.SettingsFile) { [IO.File]::Delete($Config.SettingsFile) }
    [IO.File]::Move($tmp, $Config.SettingsFile)
}
$script:IgnoreSet = $null
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
        $rank = @{ crit = 0; warn = 1; info = 2; muted = 3 }
        $cur = "$($row.Flag)"
        if (-not $cur -or $rank[$f] -lt $rank[$cur]) { $row.Flag = $f }
    }

    if ($D.PSObject.Properties['Unsupported'] -and $D.Unsupported) {
        AddI 'Info' 'Łączność' "Nie skanowano: $($D.Unsupported)" 'Issues'
        $D | Add-Member -NotePropertyName _Changes -NotePropertyValue @() -Force
        return , $list.ToArray()
    }
    if ($D.Offline) {
        # Niedostępność: przyczyna z diagnostyki (DNS, ping, porty, AD, błąd WinRM) + stan maszyny wirtualnej na hoście Hyper-V
        $dg    = if ($D.PSObject.Properties['Diag']) { $D.Diag } else { $null }
        $cls   = if ($dg) { "$($dg.Class)" } else { '' }
        $cause = if ($dg -and $dg.Cause) { "$($dg.Cause)" } else { Get-ShortText $D.Error 300 }
        $vm    = Find-VmForServer $Name $D
        $sev   = 'Krytyczny'
        $msg   = "Brak połączenia: $cause."
        if ($cls -eq 'Timeout') { $sev = 'Ostrzeżenie'; $msg = "Skan przerwany – przekroczono limit czasu ($($C.ServerTimeoutSec) s); brak aktualnych danych." }
        elseif ($cls -eq 'Remote') { $sev = 'Ostrzeżenie'; $msg = "$cause." }
        $vmOff = $vm -and "$($vm.Row.State)" -notlike 'Running*'
        if ($vmOff) {
            $vst = "$($vm.Row.State)"
            $since = "$($vm.Row.PSObject.Properties['StateSince'].Value)"
            $t = [datetime]::MinValue
            $long = $since -and [datetime]::TryParseExact($since, 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$t) -and ((Get-Date) - $t).TotalDays -gt $C.VmOffInfoDays
            $sev = if ($vst -like '*Critical' -or $vst -eq 'Paused') { 'Krytyczny' } elseif ($vst -eq 'Off' -and $long) { 'Info' } else { 'Ostrzeżenie' }
            $msg = "Maszyna wirtualna $($vm.Row.Name) jest $(Get-VmStateText $vst)$(if ($since) { " od $since" }) na hoście $($vm.HostDisplay) (stan z $($vm.ScannedAt)) – dlatego serwer nie odpowiada."
            if ($vst -eq 'Paused') { $msg += ' Wstrzymanie to zwykle brak miejsca na wolumenie z dyskami maszyny.' }
            elseif ($vst -like '*Critical') { $msg += ' Hyper-V nie ma dostępu do plików maszyny (wolumen/CSV niedostępny lub pełny).' }
            elseif ($long) { $msg += " Wyłączona ponad $($C.VmOffInfoDays) dni – prawdopodobnie wycofana; usuń serwer z listy albo go wycisz." }
        } elseif ($vm) {
            $hb = "$($vm.Row.Heartbeat)"
            if ($hb -match '^(LostCommunication|NoContact|Error)') { $msg += " Maszyna działa na hoście $($vm.HostDisplay), ale system gościa nie odpowiada (heartbeat: $hb) – możliwe zawieszenie systemu albo awaria usług integracji." }
            else { $msg += " Maszyna działa na hoście $($vm.HostDisplay)$(if ($hb) { " (heartbeat: $hb)" })." }
        }
        # host Hyper-V, na którym maszyna ostatnio działała, też nie odpowiada – przyczyną jest najpewniej host (jeden problem krytyczny na hoście)
        $hostDown = $false
        if (-not $vm -and $cls -notin 'Timeout', 'Remote') {
            $hk = Find-ServerKey (Get-LastHvHost $D)
            if ($hk -and $hk -ne $Name -and (Test-NetworkDown $script:Data[$hk])) {
                $hostDown = $true; $sev = 'Ostrzeżenie'
                $msg += " Host Hyper-V $(Get-DisplayName $hk), na którym ostatnio działała ta maszyna, też nie odpowiada – zacznij od hosta."
            }
        }
        if ($dg -and $dg.Notes) { $msg += " Uwagi: $($dg.Notes)." }
        $av = if ($script:AvailStats) { $script:AvailStats[$Name.ToLowerInvariant()] } else { $null }
        if ($av -and $av.FailSince) { $msg += " Bez połączenia od $($av.FailSince)$(if ($av.LastOk) { ", ostatni udany skan $($av.LastOk)" })." }
        elseif ($D.PSObject.Properties['_Last'] -and $D._Last) { $msg += " Ostatnie dane z $($D._Last.ScannedAt)." }
        AddI $sev 'Łączność' $msg 'Diagnostics'
        if ($dg -and $dg.Remedy -and -not $vmOff -and -not $hostDown) { AddI 'Info' 'Łączność' "Zalecenie: $($dg.Remedy)" 'Diagnostics' }
        $D | Add-Member -NotePropertyName _Changes -NotePropertyValue @() -Force
        return , @($list | Sort-Object Rank)
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
        # Host Hyper-V: pamięć przydzielona maszynom to „zajęty” RAM z założenia – liczy się zapas wolnej pamięci, nie procent
        if ($s.IsHyperV -and $s.PSObject.Properties['HvRamAssignedGB'] -and "$($s.HvRamAssignedGB)" -ne '' -and [double]$s.HvRamAssignedGB -gt 0) {
            # wolny RAM wprost z kolektora (procent jest zaokrąglony do 1% – na dużym hoście to kilka GB)
            $freeGB = if ($s.PSObject.Properties['RamFreeGB'] -and "$($s.RamFreeGB)" -ne '') { [math]::Round([double]$s.RamFreeGB, 1) } else { [math]::Round([double]$s.RamGB * (100 - [double]$s.RamUsedPct) / 100, 1) }
            $rootGB = [math]::Round([double]$s.RamGB - $freeGB - [double]$s.HvRamAssignedGB, 1)
            if ($freeGB -lt $C.HvHostMinFreeGB) { AddI 'Ostrzeżenie' 'Hyper-V' "Na hoście zostało $freeGB GB wolnej pamięci (maszyny: $($s.HvRamAssignedGB) GB, system hosta: ok. $rootGB GB z $($s.RamGB) GB) – kolejne maszyny i migracje się nie uruchomią" 'HvHost' }
        }
        elseif ($s.RamUsedPct -ge $C.RamWarnPct) { AddI 'Ostrzeżenie' 'Zasoby' "Wysokie użycie RAM: $($s.RamUsedPct)% z $($s.RamGB) GB" 'System' }
        if ($s.IsHyperV -and $s.PSObject.Properties['HvVmms'] -and "$($s.HvVmms)" -and "$($s.HvVmms)" -ne 'Running') { AddI 'Ostrzeżenie' 'Hyper-V' "Usługa zarządzania Hyper-V (vmms) nie działa ($($s.HvVmms)) – maszyny działają, ale nie da się nimi zarządzać ani ich migrować" 'HvHost' }
    }
    # Ostatni skan nie powiódł się (limit czasu), ale są wcześniejsze dane – pokazujemy je z ostrzeżeniem
    if ($D.PSObject.Properties['_ScanNote'] -and $D._ScanNote) { AddI 'Ostrzeżenie' 'Skan' "$($D._ScanNote)" 'History' }

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
    # Kernel-Power 41 i EventLog 6008 omawia sekcja Restarty (jeden problem na serwer zamiast kilku)
    foreach ($r in @($D.Events | Where-Object { $_.Level -eq 'Krytyczny' -and -not (("$($_.Source)" -eq 'Microsoft-Windows-Kernel-Power' -and "$($_.Id)" -eq '41') -or ("$($_.Source)" -eq 'EventLog' -and "$($_.Id)" -eq '6008')) } | Select-Object -First 8)) {
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
    # Jedno nieoczekiwane wyłączenie zapisuje 41 i 6008 – zdarzenia w odstępie do 5 minut liczymy jako jeden incydent
    $unexp = @($D.Restarts | Where-Object { [int]$_.Id -in 6008, 41 } | Sort-Object Time)
    if ($unexp.Count) {
        $inc = 0; $lastT = $null
        foreach ($r in $unexp) {
            SetFlag $r 'warn'
            $t = $null; try { $t = [datetime]::ParseExact("$($r.Time)", 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) } catch {}
            if (-not $t -or -not $lastT -or ($t - $lastT).TotalMinutes -gt 5) { $inc++ }
            if ($t) { $lastT = $t }
        }
        AddI 'Ostrzeżenie' 'Stabilność' "Nieoczekiwane wyłączenia w $days dni: $inc (ostatnio $($unexp[-1].Time)) – sprawdź sekcję Przestoje" 'Restarts'
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
    # (tylko IPv4 – globalne adresy IPv6 bywają wewnętrzne; 100.64.0.0/10 to CGNAT, nie internet)
    $privRx   = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.|0\.0\.0\.0|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)'
    $pubFails = @($fails | Where-Object { $ip = @((("$($_.Source)" -replace '^::ffff:', '').Trim()) -split '\s+')[0]; $ip -match '^(\d{1,3}\.){3}\d{1,3}$' -and $ip -notmatch $privRx })
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
    # Maszyny: stany wymagające uwagi, konfiguracja. Repliki (Hyper-V Replica) są z założenia wyłączone – pomijane.
    # Linux nie jest skanowany – bez ostrzeżeń o heartbeat i usługach integracji (zostają stan, replikacja, checkpointy, dyski).
    $vmOffDays = [int]$C.VmOffInfoDays
    $offRows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $D.HyperV) {
        if (-not $r) { continue }
        $st  = "$($r.State)"
        $lin = "$($r.PSObject.Properties['Linux'].Value)" -eq 'Tak'
        $rep = "$($r.PSObject.Properties['ReplicationMode'].Value)" -match 'Replica'
        $since = "$($r.PSObject.Properties['StateSince'].Value)"
        $sinceTxt = if ($since) { " od $since" } else { '' }
        if ($rep) { SetFlag $r 'muted'; if ($r.Replication -in 'Critical', 'Warning') { AddI 'Ostrzeżenie' 'Hyper-V' "Replika VM $($r.Name): stan replikacji $($r.Replication)" 'HyperV'; SetFlag $r 'warn' }; continue }
        if ($lin) { SetFlag $r 'muted' }
        if ($st -like '*Critical') { AddI 'Krytyczny' 'Hyper-V' "Maszyna $($r.Name): stan $st$sinceTxt – Hyper-V nie ma dostępu do jej plików (wolumen/CSV niedostępny lub pełny)" 'HyperV'; SetFlag $r 'crit' }
        elseif ($st -eq 'Paused') { AddI 'Krytyczny' 'Hyper-V' "Maszyna $($r.Name) wstrzymana$sinceTxt – najczęściej brak miejsca na wolumenie z jej dyskami" 'HyperV'; SetFlag $r 'crit' }
        elseif ($st -eq 'Saved') { AddI 'Ostrzeżenie' 'Hyper-V' "Maszyna $($r.Name) w stanie zapisanym (Saved)$sinceTxt" 'HyperV'; SetFlag $r 'warn' }
        elseif ($st -eq 'Off') { $offRows.Add($r); if (-not $lin) { SetFlag $r 'info' } }
        if (-not $lin -and $st -like 'Running*' -and [double]$r.UptimeDays -gt 0.01 -and "$($r.Heartbeat)" -match '^(LostCommunication|NoContact|Error)') {
            AddI 'Ostrzeżenie' 'Hyper-V' "Maszyna $($r.Name) działa, ale nie odpowiada na heartbeat ($($r.Heartbeat)) – system gościa może być zawieszony" 'HyperV'; SetFlag $r 'warn'
        }
        if ($r.Replication -in 'Critical', 'Warning') { AddI 'Ostrzeżenie' 'Hyper-V' "Replikacja VM $($r.Name): $($r.Replication)" 'HyperV'; SetFlag $r 'warn' }
        if ($st -like 'Running*' -and "$($r.PSObject.Properties['Switch'].Value)" -match 'odłączona') { AddI 'Ostrzeżenie' 'Hyper-V' "Maszyna $($r.Name) ma kartę sieciową niepodłączoną do przełącznika wirtualnego" 'HyperV'; SetFlag $r 'warn' }
        if ($st -like 'Running*' -and "$($r.PSObject.Properties['AutoStart'].Value)" -eq 'Nothing' -and "$($r.PSObject.Properties['Clustered'].Value)" -ne 'Tak') { AddI 'Ostrzeżenie' 'Hyper-V' "Maszyna $($r.Name) nie wystartuje sama po restarcie hosta (akcja przy starcie: Nothing)" 'HyperV'; SetFlag $r 'warn' }
        if ("$($r.PSObject.Properties['AutoStop'].Value)" -eq 'TurnOff' -and -not $lin) { AddI 'Ostrzeżenie' 'Hyper-V' "Maszyna $($r.Name): przy wyłączeniu hosta zostanie odcięta od zasilania (akcja przy wyłączeniu: TurnOff)" 'HyperV'; SetFlag $r 'warn' }
        $mx = "$($r.PSObject.Properties['MemMaxGB'].Value)"; $dm = "$($r.PSObject.Properties['MemDemandGB'].Value)"
        if ($st -like 'Running*' -and $mx -and $dm -and [double]$dm -gt [double]$mx) { AddI 'Ostrzeżenie' 'Hyper-V' "Maszyna $($r.Name): pamięć dynamiczna na maksimum (zapotrzebowanie $dm GB > maks. $mx GB)" 'HyperV'; SetFlag $r 'warn' }
        $cd = "$($r.PSObject.Properties['ChainDepth'].Value)"
        if ($cd -and [int]$cd -gt 3) { AddI 'Ostrzeżenie' 'Hyper-V' "Maszyna $($r.Name): łańcuch dysków różnicowych ma $cd poziomów (checkpointy) – spada wydajność, scalanie potrwa długo" 'HyperV'; SetFlag $r 'warn' }
        $ver = $null
        if ([version]::TryParse("$($r.Version)", [ref]$ver) -and $ver -lt [version]'8.0') { AddI 'Info' 'Hyper-V' "Maszyna $($r.Name): wersja konfiguracji $($r.Version) – Windows Server 2022/2025 jej nie uruchomi (Update-VMVersion przed migracją)" 'HyperV'; SetFlag $r 'info' }
        if (-not $lin -and $st -like 'Running*' -and "$($r.IntegrationServices)" -match 'Update|Aktualiz|wymag') { SetFlag $r 'info' }
    }
    if ($offRows.Count) {
        $old = @($offRows | Where-Object { $sv = "$($_.PSObject.Properties['StateSince'].Value)"; $t = [datetime]::MinValue; $sv -and [datetime]::TryParseExact($sv, 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$t) -and ((Get-Date) - $t).TotalDays -gt $vmOffDays })
        AddI 'Info' 'Hyper-V' ("Wyłączone maszyny ($($offRows.Count)): " + (Join-Short ($offRows | ForEach-Object { $_.Name }) 5) + $(if ($old.Count) { "; wyłączone ponad $vmOffDays dni (do wycofania?): $(Join-Short ($old | ForEach-Object { $_.Name }) 4)" })) 'HyperV'
    }
    foreach ($r in @($D.VMStorage | Where-Object { "$($_.PSObject.Properties['OnSystemDrive'].Value)" -eq 'Tak' })) {
        AddI 'Ostrzeżenie' 'Hyper-V' "Dysk maszyny $($r.VM) leży na dysku systemowym hosta ($($r.Disk)) – rosnący dysk może zapełnić dysk systemowy" 'VMStorage'; SetFlag $r 'warn'
    }
    foreach ($r in $D.Checkpoints) {
        $ct = "$($r.Type)"
        if ($ct -like '*Replica') { SetFlag $r 'muted'; continue }   # punkty odzyskiwania repliki rotują same
        if ($ct -eq 'Recovery' -and [double]$r.AgeDays -ge 1) { AddI 'Ostrzeżenie' 'Hyper-V' "Checkpoint typu Recovery na $($r.VM) ma $($r.AgeDays) dni – pozostałość po kopii zapasowej, sprawdź backup" 'Checkpoints'; SetFlag $r 'warn'; continue }
        if ([double]$r.AgeDays -gt $C.CheckpointWarnDays) { AddI 'Ostrzeżenie' 'Hyper-V' "Checkpoint '$($r.Name)' na $($r.VM) ma $([math]::Floor([double]$r.AgeDays)) dni" 'Checkpoints'; SetFlag $r 'warn' }
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
        $ti = Get-TimeOffsetIssue $Name $s
        if ($ti) { $list.Add($ti) }
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
            $endTxt = "$($C.OsSupportEnd[$bn])"
            $endDt = [datetime]::MinValue
            if ([datetime]::TryParseExact($endTxt, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$endDt)) {
                $left = [int]($endDt - (Get-Date)).TotalDays
                if ($left -lt 0) { AddI 'Krytyczny' 'System' "$($s.OS): koniec wsparcia $endTxt – system nie dostaje poprawek bezpieczeństwa (chyba że ma wykupione ESU)" 'System' }
                elseif ($left -le $C.SupportWarnDays) { AddI 'Info' 'System' "$($s.OS): koniec wsparcia $endTxt (za $left dni)" 'System' }
            }
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
    $clustered = $s -and $s.PSObject.Properties['HvCluster'] -and $s.HvCluster
    foreach ($g in @($D.VMStorage | Where-Object { $_.Volume -and "$($_.VolumeFreeGB)" -ne '' -and -not ($clustered -and "$($_.Volume)" -match '^[A-Za-z]:\\ClusterStorage\\') } | Group-Object Volume)) {
        $growth = [math]::Round([double](@($g.Group) | Measure-Object GrowthGB -Sum).Sum, 1)
        $free   = [double]@($g.Group)[0].VolumeFreeGB
        if ($growth -gt $free) {
            AddI 'Ostrzeżenie' 'Hyper-V' "Dyski dynamiczne VM na $($g.Name) mogą urosnąć o $growth GB, a wolne jest $free GB – zapełnienie wolumenu wstrzyma maszyny" 'VMStorage'
            foreach ($r in $g.Group) { if ([double]$r.GrowthGB -gt 0) { SetFlag $r 'warn' } }
        }
    }

    # Hyper-V: pojemność hosta (wiersze sekcji „Hyper-V: host i pojemność” budowane z danych System)
    $hvRows = @(Get-HvHostRows $D)
    $D | Add-Member -NotePropertyName _HvHost -NotePropertyValue $hvRows -Force
    foreach ($r in $hvRows) {
        if ($r.Status -eq 'Uwaga') { AddI 'Ostrzeżenie' 'Hyper-V' "$($r.Check): $($r.Value)" 'HvHost'; SetFlag $r 'warn' }
        elseif ($r.Status -eq 'Info') { SetFlag $r 'info' }
    }

    # Klaster: tylko kolorowanie wierszy – problemy klastra zgłaszane raz na klaster (Update-VmIndex), nie z każdego węzła
    foreach ($r in @($D.PSObject.Properties['Cluster'].Value)) {
        if (-not $r) { continue }
        switch ("$($r.Type)") {
            'Węzeł'   { if ("$($r.State)" -ne 'Up') { SetFlag $r $(if ("$($r.State)" -eq 'Down') { 'crit' } else { 'warn' }) } }
            'CSV'     { if ("$($r.State)" -ne 'Online') { SetFlag $r 'crit' } elseif ("$($r.Detail)" -match 'konserwacji') { SetFlag $r 'info' } }
            'Rola VM' { SetFlag $r $(if ("$($r.State)" -eq 'Failed') { 'crit' } elseif ("$($r.State)" -eq 'PartialOnline') { 'warn' } else { 'info' }) }
            'Kworum'  { if ("$($r.State)" -ne 'Online') { SetFlag $r 'warn' } }
        }
    }

    # Przestoje (okna wyłączenie → start)
    $dt = @($D.Downtime)
    if ($dt.Count) {
        $known = @($dt | Where-Object { "$($_.DowntimeMin)" -ne '' })
        $tot = [math]::Round([double](@($known | ForEach-Object { [double]$_.DowntimeMin }) | Measure-Object -Sum).Sum)
        $bad = @($dt | Where-Object { "$($_.Type)" -match 'Nieoczekiwane|Awaria' })
        AddI 'Info' 'Dostępność' "Przestoje w $days dni: $($dt.Count) (łącznie ok. $tot min$(if ($bad.Count) { ", w tym nieoczekiwane: $($bad.Count)" }))$(if ($dt[0].Initiator) { "; ostatni zainicjował: $($dt[0].Initiator)" })" 'Downtime'
        foreach ($r in $bad) { SetFlag $r 'warn' }
        foreach ($r in @($dt | Where-Object { "$($_.DowntimeMin)" -ne '' -and [double]$_.DowntimeMin -ge 60 })) { SetFlag $r 'info' }
    }

    # Czas skanu: blisko limitu jednego serwera
    if ($D.DurationSec -and [double]$D.DurationSec -ge 0.7 * $C.ServerTimeoutSec) {
        $slow = Join-Short (@($D.Timings) | Select-Object -First 3 | ForEach-Object { "$($_.Section) $($_.Sec) s" }) 3
        AddI 'Info' 'Skan' "Zbieranie danych trwało $($D.DurationSec) s (limit $($C.ServerTimeoutSec) s); najdłużej: $slow" 'Timings'
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
    # migawka z innej wersji kolektora (np. sprzed aktualizacji programu) ma inny format wierszy – porównanie dałoby fałszywe „Nowe/Usunięte”
    $verD = "$($D.PSObject.Properties['CollectorVersion'].Value)"; $verP = if ($Prev) { "$($Prev.PSObject.Properties['CollectorVersion'].Value)" } else { '' }
    if ($Prev -and -not $Prev.Offline -and $verD -ne $verP) {
        $changes.Add([pscustomobject]@{ Section = '(wszystkie)'; Change = 'Pominięto'; Item = 'Poprzedni skan wykonała inna wersja programu – zmiany będą pokazywane od następnego skanu'; Flag = '' })
    }
    elseif ($Prev -and -not $Prev.Offline) {
        foreach ($k in $script:DiffDefs.Keys) {
            $def = $script:DiffDefs[$k]
            # nie porównuj sekcji pominiętej w którymś ze skanów ani sekcji, której nie było w starszej migawce
            if (@($D.Skipped) -contains $k -or @($Prev.Skipped) -contains $k) { continue }
            # sekcja, której zbieranie się nie udało (pusta tablica), dawałaby fałszywe „Nowe”/„Usunięte”
            if (@($D.PSObject.Properties['Failed'].Value) -contains $k -or @($Prev.PSObject.Properties['Failed'].Value) -contains $k) { continue }
            if (@($Prev._Present) -notcontains $k -or @($D._Present) -notcontains $k) { continue }
            $curRows = @($D.$k); $oldRows = @($Prev.$k)
            if ($def.Filter) { $curRows = @($curRows | Where-Object $def.Filter); $oldRows = @($oldRows | Where-Object $def.Filter) }
            $oldSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($r in $oldRows) { [void]$oldSet.Add((& $def.KeyFn $r)) }
            $curSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
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
function Get-DiagClassText([string]$Class) {
    switch ($Class) {
        'Dns' { 'DNS' } 'Offline' { 'Nie odpowiada' } 'WinRM' { 'WinRM nie działa' } 'Firewall' { 'Zapora' } 'Auth' { 'Uprawnienia' }
        'Kerberos' { 'Kerberos' } 'TrustedHosts' { 'TrustedHosts' } 'Limit' { 'Limit WinRM' } 'Remote' { 'Błąd zbierania danych' }
        'Timeout' { 'Limit czasu' } 'Network' { 'Sieć' } 'OK' { 'Osiągalny' } default { 'Inny' }
    }
}
function Get-VmStateText([string]$State) {
    switch ($State) {
        'Off'      { 'wyłączona' }
        'Saved'    { 'w stanie zapisanym (Saved)' }
        'Paused'   { 'wstrzymana (Paused)' }
        'Starting' { 'w trakcie uruchamiania' }
        'Stopping' { 'w trakcie zatrzymywania' }
        'Saving'   { 'w trakcie zapisywania stanu' }
        'Running'  { 'uruchomiona' }
        default    { "w stanie $State" }
    }
}

function Get-HvHostRows($D) {
    # Wiersze sekcji „Hyper-V: host i pojemność” (Check / Value / Status) z liczb zebranych na hoście; progi z ustawień
    $s = $D.System
    if (-not $s -or -not $s.IsHyperV -or -not $s.PSObject.Properties['HvVmTotal']) { return @() }
    $rows = New-Object System.Collections.Generic.List[object]
    $add = { param($c, $v, $st) $rows.Add([pscustomobject]@{ Check = $c; Value = "$v"; Status = $st; Flag = '' }) }
    & $add 'Maszyny wirtualne' "$($s.HvVmRunning) działa z $($s.HvVmTotal)" 'Info'
    $lp = [int]$s.HvLogicalCpus; $vr = [int]$s.HvVcpuRunning
    if ($lp -gt 0) {
        $ratio = [math]::Round($vr / $lp, 2)
        & $add 'vCPU działających maszyn / procesory logiczne hosta' "$vr / $lp (≈ $ratio : 1)" $(if ($ratio -gt $Config.VcpuRatioWarn) { 'Uwaga' } else { 'OK' })
    }
    & $add 'vCPU wszystkich maszyn' "$($s.HvVcpuTotal)" 'Info'
    $ram = [double]$s.RamGB
    if ($ram -gt 0) {
        $as = [double]$s.HvRamAssignedGB; $pct = [math]::Round($as / $ram * 100)
        & $add 'RAM przydzielony działającym maszynom' "$as GB z $ram GB ($pct%)" $(if ($pct -ge $Config.HostRamWarnPct) { 'Uwaga' } else { 'OK' })
        $su = [double]$s.HvRamStartupGB; $pct2 = [math]::Round($su / $ram * 100)
        & $add 'RAM startowy wszystkich maszyn' "$su GB ($pct2% RAM hosta)$(if ($pct2 -gt 100) { ' – wszystkie maszyny nie uruchomią się jednocześnie (np. po przejęciu maszyn z innego węzła)' })" $(if ($pct2 -gt 100) { 'Info' } else { 'OK' })
    }
    if ($s.PSObject.Properties['HvNumaSpanning']) { & $add 'NUMA spanning' $(if ($s.HvNumaSpanning) { 'włączone' } else { 'wyłączone' }) 'Info' }
    if ($s.PSObject.Properties['HvCluster'] -and $s.HvCluster) { & $add 'Klaster' "$($s.HvCluster): $($s.HvClusterNodes)" $(if ("$($s.HvClusterNodes)" -match '\((Down|Paused|Unknown)\)') { 'Info' } else { 'OK' }) }
    if ($s.PSObject.Properties['HvVhdPath'] -and $s.HvVhdPath) { & $add 'Domyślna ścieżka dysków VM' "$($s.HvVhdPath)" 'Info' }
    [object[]]$rows.ToArray()
}

$script:StationOffset = 0.0   # mediana różnicy czasu serwerów – gdy to zegar STACJI odbiega od domeny, korygujemy wszystkie serwery
function Get-TimeOffsetIssue([string]$Name, $s) {
    if (-not $s -or -not $s.PSObject.Properties['TimeOffsetSec'] -or "$($s.TimeOffsetSec)" -eq '') { return $null }
    $off = [double]$s.TimeOffsetSec - $script:StationOffset
    $ao  = [math]::Abs($off)
    $msg = "Różnica czasu względem stacji skanującej: $([math]::Round($off, 1)) s (Kerberos domyślnie toleruje 300 s)"
    if ($script:StationOffset) { $msg += " – po uwzględnieniu przesunięcia zegara stacji o $([math]::Round($script:StationOffset, 1)) s" }
    if ($ao -ge $Config.TimeSkewCritSec) { New-Issue $Name 'Krytyczny' 'Czas' $msg 'System' }
    elseif ($ao -ge $Config.TimeSkewWarnSec) { New-Issue $Name 'Ostrzeżenie' 'Czas' $msg 'System' }
    else { $null }
}
function Update-StationClock {
    # Gdy co najmniej 5 serwerów ma różnicę czasu w tę samą stronę (mediana ≥ próg ostrzeżenia), błędny jest zegar stacji:
    # jeden problem ogólny zamiast ostrzeżenia na każdym serwerze
    $offs = @(foreach ($d in $script:Data.Values) { if ($d -and -not $d.Offline -and $d.System -and $d.System.PSObject.Properties['TimeOffsetSec'] -and "$($d.System.TimeOffsetSec)" -ne '') { [double]$d.System.TimeOffsetSec } })
    $new = 0.0
    if ($offs.Count -ge 5) {
        $sorted = @($offs | Sort-Object)
        $med = $sorted[[int][math]::Floor($sorted.Count / 2)]
        $same = @($offs | Where-Object { [math]::Sign($_) -eq [math]::Sign($med) -and [math]::Abs($_) -ge $Config.TimeSkewWarnSec }).Count
        if ([math]::Abs($med) -ge $Config.TimeSkewWarnSec -and $same -ge 0.8 * $offs.Count) { $new = [math]::Round($med, 1) }
    }
    if ($new -eq $script:StationOffset) { return }
    $script:StationOffset = $new
    if ($new) { Write-Log "Zegar stacji różni się od większości serwerów o $(-$new) s – różnice czasu serwerów liczone względem mediany" 'WARN' 'Analiza' }
    foreach ($k in @($script:Data.Keys)) {
        $d = $script:Data[$k]
        if (-not $d -or $d.Offline -or -not $d.PSObject.Properties['_AllIssues']) { continue }
        $all = @($d._AllIssues | Where-Object { -not ($_.Category -eq 'Czas' -and "$($_.IssueKey)".StartsWith('Czas|System|Różnica czasu względem stacji')) })
        $ti = Get-TimeOffsetIssue $k $d.System
        if ($ti) { $all = @(@($ti) + $all | Sort-Object Rank) }
        $d | Add-Member -NotePropertyName _AllIssues -NotePropertyValue $all -Force
        Split-ServerIssues $k $d
        Update-ServerItem $k
    }
    $script:FullCache.Clear()   # szczegóły serwera przeliczą się z nową korektą zegara
}
function Get-StationClockIssue {
    if (-not $script:StationOffset) { return $null }
    $i = New-Issue '(stacja)' 'Ostrzeżenie' 'Czas' "Zegar stacji, z której uruchomiono program, różni się od większości serwerów o $(-$script:StationOffset) s – sprawdź synchronizację czasu stacji (w32tm /resync). Różnice czasu serwerów są liczone względem mediany." 'System'
    $i.Server = 'Stacja'
    $i
}

$script:StationNetIssue = $null
function Update-StationNetwork($St) {
    # Żaden serwer nie odpowiedział, a przyczyny to sieć/DNS: najpewniej problem stacji (VPN, DNS, karta sieciowa), nie awaria serwerów
    $script:StationNetIssue = $null
    if (-not $St -or $St.Ok -gt 0 -or $St.Offline -lt 5 -or @($St.Targets).Count -lt 0.5 * @($script:Servers).Count) { return }   # nie przy skanie kilku wybranych serwerów
    $net = @(foreach ($t in @($St.Targets)) { $d = $script:Data[$t]; if ($d -and $d.Offline -and "$($d.PSObject.Properties['Diag'].Value.Class)" -in 'Offline', 'Dns', 'Network', '') { $t } }).Count
    if ($net -lt 0.8 * $St.Offline) { return }
    $msg = "Żaden z $($St.Offline) skanowanych serwerów nie odpowiedział (sieć/DNS) – sprawdź najpierw połączenie sieciowe stacji (VPN, DNS, karta sieciowa, zapora stacji), zanim zaczniesz szukać awarii serwerów"
    $i = New-Issue '(stacja)' 'Krytyczny' 'Łączność' $msg 'Diagnostics'
    $i.Server = 'Stacja'
    $script:StationNetIssue = $i
    Write-Log $msg 'ERROR' 'Skan'
}
function Split-ServerIssues([string]$Name, $D) {
    # Problemy aktywne i wyciszone (reguły z Ustawień / menu problemu) + liczniki do listy serwerów i kafelków
    $act = New-Object System.Collections.Generic.List[object]
    $ign = New-Object System.Collections.Generic.List[object]
    $c = 0; $w = 0
    foreach ($i in @($D._AllIssues)) {
        if (-not $i) { continue }
        if (Test-IssueIgnored $Name $i.IssueKey) { $i.Ignored = $true; $ign.Add($i) }
        else {
            $i.Ignored = $false; $act.Add($i)
            if ($i.Rank -eq 0) { $c++ } elseif ($i.Rank -eq 1) { $w++ }
        }
    }
    $D | Add-Member -NotePropertyName _Issues -NotePropertyValue ([object[]]$act.ToArray()) -Force
    $D | Add-Member -NotePropertyName _Ignored -NotePropertyValue ([object[]]$ign.ToArray()) -Force
    $D | Add-Member -NotePropertyName _Crit -NotePropertyValue $c -Force
    $D | Add-Member -NotePropertyName _Warn -NotePropertyValue $w -Force
}

# ── Indeks maszyn wirtualnych ze wszystkich hostów (powiązanie gość ↔ maszyna, widok Hyper-V, wolumeny CSV klastra) ──
$script:VmIndex = $null
$script:ClusterIssues = @()
function Update-VmIndex {
    $byName = @{}; $byGuest = @{}; $byId = @{}
    $all = New-Object System.Collections.Generic.List[object]
    $vols = @{}
    foreach ($it in @($script:Servers)) {
        $d = $script:Data[$it.Name]
        if (-not $d -or $d.Offline -or -not $d.System -or -not $d.System.IsHyperV) { continue }
        $cl = if ($d.System.PSObject.Properties['HvCluster']) { "$($d.System.HvCluster)" } else { '' }
        foreach ($r in @($d.HyperV)) {
            if (-not $r) { continue }
            $e = @{ Host = $it.Name; HostDisplay = $it.Display; Row = $r; ScannedAt = $d.ScannedAt; Cluster = $cl }
            $all.Add($e)
            $vid = "$($r.PSObject.Properties['Id'].Value)"
            if ($vid) { if (-not $byId.ContainsKey($vid)) { $byId[$vid] = New-Object System.Collections.Generic.List[object] }; $byId[$vid].Add($e) }
            $k1 = "$($r.Name)".ToUpperInvariant()
            if (-not $byName.ContainsKey($k1)) { $byName[$k1] = New-Object System.Collections.Generic.List[object] }
            $byName[$k1].Add($e)
            $g = "$($r.PSObject.Properties['GuestFQDN'].Value)"
            if ($g) {
                $k2 = Get-DisplayName $g
                if (-not $byGuest.ContainsKey($k2)) { $byGuest[$k2] = New-Object System.Collections.Generic.List[object] }
                $byGuest[$k2].Add($e)
            }
        }
        # Wolumeny dysków VM: CSV klastra i udziały SMB są wspólne dla wielu hostów – sumujemy możliwy przyrost dysków ze wszystkich hostów
        foreach ($r in @($d.VMStorage)) {
            if (-not $r -or -not $r.Volume -or "$($r.VolumeFreeGB)" -eq '') { continue }
            $vol = "$($r.Volume)"
            $shared = ($cl -and $vol -match '^[A-Za-z]:\\ClusterStorage\\') -or $vol.StartsWith('\\')
            if (-not $shared) { continue }
            $key = $(if ($vol.StartsWith('\\')) { $vol } else { "$cl|$vol" }).ToLowerInvariant()
            $v = $vols[$key]
            if (-not $v) { $v = @{ Volume = $vol; Cluster = $cl; Hosts = (New-Object 'System.Collections.Generic.HashSet[string]'); Disks = 0; Growth = 0.0; Free = [double]$r.VolumeFreeGB; Owner = $it.Name }; $vols[$key] = $v }
            [void]$v.Hosts.Add($it.Display); $v.Disks++; $v.Growth += [double]$r.GrowthGB
            $v.Free = [math]::Min($v.Free, [double]$r.VolumeFreeGB)
        }
    }
    # listy → tablice (PS 5.1: @(List[object]) w wyrażeniach rzuca „Argument types do not match”)
    foreach ($h in $byName, $byGuest, $byId) { foreach ($k in @($h.Keys)) { $h[$k] = [object[]]$h[$k].ToArray() } }
    $script:VmIndex = @{ ByName = $byName; ByGuest = $byGuest; ById = $byId; All = [object[]]$all.ToArray() }
    $cross = New-Object System.Collections.Generic.List[object]
    $addX = {
        param($key, $sev, $msg, $sec, $srvText, $cat)
        $i = New-Issue $key $sev $(if ($cat) { $cat } elseif ($sec -eq 'Cluster') { 'Klaster' } else { 'Hyper-V' }) $msg $sec
        if ($srvText) { $i.Server = $srvText; $i._Search = ("$srvText $($i.Category) $msg").ToLowerInvariant() }
        if (-not (Test-IssueIgnored $key $i.IssueKey)) { $cross.Add($i) }
    }
    # Klastry: ocena raz na klaster, z danych węzła reprezentującego (pierwszy alfabetycznie z udanym skanem)
    $clusters = @{}
    foreach ($it in @($script:Servers)) {
        $d = $script:Data[$it.Name]
        if (-not $d -or $d.Offline -or -not $d.PSObject.Properties['System'] -or -not $d.System -or -not $d.System.PSObject.Properties['HvCluster'] -or -not $d.System.HvCluster) { continue }
        $cn = "$($d.System.HvCluster)"
        if (-not $clusters.ContainsKey($cn)) { $clusters[$cn] = New-Object System.Collections.Generic.List[object] }
        $clusters[$cn].Add(@{ Key = $it.Name; D = $d })
    }
    foreach ($cn in @($clusters.Keys | Sort-Object)) {
        $nodes = @($clusters[$cn] | Sort-Object { $_.Key })
        # węzeł reprezentujący: pierwszy alfabetycznie ze świeżymi danymi klastra (bez danych sprzed limitu czasu i bez błędu sekcji)
        $good = @($nodes | Where-Object { -not ($_.D.PSObject.Properties['_ScanNote'] -and $_.D._ScanNote) -and @($_.D.PSObject.Properties['Failed'].Value) -notcontains 'Cluster' })
        $rep = if ($good.Count) { $good[0] } else { $nodes[0] }
        $rows = @($rep.D.PSObject.Properties['Cluster'].Value | Where-Object { $_ })
        foreach ($r in $rows) {
            switch ("$($r.Type)") {
                'Węzeł'   { if ("$($r.State)" -ne 'Up') { & $addX $rep.Key $(if ("$($r.State)" -eq 'Down') { 'Krytyczny' } else { 'Ostrzeżenie' }) "Węzeł $($r.Name) klastra $cn w stanie $($r.State)" 'Cluster' $cn } }
                'CSV'     { if ("$($r.State)" -ne 'Online') { & $addX $rep.Key 'Krytyczny' "Wolumen CSV $($r.Name) klastra $cn w stanie $($r.State) – maszyny na nim mogą być wstrzymane" 'Cluster' $cn } }
                'Rola VM' { if ("$($r.State)" -eq 'Failed') { & $addX $rep.Key 'Krytyczny' "Rola maszyny $($r.Name) w klastrze $cn w stanie Failed (właściciel: $($r.Owner))" 'Cluster' $cn } elseif ("$($r.State)" -eq 'PartialOnline') { & $addX $rep.Key 'Ostrzeżenie' "Rola maszyny $($r.Name) w klastrze $cn częściowo online" 'Cluster' $cn } }
                'Kworum'  { if ("$($r.State)" -ne 'Online') { & $addX $rep.Key 'Ostrzeżenie' "Zasób kworum $($r.Name) klastra $cn w stanie $($r.State)" 'Cluster' $cn } }
            }
        }
        # N+1: czy pozostałe węzły pomieszczą maszyny po awarii największego węzła (tylko gdy przeskanowano wszystkie węzły)
        $want = [int]$rep.D.System.PSObject.Properties['HvClusterNodeCount'].Value
        if ($nodes.Count -ge 2 -and $want -and $nodes.Count -ge $want) {
            $used = 0.0; $ramAll = 0.0; $ramMax = 0.0
            foreach ($n in $nodes) { $used += [double]$n.D.System.HvRamAssignedGB; $ram = [double]$n.D.System.RamGB; $ramAll += $ram; if ($ram -gt $ramMax) { $ramMax = $ram } }
            $avail = $ramAll - $ramMax - ($nodes.Count - 1) * [double]$Config.HvHostMinFreeGB
            if ($used -gt $avail) { & $addX $rep.Key 'Ostrzeżenie' "Klaster $cn nie przetrwa awarii największego węzła: maszyny używają $([math]::Round($used)) GB RAM, a po awarii zostanie ok. $([math]::Round($avail)) GB (z zapasem $($Config.HvHostMinFreeGB) GB na węzeł)" 'Cluster' $cn }
        }
    }
    # Wszystkie kontrolery domeny na jednym hoście = awaria hosta wyłącza logowanie w całej domenie
    $dcByHost = @{}; $dcCount = 0
    foreach ($it in @($script:Servers)) {
        $d = $script:Data[$it.Name]
        if (-not $d -or $d.Offline -or -not $d.PSObject.Properties['System'] -or -not $d.System -or -not $d.System.IsDC) { continue }
        $dcCount++
        $h = if ($d.System.PSObject.Properties['HvHost'] -and $d.System.HvHost) { Get-DisplayName "$($d.System.HvHost)" } else { "(fizyczny) $($it.Display)" }
        if (-not $dcByHost.ContainsKey($h)) { $dcByHost[$h] = New-Object System.Collections.Generic.List[string] }
        $dcByHost[$h].Add($it.Display)
    }
    if ($dcCount -ge 2 -and $dcByHost.Count -eq 1) {
        $h = @($dcByHost.Keys)[0]
        & $addX (@($script:Servers | Where-Object { $dcByHost[$h] -contains $_.Display })[0].Name) 'Ostrzeżenie' "Wszystkie skanowane kontrolery domeny ($($dcByHost[$h] -join ', ')) działają na jednym hoście $h – jego awaria wyłączy logowanie w domenie" 'System' ''
    }
    # Ta sama maszyna pod dwiema nazwami (alias DNS, nazwa klastra, adres IP) – skanowana podwójnie
    $byComp = @{}
    foreach ($it in @($script:Servers)) {
        $d = $script:Data[$it.Name]
        if (-not $d -or $d.Offline -or -not $d.PSObject.Properties['System'] -or -not $d.System -or -not $d.System.ComputerName) { continue }
        $cnm = "$($d.System.ComputerName)".ToUpperInvariant()
        if ($byComp.ContainsKey($cnm)) { & $addX $it.Name 'Info' "Nazwa $($it.Name) wskazuje na ten sam serwer co $($byComp[$cnm]) (alias, nazwa klastra albo adres IP) – usuń duplikat z listy" 'System' '' }
        else { $byComp[$cnm] = $it.Name }
    }
    # Awarie zbiorcze: wiele niedostępnych serwerów z jednego hosta Hyper-V albo z jednej podsieci to zwykle jedna przyczyna
    # tylko serwery, które faktycznie nie odpowiadają w sieci (błąd uprawnień, Kerberos czy zatrzymany WinRM to nie awaria sieci)
    $down = @(foreach ($it in @($script:Servers)) { if (Test-NetworkDown $script:Data[$it.Name] -AllowFirewall) { $it } })
    if ($down.Count -ge 2) {
        $byHost = @{}
        foreach ($it in $down) {
            $d = $script:Data[$it.Name]
            $hk = Find-ServerKey (Get-LastHvHost $d)
            if (-not $hk -or $hk -eq $it.Name -or -not (Test-NetworkDown $script:Data[$hk]) -or (Find-VmForServer $it.Name $d)) { continue }
            if (-not $byHost.ContainsKey($hk)) { $byHost[$hk] = New-Object System.Collections.Generic.List[string] }
            $byHost[$hk].Add($it.Display)
        }
        foreach ($hk in @($byHost.Keys)) {
            $g = $byHost[$hk]
            if ($g.Count -ge 2) { & $addX $hk 'Krytyczny' "Host Hyper-V $(Get-DisplayName $hk) nie odpowiada, a razem z nim maszyny z listy, które ostatnio na nim działały ($($g.Count)): $(Join-Short $g 8) – zacznij od hosta (konsola iLO/iDRAC, zasilanie, sieć)" 'Diagnostics' '' 'Łączność' }
        }
        # podsieć /24: co najmniej 3 niedostępne i ≥ 80% znanych serwerów tej podsieci
        $netAll = @{}; $netDown = @{}; $noAddr = 0
        foreach ($it in @($script:Servers)) {
            $d = $script:Data[$it.Name]
            if (-not $d -or ($d.PSObject.Properties['Unsupported'] -and $d.Unsupported)) { continue }
            $sns = @(Get-ServerSubnets $d)
            if (-not $d.Offline -and -not $sns.Count) { $noAddr++ }   # np. pominięta sekcja Adresacja – nie wiadomo, ile serwerów podsieci działa
            foreach ($sn in $sns) { if (-not $netAll.ContainsKey($sn)) { $netAll[$sn] = 0 }; $netAll[$sn]++ }
        }
        foreach ($it in $down) {
            foreach ($sn in @(Get-ServerSubnets $script:Data[$it.Name])) {
                if (-not $netDown.ContainsKey($sn)) { $netDown[$sn] = New-Object System.Collections.Generic.List[object] }
                $netDown[$sn].Add($it)
            }
        }
        foreach ($sn in @($netDown.Keys | Sort-Object)) {
            if ($noAddr) { break }
            $g = $netDown[$sn]; $tot = [int]$netAll[$sn]
            if ($g.Count -lt 3 -or $tot -lt 1 -or $g.Count / $tot -lt 0.8) { continue }
            $fw = @($g | Where-Object { "$($script:Data[$_.Name].Diag.Class)" -eq 'Firewall' }).Count
            $names = Join-Short ($g | ForEach-Object { $_.Display }) 8
            $txt = if ($fw -ge $g.Count / 2) { "W podsieci $sn serwery odpowiadają, ale WinRM (TCP 5985) jest blokowany na $($g.Count) z $tot ($names) – prawdopodobnie zapora sieciowa / ACL między stacją a podsiecią albo reguła zapory z GPO" }
                   else { "Nie odpowiada $($g.Count) z $tot serwerów w podsieci $sn ($names) – prawdopodobnie awaria sieci, routingu, VPN albo zapory między stacją a tą podsiecią; zacznij od łączności z podsiecią" }
            & $addX $g[0].Name 'Krytyczny' $txt 'Diagnostics' "podsieć $sn" 'Sieć'
        }
    }
    foreach ($v in $vols.Values) {
        if ($v.Growth -gt $v.Free) {
            $where = if ($v.Cluster) { "w klastrze $($v.Cluster)" } else { 'na udziale' }
            $i = New-Issue $v.Owner 'Ostrzeżenie' 'Hyper-V' ("Dyski dynamiczne maszyn z $(if ($v.Hosts.Count -eq 1) { 'hosta' } else { 'hostów' }) $((@($v.Hosts) | Sort-Object) -join ', ') na wolumenie $($v.Volume) $where mogą urosnąć łącznie o $([math]::Round($v.Growth, 1)) GB, a wolne jest $([math]::Round($v.Free, 1)) GB – zapełnienie wstrzyma maszyny") 'VMStorage'
            if ($v.Cluster) { $i.Server = $v.Cluster }
            if (-not (Test-IssueIgnored $v.Owner $i.IssueKey)) { $cross.Add($i) }
        }
    }
    $script:ClusterIssues = [object[]]$cross.ToArray()
}
function Find-VmForServer([string]$Name, $D) {
    # Maszyna wirtualna odpowiadająca serwerowi z listy: najpierw dane gościa (host i nazwa VM z usług integracji),
    # potem nazwa gościa z KVP hosta albo nazwa VM równa nazwie serwera. Działająca kopia ma pierwszeństwo (replika jest wyłączona).
    $ix = $script:VmIndex
    if (-not $ix -or -not $Name) { return $null }
    $sys = $null
    if ($D -and $D.PSObject.Properties['System'] -and $D.System) { $sys = $D.System }
    elseif ($D -and $D.PSObject.Properties['_Last'] -and $D._Last -and $D._Last.System) { $sys = $D._Last.System }
    $cands = @()
    if ($sys -and $sys.PSObject.Properties['HvVmId'] -and $sys.HvVmId -and $ix.ById.ContainsKey("$($sys.HvVmId)")) { $cands = @($ix.ById["$($sys.HvVmId)"]) }
    if (-not $cands.Count -and $sys -and $sys.PSObject.Properties['HvVmName'] -and $sys.HvVmName) {
        $cands = @($ix.ByName["$($sys.HvVmName)".ToUpperInvariant()] | Where-Object { $_ })
        if ($cands.Count -gt 1 -and $sys.HvHost) { $hs = Get-DisplayName "$($sys.HvHost)"; $p = @($cands | Where-Object { $_.HostDisplay -eq $hs }); if ($p.Count) { $cands = $p } }
    }
    if (-not $cands.Count) {
        $short = Get-DisplayName $Name
        $cands = @(@($ix.ByGuest[$short]) + @($ix.ByName[$short.ToUpperInvariant()]) | Where-Object { $_ })
    }
    # repliki (Hyper-V Replica) mają ten sam identyfikator i nazwę co maszyna główna – nie reprezentują gościa
    $nonRep = @($cands | Where-Object { "$($_.Row.PSObject.Properties['ReplicationMode'].Value)" -notmatch 'Replica' })
    if ($nonRep.Count) { $cands = $nonRep }
    else { $cands = @($cands | Where-Object { "$($_.Row.State)" -like 'Running*' }) }   # sama replika liczy się tylko po przełączeniu (gdy działa)
    if (-not $cands.Count) { return $null }
    $run = @($cands | Where-Object { "$($_.Row.State)" -like 'Running*' })
    if ($run.Count) { return $run[0] }
    @($cands | Sort-Object { "$($_.ScannedAt)" } -Descending)[0]
}
function Test-NetworkDown($D, [switch]$AllowFirewall) {
    # Serwer niedostępny z przyczyn sieciowych (nie odpowiada, błąd sieci, nieznana przyczyna; z -AllowFirewall także zablokowany 5985)
    if (-not $D -or -not $D.Offline) { return $false }
    $cls = "$($D.PSObject.Properties['Diag'].Value.Class)"
    $ok = @('', 'Offline', 'Network', 'Unknown')
    if ($AllowFirewall) { $ok += 'Firewall' }
    $ok -contains $cls
}
function Get-LastHvHost($D) {
    # Host Hyper-V z danych gościa (usługi integracji) – z bieżącego skanu albo z ostatnich udanych danych serwera niedostępnego
    if (-not $D) { return '' }
    $sys = $null
    if ($D.PSObject.Properties['System'] -and $D.System) { $sys = $D.System }
    elseif ($D.PSObject.Properties['_Last'] -and $D._Last -and $D._Last.System) { $sys = $D._Last.System }
    if ($sys -and $sys.PSObject.Properties['HvHost'] -and $sys.HvHost) { "$($sys.HvHost)" } else { '' }
}
function Find-ServerKey([string]$HostName) {
    # Pozycja listy serwerów dla nazwy (FQDN albo krótkiej)
    if (-not $HostName) { return $null }
    $dn = Get-DisplayName $HostName
    foreach ($it in @($script:Servers)) { if ($it.Name -eq $HostName -or $it.Display -eq $dn) { return $it.Name } }
    $null
}
function Get-ServerSubnets($D) {
    # Podsieci /24 serwera: niedostępny – adres z diagnostyki (DNS) albo z ostatnich danych; dostępny – adresy wszystkich kart
    $ips = @()
    if ($D.Offline) {
        if ($D.PSObject.Properties['Diag'] -and $D.Diag -and $D.Diag.PSObject.Properties['Ip'] -and $D.Diag.Ip) { $ips = @("$($D.Diag.Ip)") }
        elseif ($D.PSObject.Properties['_Last'] -and $D._Last -and $D._Last.IPv4) { $ips = @("$($D._Last.IPv4)") }
    } elseif ($D.PSObject.Properties['Network']) {
        $ips = @(foreach ($n in @($D.Network)) { if ($n -and $n.IPv4) { foreach ($a in ("$($n.IPv4)" -split ',')) { ($a.Trim() -split '/')[0] } } })
    }
    @(foreach ($ip in $ips) { if ($ip -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') { "$($Matches[1]).0/24" } }) | Select-Object -Unique
}
function Test-LinuxGuest([string]$Name) {
    $vm = Find-VmForServer $Name $script:Data[$Name]
    $vm -and "$($vm.Row.PSObject.Properties['Linux'].Value)" -eq 'Tak'
}
#endregion

#region ── Motyw i XAML okien ──────────────────────────────────────────────────────
# Motyw (ciemny, spójny z AD-ManagerDiamond / Domain Ops). New-UiElement wstrzykuje go do zasobów każdego okna.
$script:ThemeXaml = @'
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <SolidColorBrush x:Key="Muted" Color="#8791A5"/>
  <SolidColorBrush x:Key="Faint" Color="#5E6779"/>

  <Style x:Key="Card" TargetType="Border">
    <Setter Property="Background" Value="#161B22"/>
    <Setter Property="BorderBrush" Value="#242B36"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="CornerRadius" Value="10"/>
    <Setter Property="Padding" Value="16,14"/>
  </Style>
  <Style x:Key="Tile" TargetType="Border" BasedOn="{StaticResource Card}">
    <Setter Property="Cursor" Value="Hand"/>
    <Style.Triggers>
      <Trigger Property="IsMouseOver" Value="True"><Setter Property="BorderBrush" Value="#2F4478"/></Trigger>
    </Style.Triggers>
  </Style>
  <Style x:Key="SegmentHost" TargetType="Border">
    <Setter Property="Background" Value="#161B22"/>
    <Setter Property="BorderBrush" Value="#242B36"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="CornerRadius" Value="8"/>
    <Setter Property="Padding" Value="3"/>
  </Style>
  <Style x:Key="Glyph" TargetType="TextBlock">
    <Setter Property="FontFamily" Value="Segoe Fluent Icons, Segoe MDL2 Assets"/>
    <Setter Property="FontSize" Value="14"/>
    <Setter Property="VerticalAlignment" Value="Center"/>
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
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="Button">
          <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="7" Padding="{TemplateBinding Padding}">
            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#4C7DF0"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#4C7DF0"/></Trigger>
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
  <Style x:Key="DangerButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
    <Setter Property="Foreground" Value="#FF8A95"/>
    <Setter Property="BorderBrush" Value="#4A2A32"/>
    <Setter Property="Background" Value="#21181C"/>
    <Style.Triggers>
      <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#3A1F26"/></Trigger>
    </Style.Triggers>
  </Style>
  <Style x:Key="DangerPrimaryButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
    <Setter Property="Background" Value="#D9475A"/>
    <Setter Property="BorderBrush" Value="#D9475A"/>
    <Setter Property="Foreground" Value="White"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Style.Triggers>
      <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#E85C6E"/></Trigger>
    </Style.Triggers>
  </Style>
  <Style x:Key="GhostButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
    <Setter Property="Background" Value="Transparent"/>
    <Setter Property="BorderBrush" Value="Transparent"/>
    <Setter Property="Foreground" Value="#AEB6C4"/>
    <Setter Property="Padding" Value="8,4"/>
    <Style.Triggers>
      <Trigger Property="IsMouseOver" Value="True">
        <Setter Property="Background" Value="#1E252F"/>
        <Setter Property="Foreground" Value="#E4E8EF"/>
      </Trigger>
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
              <ScrollViewer x:Name="PART_ContentHost" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
              <TextBlock x:Name="wm" Text="{TemplateBinding Tag}" Foreground="#5E6779" Margin="2,0,0,0"
                         VerticalAlignment="{TemplateBinding VerticalContentAlignment}" IsHitTestVisible="False" Visibility="Collapsed"/>
            </Grid>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="Text" Value=""><Setter TargetName="wm" Property="Visibility" Value="Visible"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#4C7DF0"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.45"/></Trigger>
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
  </Style>
  <Style TargetType="PasswordBox">
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
        <ControlTemplate TargetType="PasswordBox">
          <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="7" Padding="{TemplateBinding Padding}">
            <ScrollViewer x:Name="PART_ContentHost" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
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
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
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
  <Style x:Key="FilterChip" TargetType="RadioButton">
    <Setter Property="Foreground" Value="#8791A5"/>
    <Setter Property="FontSize" Value="11.5"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="Margin" Value="0,0,5,5"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="RadioButton">
          <Border x:Name="b" Background="#161B22" BorderBrush="#242B36" BorderThickness="1" CornerRadius="10" Padding="9,2">
            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter Property="Foreground" Value="#E4E8EF"/></Trigger>
            <Trigger Property="IsChecked" Value="True">
              <Setter TargetName="b" Property="Background" Value="#1A2640"/>
              <Setter TargetName="b" Property="BorderBrush" Value="#2F4478"/>
              <Setter Property="Foreground" Value="#E4E8EF"/>
            </Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style TargetType="CheckBox">
    <Setter Property="Foreground" Value="#D5DAE3"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="VerticalAlignment" Value="Center"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="CheckBox">
          <Grid Background="Transparent">
            <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Border x:Name="box" Width="16" Height="16" CornerRadius="4" BorderThickness="1" BorderBrush="#3A4352" Background="#1B212A" VerticalAlignment="Top" Margin="0,1,0,0">
              <Path x:Name="mark" Data="M 3 7.2 L 5.8 10 L 11 4.2" Stroke="White" StrokeThickness="2" Visibility="Collapsed"
                    StrokeStartLineCap="Round" StrokeEndLineCap="Round" StrokeLineJoin="Round"/>
            </Border>
            <ContentPresenter x:Name="cp" Grid.Column="1" Margin="9,0,0,0" VerticalAlignment="Center">
              <ContentPresenter.Resources><Style TargetType="TextBlock"><Setter Property="TextWrapping" Value="Wrap"/></Style></ContentPresenter.Resources>
            </ContentPresenter>
          </Grid>
          <ControlTemplate.Triggers>
            <Trigger Property="Content" Value="{x:Null}"><Setter TargetName="cp" Property="Margin" Value="0"/></Trigger>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="box" Property="BorderBrush" Value="#4C7DF0"/></Trigger>
            <Trigger Property="IsChecked" Value="True">
              <Setter TargetName="box" Property="Background" Value="#3E6FE0"/>
              <Setter TargetName="box" Property="BorderBrush" Value="#3E6FE0"/>
              <Setter TargetName="mark" Property="Visibility" Value="Visible"/>
            </Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
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
    <Setter Property="VirtualizingPanel.IsVirtualizing" Value="True"/>
    <Setter Property="VirtualizingPanel.VirtualizationMode" Value="Recycling"/>
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
    <Setter Property="EnableColumnVirtualization" Value="True"/>
    <Setter Property="VirtualizingPanel.VirtualizationMode" Value="Recycling"/>
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
          <Setter Property="ToolTip" Value="Kliknij, aby sortować: rosnąco → malejąco → bez sortowania. Shift+klik dodaje kolejną kolumnę."/>
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
            <DataTrigger Binding="{Binding Flag}" Value="muted"><Setter Property="Foreground" Value="#6B7385"/></DataTrigger>
            <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#1D2430"/></Trigger>
          </Style.Triggers>
        </Style>
      </Setter.Value>
    </Setter>
  </Style>

  <Style TargetType="ContextMenu">
    <Setter Property="Background" Value="#1B212A"/>
    <Setter Property="BorderBrush" Value="#2F3846"/>
    <Setter Property="Foreground" Value="#E4E8EF"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="ContextMenu">
          <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="8" Padding="4">
            <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Cycle"/>
          </Border>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style TargetType="MenuItem">
    <Setter Property="Foreground" Value="#E4E8EF"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="MenuItem">
          <Border x:Name="b" Background="Transparent" CornerRadius="6" Padding="8,6" MinWidth="210">
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="26"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>
              <ContentPresenter ContentSource="Icon" VerticalAlignment="Center" TextElement.Foreground="#8791A5"/>
              <ContentPresenter Grid.Column="1" ContentSource="Header" VerticalAlignment="Center"/>
            </Grid>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsHighlighted" Value="True"><Setter TargetName="b" Property="Background" Value="#24304A"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.4"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style x:Key="MenuSeparator" TargetType="Separator">
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="Separator">
          <Border Height="1" Background="#2A323F" Margin="6,4"/>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style TargetType="ToolTip">
    <Setter Property="Foreground" Value="#E4E8EF"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="ToolTip">
          <Border Background="#232A35" BorderBrush="#2F3846" BorderThickness="1" CornerRadius="6" Padding="9,6" MaxWidth="520">
            <ContentPresenter>
              <ContentPresenter.Resources>
                <Style TargetType="TextBlock"><Setter Property="TextWrapping" Value="Wrap"/></Style>
              </ContentPresenter.Resources>
            </ContentPresenter>
          </Border>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
  <Style TargetType="GridSplitter">
    <Setter Property="Background" Value="Transparent"/>
    <Setter Property="Focusable" Value="False"/>
    <Style.Triggers>
      <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#2F4478"/></Trigger>
    </Style.Triggers>
  </Style>
</ResourceDictionary>
'@

$script:MainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Przegląd serwerów" Width="1540" Height="940" MinWidth="1180" MinHeight="680"
        WindowStartupLocation="CenterScreen" Background="#0F1318" Foreground="#E4E8EF"
        FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True" SnapsToDevicePixels="True" TextOptions.TextFormattingMode="Display">
  <Grid x:Name="rootGrid">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*" MinHeight="300"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition x:Name="logRow" Height="0"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Pasek górny -->
    <Border Grid.Row="0" Background="#12171D" BorderBrush="#1E242E" BorderThickness="0,0,0,1" Padding="16,10">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
          <Border Width="36" Height="36" CornerRadius="10">
            <Border.Background>
              <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                <GradientStop Color="#4C7DF0" Offset="0"/>
                <GradientStop Color="#2FB38A" Offset="1"/>
              </LinearGradientBrush>
            </Border.Background>
            <TextBlock Style="{StaticResource Glyph}" Text="&#xE9D9;" FontSize="17" Foreground="White" HorizontalAlignment="Center"/>
          </Border>
          <StackPanel Margin="11,0,0,0" VerticalAlignment="Center">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="Przegląd serwerów" FontSize="15" FontWeight="SemiBold" Foreground="White"/>
              <TextBlock x:Name="txtVersion" Foreground="#5E6779" FontSize="11" Margin="7,3,0,0"/>
            </StackPanel>
            <TextBlock x:Name="txtSubtitle" Foreground="#7B8496" FontSize="11.5"/>
          </StackPanel>
        </StackPanel>
        <Border Grid.Column="1" Style="{StaticResource SegmentHost}" Margin="28,0,0,0" VerticalAlignment="Center">
          <StackPanel Orientation="Horizontal">
            <RadioButton x:Name="rbOverview" GroupName="view" IsChecked="True" ToolTip="Wszystkie serwery (Ctrl+1)">
              <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE80F;" FontSize="13" Margin="0,0,8,0"/><TextBlock Text="Wszystkie serwery"/></StackPanel>
            </RadioButton>
            <RadioButton x:Name="rbVms" GroupName="view" ToolTip="Hosty i maszyny wirtualne Hyper-V ze wszystkich hostów (Ctrl+2)">
              <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE8FD;" FontSize="13" Margin="0,0,8,0"/><TextBlock Text="Hyper-V"/></StackPanel>
            </RadioButton>
            <RadioButton x:Name="rbServer" GroupName="view" ToolTip="Szczegóły wybranego serwera (Ctrl+3)">
              <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE9D9;" FontSize="13" Margin="0,0,8,0"/><TextBlock Text="Szczegóły serwera"/></StackPanel>
            </RadioButton>
          </StackPanel>
        </Border>
        <StackPanel Grid.Column="3" Orientation="Horizontal" VerticalAlignment="Center">
          <TextBlock Text="Zdarzenia z" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="0,0,7,0"/>
          <TextBox x:Name="txtDays" Width="44" TextAlignment="Center" Padding="4,5" ToolTip="Zakres zdarzeń tylko dla bieżącego skanu (1–180 dni); domyślny – w Ustawieniach"/>
          <TextBlock Text="dni" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="7,0,10,0"/>
          <Button x:Name="btnCred" Style="{StaticResource GhostButton}" ToolTip="Konto używane do połączeń z serwerami (kliknij, aby zmienić)" Padding="8,3">
            <StackPanel Orientation="Horizontal">
              <Border Width="26" Height="26" CornerRadius="13" Background="#1F2B47" Margin="0,0,8,0">
                <TextBlock Style="{StaticResource Glyph}" Text="&#xE77B;" FontSize="12" Foreground="#8CB0FF" HorizontalAlignment="Center"/>
              </Border>
              <StackPanel VerticalAlignment="Center">
                <TextBlock x:Name="txtCredUser" Foreground="#E4E8EF" FontSize="12.5"/>
                <TextBlock x:Name="txtCredMode" Foreground="#7B8496" FontSize="11"/>
              </StackPanel>
            </StackPanel>
          </Button>
          <Button x:Name="btnReport" Style="{StaticResource GhostButton}" Margin="4,0,0,0" Padding="10,7" ToolTip="Raport HTML (podsumowanie albo pełny)">
            <StackPanel Orientation="Horizontal">
              <TextBlock Style="{StaticResource Glyph}" Text="&#xE8A5;" FontSize="14" Margin="0,0,8,0"/>
              <TextBlock Text="Raport" VerticalAlignment="Center"/>
              <TextBlock Style="{StaticResource Glyph}" Text="&#xE70D;" FontSize="9" Margin="7,1,0,0" Foreground="#7B8496"/>
            </StackPanel>
          </Button>
          <Button x:Name="btnSettings" Style="{StaticResource GhostButton}" Margin="2,0,0,0" Padding="10,7">
            <StackPanel Orientation="Horizontal">
              <TextBlock Style="{StaticResource Glyph}" Text="&#xE713;" FontSize="15"/>
              <TextBlock x:Name="txtSkipCount" FontSize="11.5" Margin="5,0,0,0" Foreground="#FFC46B" VerticalAlignment="Center" Visibility="Collapsed"/>
            </StackPanel>
          </Button>
          <Button x:Name="btnLock" Style="{StaticResource GhostButton}" Margin="2,0,0,0" Padding="10,7" ToolTip="Zablokuj program – odblokowanie PIN-em (Ctrl+Shift+L)">
            <TextBlock Style="{StaticResource Glyph}" Text="&#xE72E;" FontSize="15"/>
          </Button>
          <Button x:Name="btnScan" Style="{StaticResource PrimaryButton}" Margin="10,0,0,0" ToolTip="Skanuj wszystkie serwery z listy (F5)">
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="btnScanIcon" Style="{StaticResource Glyph}" Text="&#xE768;" FontSize="12" Margin="0,0,8,0" Foreground="White"/>
              <TextBlock x:Name="btnScanText" Text="Skanuj wszystkie"/>
            </StackPanel>
          </Button>
        </StackPanel>
      </Grid>
    </Border>

    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="285"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Lista serwerów -->
      <Border Background="#12171D" BorderBrush="#1E242E" BorderThickness="0,0,1,0" Padding="12,12">
        <DockPanel>
          <DockPanel DockPanel.Dock="Top" Margin="4,0,0,8">
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
              <Button x:Name="btnAD" Style="{StaticResource GhostButton}" Padding="7,3" ToolTip="Pobierz z AD aktywne serwery Windows (zakres OU – w Ustawieniach)">
                <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE710;" FontSize="11" Margin="0,0,5,0"/><TextBlock Text="AD" FontSize="12"/></StackPanel>
              </Button>
              <Button x:Name="btnFile" Style="{StaticResource GhostButton}" Padding="7,3" ToolTip="Wczytaj listę z pliku TXT/CSV">
                <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE8E5;" FontSize="11" Margin="0,0,5,0"/><TextBlock Text="Plik" FontSize="12"/></StackPanel>
              </Button>
            </StackPanel>
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
              <TextBlock Text="Serwery" FontSize="14" FontWeight="SemiBold"/>
              <TextBlock x:Name="txtServerCount" Foreground="{StaticResource Muted}" FontSize="12" Margin="8,0,0,0" VerticalAlignment="Bottom" Padding="0,0,0,1"/>
            </StackPanel>
          </DockPanel>
          <TextBox x:Name="txtServerFilter" DockPanel.Dock="Top" Tag="Szukaj serwera (nazwa, system, host)" Margin="0,0,0,8"/>
          <WrapPanel DockPanel.Dock="Top" Margin="0,0,0,4">
            <RadioButton x:Name="sfAll" GroupName="sf" Style="{StaticResource FilterChip}" IsChecked="True" Content="Wszystkie"/>
            <RadioButton x:Name="sfProblems" GroupName="sf" Style="{StaticResource FilterChip}" Content="Z problemami"/>
            <RadioButton x:Name="sfOffline" GroupName="sf" Style="{StaticResource FilterChip}" Content="Bez połączenia"/>
            <RadioButton x:Name="sfHosts" GroupName="sf" Style="{StaticResource FilterChip}" Content="Hosty Hyper-V"/>
            <RadioButton x:Name="sfVms" GroupName="sf" Style="{StaticResource FilterChip}" Content="Maszyny wirtualne"/>
            <RadioButton x:Name="sfNew" GroupName="sf" Style="{StaticResource FilterChip}" Content="Nieskanowane"/>
          </WrapPanel>
          <StackPanel DockPanel.Dock="Bottom" Margin="0,8,0,0">
            <DockPanel>
              <Button x:Name="btnAdd" DockPanel.Dock="Right" Content="Dodaj" Margin="6,0,0,0" Padding="12,6"/>
              <TextBox x:Name="txtAdd" Tag="SRV01, SRV02…"/>
            </DockPanel>
            <TextBlock Text="Ctrl/Shift+klik zaznacza kilka serwerów, prawy klik – menu (skan, diagnoza, RDP, konsole), Delete usuwa" Foreground="{StaticResource Faint}" FontSize="11" Margin="3,6,0,0" TextWrapping="Wrap"/>
          </StackPanel>
          <ListBox x:Name="lstServers" SelectionMode="Extended">
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
                    <StackPanel Orientation="Horizontal">
                      <TextBlock Text="{Binding Display}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
                      <Border Background="#1E2A44" CornerRadius="5" Padding="5,0" Margin="6,1,0,0" Visibility="{Binding KindVis}" VerticalAlignment="Center">
                        <TextBlock Text="{Binding Kind}" Foreground="#8CB0FF" FontSize="10" FontWeight="SemiBold"/>
                      </Border>
                    </StackPanel>
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

      <Grid Grid.Column="1">
        <Grid Margin="20,16,20,12">

          <!-- Widok: wszystkie serwery -->
          <Grid x:Name="viewOverview">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="3*"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="2*"/>
            </Grid.RowDefinitions>
            <UniformGrid Grid.Row="0" Columns="6" Margin="0,0,0,16">
              <Border x:Name="tileTotal" Style="{StaticResource Tile}" Margin="0,0,10,0" ToolTip="Pokaż wszystkie serwery">
                <StackPanel><TextBlock Text="Serwery na liście" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tTotal" Text="0" FontSize="28" FontWeight="SemiBold" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border x:Name="tileOnline" Style="{StaticResource Tile}" Margin="0,0,10,0" ToolTip="Serwery, z których zebrano dane">
                <StackPanel><TextBlock Text="Odpowiada" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tOnline" Text="0" FontSize="28" FontWeight="SemiBold" Foreground="#4FD1A1" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border x:Name="tileOffline" Style="{StaticResource Tile}" Margin="0,0,10,0" ToolTip="Pokaż serwery bez połączenia (z diagnozą przyczyny)">
                <StackPanel><TextBlock Text="Bez połączenia" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tOffline" Text="0" FontSize="28" FontWeight="SemiBold" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border x:Name="tileCrit" Style="{StaticResource Tile}" Margin="0,0,10,0" ToolTip="Pokaż problemy krytyczne">
                <StackPanel><TextBlock Text="Problemy krytyczne" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tCrit" Text="0" FontSize="28" FontWeight="SemiBold" Foreground="#FF7A86" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border x:Name="tileWarn" Style="{StaticResource Tile}" Margin="0,0,10,0" ToolTip="Pokaż ostrzeżenia">
                <StackPanel><TextBlock Text="Ostrzeżenia" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tWarn" Text="0" FontSize="28" FontWeight="SemiBold" Foreground="#FFC46B" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border x:Name="tileHv" Style="{StaticResource Tile}" ToolTip="Hosty Hyper-V i maszyny wirtualne (działające / wszystkie)">
                <StackPanel><TextBlock Text="Hyper-V: hosty / VM" Foreground="{StaticResource Muted}"/><TextBlock x:Name="tHv" Text="0" FontSize="28" FontWeight="SemiBold" Foreground="#8CB0FF" Margin="0,2,0,0"/></StackPanel>
              </Border>
            </UniformGrid>

            <DockPanel Grid.Row="1" Margin="0,0,0,10">
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                <CheckBox x:Name="chkIgnored" Content="Wyciszone" Margin="0,0,12,0" ToolTip="Pokaż problemy wyciszone (prawy klik na problemie – wycisz / przywróć)"/>
                <Border Style="{StaticResource SegmentHost}" Margin="0,0,10,0">
                  <StackPanel Orientation="Horizontal">
                    <RadioButton x:Name="rbSevAll" GroupName="sev" Content="Wszystkie" IsChecked="True" Padding="10,4"/>
                    <RadioButton x:Name="rbSevCrit" GroupName="sev" Content="Krytyczne" Padding="10,4"/>
                    <RadioButton x:Name="rbSevWarn" GroupName="sev" Content="Ostrzeżenia" Padding="10,4"/>
                    <RadioButton x:Name="rbSevInfo" GroupName="sev" Content="Info" Padding="10,4"/>
                  </StackPanel>
                </Border>
                <TextBox x:Name="txtIssueFilter" Width="230" Tag="Filtruj problemy (Ctrl+F)"/>
                <Button x:Name="btnIssuesCsv" Style="{StaticResource GhostButton}" Margin="6,0,0,0" Padding="9,5" ToolTip="Eksport widocznych problemów do CSV">
                  <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE896;" FontSize="12" Margin="0,0,6,0"/><TextBlock Text="CSV"/></StackPanel>
                </Button>
              </StackPanel>
              <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock x:Name="txtIssuesTitle" Text="Wykryte problemy" FontSize="15" FontWeight="SemiBold"/>
                <TextBlock x:Name="txtIssuesCount" Foreground="{StaticResource Muted}" FontSize="12" Margin="10,0,0,0" VerticalAlignment="Bottom" Padding="0,0,0,1"/>
                <TextBlock Text="dwuklik otwiera serwer, prawy klik – wycisz" Foreground="{StaticResource Faint}" FontSize="11.5" Margin="12,0,0,0" VerticalAlignment="Bottom" Padding="0,0,0,1"/>
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
                    <DataGridTemplateColumn Header="Poziom" Width="118" SortMemberPath="Rank" ClipboardContentBinding="{Binding Severity}">
                      <DataGridTemplateColumn.CellTemplate>
                        <DataTemplate>
                          <Border Background="{Binding SevBg}" CornerRadius="9" Padding="9,2" HorizontalAlignment="Left">
                            <TextBlock Text="{Binding Severity}" Foreground="{Binding SevColor}" FontSize="11.5" FontWeight="SemiBold"/>
                          </Border>
                        </DataTemplate>
                      </DataGridTemplateColumn.CellTemplate>
                    </DataGridTemplateColumn>
                    <DataGridTextColumn Header="Serwer" Binding="{Binding Server}" Width="140" SortMemberPath="Server"/>
                    <DataGridTextColumn Header="Kategoria" Binding="{Binding Category}" Width="140" SortMemberPath="Category"/>
                    <DataGridTextColumn Header="Opis" Binding="{Binding Message}" Width="*" SortMemberPath="Message">
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

            <DockPanel Grid.Row="3" Margin="0,16,0,10">
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                <Button x:Name="btnServersCsv" Style="{StaticResource GhostButton}" Padding="9,5" ToolTip="Eksport tabeli stanu serwerów do CSV">
                  <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE896;" FontSize="12" Margin="0,0,6,0"/><TextBlock Text="CSV"/></StackPanel>
                </Button>
              </StackPanel>
              <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="Stan serwerów" FontSize="15" FontWeight="SemiBold"/>
                <TextBlock Text="dostępność z dziennika – ostatnie 30 dni" Foreground="{StaticResource Faint}" FontSize="11.5" Margin="12,0,0,0" VerticalAlignment="Bottom" Padding="0,0,0,1"/>
              </StackPanel>
            </DockPanel>
            <Border Grid.Row="4" Style="{StaticResource Card}" Padding="1">
              <DataGrid x:Name="gridServers" Style="{StaticResource DarkGrid}"/>
            </Border>
          </Grid>

          <!-- Widok: Hyper-V (wszystkie hosty i maszyny) -->
          <Grid x:Name="viewVms" Visibility="Collapsed">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="2*"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="3*"/>
            </Grid.RowDefinitions>
            <UniformGrid Grid.Row="0" Columns="6" Margin="0,0,0,16">
              <Border Style="{StaticResource Card}" Margin="0,0,10,0">
                <StackPanel><TextBlock Text="Hosty Hyper-V" Foreground="{StaticResource Muted}"/><TextBlock x:Name="vHosts" Text="0" FontSize="26" FontWeight="SemiBold" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,0,10,0">
                <StackPanel><TextBlock Text="Maszyny działające / wszystkie" Foreground="{StaticResource Muted}"/><TextBlock x:Name="vVms" Text="0" FontSize="26" FontWeight="SemiBold" Foreground="#4FD1A1" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,0,10,0">
                <StackPanel><TextBlock Text="vCPU działających maszyn" Foreground="{StaticResource Muted}"/><TextBlock x:Name="vCpu" Text="0" FontSize="26" FontWeight="SemiBold" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,0,10,0">
                <StackPanel><TextBlock Text="RAM przydzielony [GB]" Foreground="{StaticResource Muted}"/><TextBlock x:Name="vRam" Text="0" FontSize="26" FontWeight="SemiBold" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,0,10,0">
                <StackPanel><TextBlock Text="Stare checkpointy" Foreground="{StaticResource Muted}"/><TextBlock x:Name="vCheckpoints" Text="0" FontSize="26" FontWeight="SemiBold" Foreground="#FFC46B" Margin="0,2,0,0"/></StackPanel>
              </Border>
              <Border Style="{StaticResource Card}">
                <StackPanel><TextBlock Text="Linux (nie skanujemy)" Foreground="{StaticResource Muted}"/><TextBlock x:Name="vLinux" Text="0" FontSize="26" FontWeight="SemiBold" Foreground="#8791A5" Margin="0,2,0,0"/></StackPanel>
              </Border>
            </UniformGrid>
            <DockPanel Grid.Row="1" Margin="0,0,0,10">
              <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="Hosty i pojemność" FontSize="15" FontWeight="SemiBold"/>
                <TextBlock Text="z ostatniego skanu każdego hosta; dwuklik otwiera host" Foreground="{StaticResource Faint}" FontSize="11.5" Margin="12,0,0,0" VerticalAlignment="Bottom" Padding="0,0,0,1"/>
              </StackPanel>
            </DockPanel>
            <Border Grid.Row="2" Style="{StaticResource Card}" Padding="1">
              <DataGrid x:Name="gridHosts" Style="{StaticResource DarkGrid}"/>
            </Border>
            <DockPanel Grid.Row="3" Margin="0,16,0,10">
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                <Border Style="{StaticResource SegmentHost}" Margin="0,0,10,0">
                  <StackPanel Orientation="Horizontal">
                    <RadioButton x:Name="vfAll" GroupName="vf" Content="Wszystkie" IsChecked="True" Padding="10,4"/>
                    <RadioButton x:Name="vfRunning" GroupName="vf" Content="Działające" Padding="10,4"/>
                    <RadioButton x:Name="vfOff" GroupName="vf" Content="Wyłączone" Padding="10,4"/>
                    <RadioButton x:Name="vfProblems" GroupName="vf" Content="Do sprawdzenia" Padding="10,4"/>
                    <RadioButton x:Name="vfNotListed" GroupName="vf" Content="Spoza listy" Padding="10,4"/>
                  </StackPanel>
                </Border>
                <TextBox x:Name="txtVmFilter" Width="220" Tag="Filtruj maszyny"/>
                <Button x:Name="btnVmAdd" Style="{StaticResource GhostButton}" Margin="6,0,0,0" Padding="9,5" ToolTip="Dodaj do listy serwerów maszyny Windows spoza listy (zaznaczone albo wszystkie widoczne); Linux jest pomijany">
                  <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE710;" FontSize="12" Margin="0,0,6,0"/><TextBlock Text="Dodaj do listy"/></StackPanel>
                </Button>
                <Button x:Name="btnVmCsv" Style="{StaticResource GhostButton}" Margin="2,0,0,0" Padding="9,5" ToolTip="Eksport widocznych maszyn do CSV">
                  <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE896;" FontSize="12" Margin="0,0,6,0"/><TextBlock Text="CSV"/></StackPanel>
                </Button>
              </StackPanel>
              <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="Maszyny wirtualne" FontSize="15" FontWeight="SemiBold"/>
                <TextBlock x:Name="txtVmCount" Foreground="{StaticResource Muted}" FontSize="12" Margin="10,0,0,0" VerticalAlignment="Bottom" Padding="0,0,0,1"/>
              </StackPanel>
            </DockPanel>
            <Border Grid.Row="4" Style="{StaticResource Card}" Padding="1">
              <DataGrid x:Name="gridVms" Style="{StaticResource DarkGrid}"/>
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
                  <StackPanel Width="110" Margin="0,0,16,0">
                    <TextBlock Text="CPU" Foreground="{StaticResource Muted}" FontSize="11.5"/>
                    <TextBlock x:Name="dCpu" Text="–" FontSize="22" FontWeight="SemiBold"/>
                    <ProgressBar x:Name="pCpu" Height="5" Margin="0,6,0,0" Maximum="100"/>
                  </StackPanel>
                  <StackPanel Width="110" Margin="0,0,16,0">
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
                  <StackPanel Margin="16,0,0,0" VerticalAlignment="Center">
                    <Button x:Name="btnRescan" ToolTip="Skanuj ponownie ten serwer">
                      <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE72C;" FontSize="12" Margin="0,0,7,0"/><TextBlock Text="Skanuj ponownie"/></StackPanel>
                    </Button>
                    <Button x:Name="btnDiag" Style="{StaticResource GhostButton}" Margin="0,6,0,0" ToolTip="Sprawdź połączenie: DNS, ping, porty WinRM/RPC/SMB/RDP, konto w AD">
                      <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE9D9;" FontSize="12" Margin="0,0,7,0"/><TextBlock Text="Diagnozuj połączenie"/></StackPanel>
                    </Button>
                  </StackPanel>
                </StackPanel>
              </Grid>
            </Border>

            <Grid Grid.Row="1" Margin="0,14,0,0">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="255"/>
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
                    <TextBox x:Name="txtGridFilter" Width="260" Tag="Filtruj wiersze (Ctrl+F)"/>
                    <Button x:Name="btnCsv" Style="{StaticResource GhostButton}" Margin="6,0,0,0" Padding="9,5" ToolTip="Eksport widocznych wierszy do CSV">
                      <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Glyph}" Text="&#xE896;" FontSize="12" Margin="0,0,6,0"/><TextBlock Text="CSV"/></StackPanel>
                    </Button>
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
        <StackPanel x:Name="toastHost" HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,0,26,22"/>
      </Grid>
    </Grid>

    <!-- Dziennik operacji -->
    <GridSplitter x:Name="logSplitter" Grid.Row="2" Height="5" HorizontalAlignment="Stretch" ResizeDirection="Rows"
                  ResizeBehavior="PreviousAndNext" Visibility="Collapsed"/>
    <Border x:Name="logPanel" Grid.Row="3" Background="#12171D" BorderBrush="#1E242E" BorderThickness="0,1,0,0" Visibility="Collapsed">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <Grid Margin="18,6,10,2">
          <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
            <TextBlock Text="DZIENNIK OPERACJI" Foreground="#5E6779" FontSize="11" FontWeight="SemiBold" VerticalAlignment="Center"/>
            <Border Style="{StaticResource SegmentHost}" Padding="2" Margin="14,0,0,0">
              <StackPanel Orientation="Horizontal">
                <RadioButton x:Name="lfAll" GroupName="lf" Content="Wszystko" IsChecked="True" Padding="8,1" FontSize="11.5"/>
                <RadioButton x:Name="lfWarn" GroupName="lf" Content="Ostrzeżenia i błędy" Padding="8,1" FontSize="11.5"/>
                <RadioButton x:Name="lfErr" GroupName="lf" Content="Błędy" Padding="8,1" FontSize="11.5"/>
              </StackPanel>
            </Border>
            <TextBox x:Name="txtLogFilter" Width="200" Margin="8,0,0,0" Padding="6,2" FontSize="12" Tag="Szukaj w dzienniku"/>
          </StackPanel>
          <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="btnLogCopy" Style="{StaticResource GhostButton}" ToolTip="Kopiuj zaznaczone wpisy (albo wszystkie widoczne)" MinHeight="26" Padding="8,2"/>
            <Button x:Name="btnLogFile" Style="{StaticResource GhostButton}" ToolTip="Otwórz plik dziennika" MinHeight="26" Padding="8,2"/>
            <Button x:Name="btnLogFolder" Style="{StaticResource GhostButton}" ToolTip="Otwórz folder dzienników (także dziennik dostępności CSV)" MinHeight="26" Padding="8,2"/>
            <Button x:Name="btnLogClear" Style="{StaticResource GhostButton}" ToolTip="Wyczyść okno dziennika (plik zostaje)" MinHeight="26" Padding="8,2"/>
            <Button x:Name="btnLogHide" Style="{StaticResource GhostButton}" ToolTip="Ukryj dziennik (Ctrl+L)" MinHeight="26" Padding="8,2"/>
          </StackPanel>
        </Grid>
        <ListBox x:Name="logList" Grid.Row="1" Margin="8,0,8,6" SelectionMode="Extended" FontSize="12.5">
          <ListBox.ItemContainerStyle>
            <Style TargetType="ListBoxItem" BasedOn="{StaticResource ItemCard}">
              <Setter Property="Padding" Value="8,2"/>
              <Setter Property="Margin" Value="0"/>
              <Setter Property="Cursor" Value="Arrow"/>
            </Style>
          </ListBox.ItemContainerStyle>
          <ListBox.ItemTemplate>
            <DataTemplate>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="62"/>
                  <ColumnDefinition Width="70"/>
                  <ColumnDefinition Width="Auto" MaxWidth="230"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <TextBlock Text="{Binding Time}" Foreground="#5E6779" FontFamily="Consolas" VerticalAlignment="Center"/>
                <Border x:Name="pill" Grid.Column="1" CornerRadius="8" Padding="7,0" HorizontalAlignment="Left" Background="#1E252F" VerticalAlignment="Center">
                  <TextBlock x:Name="lvl" Text="{Binding Level}" FontSize="10.5" FontWeight="SemiBold" Foreground="#AEB6C4"/>
                </Border>
                <TextBlock Grid.Column="2" Text="{Binding Module}" Foreground="#8CB0FF" Margin="0,0,12,0" TextTrimming="CharacterEllipsis" VerticalAlignment="Center"/>
                <TextBlock Grid.Column="3" Text="{Binding Message}" TextWrapping="Wrap" VerticalAlignment="Center"/>
              </Grid>
              <DataTemplate.Triggers>
                <DataTrigger Binding="{Binding Level}" Value="OK">
                  <Setter TargetName="pill" Property="Background" Value="#15291F"/>
                  <Setter TargetName="lvl" Property="Foreground" Value="#5EE3AE"/>
                </DataTrigger>
                <DataTrigger Binding="{Binding Level}" Value="WARN">
                  <Setter TargetName="pill" Property="Background" Value="#2E2616"/>
                  <Setter TargetName="lvl" Property="Foreground" Value="#FFC46B"/>
                </DataTrigger>
                <DataTrigger Binding="{Binding Level}" Value="ERROR">
                  <Setter TargetName="pill" Property="Background" Value="#2E1A1E"/>
                  <Setter TargetName="lvl" Property="Foreground" Value="#FF7A86"/>
                </DataTrigger>
              </DataTemplate.Triggers>
            </DataTemplate>
          </ListBox.ItemTemplate>
        </ListBox>
      </Grid>
    </Border>

    <!-- Pasek stanu -->
    <Border Grid.Row="4" Background="#12171D" BorderBrush="#1E242E" BorderThickness="0,1,0,0" Padding="16,4,10,4">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Ellipse x:Name="statusDot" Width="8" Height="8" Fill="#5EE3AE" VerticalAlignment="Center"/>
        <TextBlock x:Name="txtStatus" Grid.Column="1" Text="Gotowe" Margin="10,0,0,0" Foreground="#AEB6C4" FontSize="12" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
        <ProgressBar x:Name="prg" Grid.Column="2" Width="200" Height="6" Margin="12,0" Maximum="100" VerticalAlignment="Center" Visibility="Collapsed"/>
        <Button x:Name="btnCancelOps" Grid.Column="3" Style="{StaticResource DangerButton}" Padding="10,2" MinHeight="26" Visibility="Collapsed" ToolTip="Przerwij trwające operacje (skan, wczytywanie, diagnoza)"/>
        <TextBlock x:Name="txtLastScan" Grid.Column="4" Foreground="#7B8496" FontSize="12" VerticalAlignment="Center" Margin="12,0,4,0"/>
        <Button x:Name="btnLogToggle" Grid.Column="5" Style="{StaticResource GhostButton}" MinHeight="26" Padding="8,2" Margin="8,0,0,0" ToolTip="Dziennik operacji (Ctrl+L)">
          <StackPanel Orientation="Horizontal">
            <TextBlock Style="{StaticResource Glyph}" Text="&#xE81C;" FontSize="12" Margin="0,0,7,0"/>
            <TextBlock Text="Dziennik" FontSize="12" VerticalAlignment="Center"/>
            <Border x:Name="logBadge" Background="#D9475A" CornerRadius="8" Padding="6,0" Margin="7,0,0,0" Visibility="Collapsed" VerticalAlignment="Center">
              <TextBlock x:Name="logBadgeText" Foreground="White" FontSize="10.5" FontWeight="SemiBold"/>
            </Border>
          </StackPanel>
        </Button>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

# Okno dialogowe (komunikat, pytanie, formularz): treść wstawiana w miejsce <!--BODY-->
$script:DialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="480" SizeToContent="Height" ResizeMode="NoResize" WindowStartupLocation="CenterOwner"
        ShowInTaskbar="False" Background="#12171D" Foreground="#E4E8EF" FontFamily="Segoe UI" FontSize="13"
        UseLayoutRounding="True" SnapsToDevicePixels="True" TextOptions.TextFormattingMode="Display">
  <Grid Background="#12171D">
  <Grid Margin="22,20,22,18">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <Grid Margin="0,0,0,16">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Border x:Name="dlgIconTile" Width="38" Height="38" CornerRadius="10" Background="#1A2640" Margin="0,0,14,0" VerticalAlignment="Top">
        <TextBlock x:Name="dlgIcon" Style="{StaticResource Glyph}" FontSize="17" Foreground="#8CB0FF" HorizontalAlignment="Center"/>
      </Border>
      <StackPanel Grid.Column="1" VerticalAlignment="Center">
        <TextBlock x:Name="dlgTitle" FontSize="16" FontWeight="SemiBold" Foreground="White" TextWrapping="Wrap"/>
        <TextBlock x:Name="dlgSubtitle" Foreground="#8791A5" TextWrapping="Wrap" Margin="0,3,0,0"/>
      </StackPanel>
    </Grid>
    <Grid x:Name="dlgBody" Grid.Row="1">
<!--BODY-->
    </Grid>
    <Grid Grid.Row="2" Margin="0,18,0,0">
      <StackPanel x:Name="dlgExtra" Orientation="Horizontal" HorizontalAlignment="Left"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="btnCancel" Content="Anuluj" MinWidth="96" IsCancel="True"/>
        <Button x:Name="btnOk" Content="OK" MinWidth="96" Margin="8,0,0,0" Style="{StaticResource PrimaryButton}" IsDefault="True"/>
      </StackPanel>
    </Grid>
  </Grid>
  </Grid>
</Window>
'@

# Ekran PIN (start programu i blokada w trakcie pracy) – jak w AD-ManagerDiamond
$script:UnlockXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="340" SizeToContent="Height" ResizeMode="NoResize" WindowStartupLocation="CenterScreen"
        Background="#12171D" Foreground="#E4E8EF" FontFamily="Segoe UI" FontSize="13"
        UseLayoutRounding="True" SnapsToDevicePixels="True" TextOptions.TextFormattingMode="Display">
  <Grid Background="#12171D">
    <StackPanel Margin="28,26,28,22">
      <Border Width="52" Height="52" CornerRadius="14" Background="#1A2640" HorizontalAlignment="Center">
        <TextBlock x:Name="lockIcon" Style="{StaticResource Glyph}" FontSize="22" Foreground="#8CB0FF" HorizontalAlignment="Center"/>
      </Border>
      <TextBlock x:Name="lockTitle" Text="Przegląd serwerów" FontSize="18" FontWeight="SemiBold" Foreground="White" HorizontalAlignment="Center" Margin="0,14,0,0"/>
      <TextBlock x:Name="lockHint" Text="Wpisz PIN, aby odblokować program" Foreground="#8791A5" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap" Margin="0,4,0,0"/>
      <StackPanel x:Name="lockDots" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,22,0,0"/>
      <TextBlock x:Name="lockMsg" Foreground="#FF7A86" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap" MinHeight="18" Margin="0,12,0,0"/>
      <UniformGrid x:Name="lockPad" Columns="3" Margin="0,12,0,0"/>
      <Button x:Name="lockClose" Content="Zamknij" Style="{StaticResource GhostButton}" HorizontalAlignment="Center" MinWidth="110" Margin="0,14,0,0" Focusable="False"/>
      <Button x:Name="lockExit" Style="{StaticResource GhostButton}" HorizontalAlignment="Center" MinWidth="170" Margin="0,14,0,0" Focusable="False" Visibility="Collapsed"
              ToolTip="Zamyka program bez odblokowania – trwający skan zostanie przerwany"/>
      <TextBlock x:Name="lockExitMsg" Foreground="#E5B567" FontSize="12" HorizontalAlignment="Center" TextAlignment="Center" TextWrapping="Wrap" Margin="0,8,0,0" Visibility="Collapsed"/>
    </StackPanel>
  </Grid>
</Window>
'@

$script:SettingsXamlText = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Ustawienia" Width="1080" Height="800" MinWidth="860" MinHeight="560"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" Background="#0F1318" Foreground="#E4E8EF"
        FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True" SnapsToDevicePixels="True" TextOptions.TextFormattingMode="Display">
  <Grid Margin="20,16,20,16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <StackPanel Margin="0,0,0,14">
      <TextBlock Text="Ustawienia" FontSize="18" FontWeight="SemiBold"/>
      <TextBlock x:Name="sSubtitle" Foreground="#8791A5" FontSize="11.5" TextWrapping="Wrap" Margin="0,2,0,0"/>
    </StackPanel>
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="4*"/>
        <ColumnDefinition Width="16"/>
        <ColumnDefinition Width="6*"/>
      </Grid.ColumnDefinitions>
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
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
        <Border Grid.Row="1" Style="{StaticResource Card}" Margin="0,14,0,0">
          <StackPanel>
            <TextBlock Text="Blokada programu" FontSize="15" FontWeight="SemiBold"/>
            <TextBlock x:Name="sPinState" Foreground="#8791A5" FontSize="12" TextWrapping="Wrap" Margin="0,2,0,10"/>
            <CheckBox x:Name="sPinAtStart" Content="Wymagaj PIN-u przy uruchomieniu programu" Margin="0,0,0,10"/>
            <StackPanel Orientation="Horizontal">
              <Button x:Name="sPinSet" Content="Ustaw PIN…"/>
              <Button x:Name="sPinClear" Content="Usuń PIN" Style="{StaticResource DangerButton}" Margin="8,0,0,0"/>
            </StackPanel>
          </StackPanel>
        </Border>
      </Grid>
      <Border Grid.Column="2" Style="{StaticResource Card}">
        <DockPanel>
          <StackPanel DockPanel.Dock="Top" Margin="0,0,0,6">
            <TextBlock Text="Parametry i progi" FontSize="15" FontWeight="SemiBold"/>
            <TextBlock Text="Pole „Zdarzenia z … dni” w głównym oknie zmienia zakres tylko dla bieżącego skanu" Foreground="#5E6779" FontSize="11.5" TextWrapping="Wrap"/>
          </StackPanel>
          <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel x:Name="sParams" Margin="0,0,10,0"/></ScrollViewer>
        </DockPanel>
      </Border>
    </Grid>
    <DockPanel Grid.Row="2" Margin="0,14,0,0">
      <StackPanel DockPanel.Dock="Left" Orientation="Horizontal">
        <Button x:Name="sDefaults" Content="Przywróć domyślne"/>
        <Button x:Name="sIgnored" Content="Wyciszone problemy…" Margin="8,0,0,0"/>
        <Button x:Name="sFolder" Content="Folder danych" Style="{StaticResource GhostButton}" Margin="8,0,0,0"/>
      </StackPanel>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="sCancel" Content="Anuluj" IsCancel="True"/>
        <Button x:Name="sSave" Content="Zapisz" Style="{StaticResource PrimaryButton}" Margin="8,0,0,0"/>
      </StackPanel>
    </DockPanel>
  </Grid>
</Window>
'@
#endregion

#region ── Interfejs: ładowanie XAML, ikony, okna dialogowe, powiadomienia ───────
# Kod natywny (jedna kompilacja przy starcie): ciemny pasek tytułu okien i szybkie sortowanie dużych tabel.
# Gdy kompilacja nie jest możliwa (np. zablokowany csc.exe), program działa dalej – z jasnym paskiem i wolniejszym sortowaniem.
$script:NativeOk = $false
function Initialize-Native {
    if ('ServerReviewNative.Sorter' -as [type]) { $script:NativeOk = $true; return }
    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Globalization;
using System.Runtime.InteropServices;
namespace ServerReviewNative {
    public static class Dwm {
        [DllImport("dwmapi.dll")]
        public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
    }
    public static class Sorter {
        // Kolejność wierszy wg kluczy z Get-SortKeys: E (puste na końcu), C (liczba/tekst), N (wartość), T (tekst); remisy – kolejność oryginalna
        public static int[] Order(int[][] e, int[][] c, double[][] n, string[][] t, bool[] desc) {
            int rows = e.Length > 0 ? e[0].Length : 0;
            int[] idx = new int[rows];
            for (int i = 0; i < rows; i++) idx[i] = i;
            CompareInfo ci = CultureInfo.CurrentCulture.CompareInfo;
            Array.Sort(idx, delegate(int a, int b) {
                for (int k = 0; k < e.Length; k++) {
                    int r = e[k][a].CompareTo(e[k][b]);
                    if (r != 0) return r;
                    int s = desc[k] ? -1 : 1;
                    r = c[k][a].CompareTo(c[k][b]); if (r != 0) return s * r;
                    r = n[k][a].CompareTo(n[k][b]); if (r != 0) return s * r;
                    r = ci.Compare(t[k][a] ?? "", t[k][b] ?? "", CompareOptions.IgnoreCase); if (r != 0) return s * r;
                }
                return a.CompareTo(b);
            });
            return idx;
        }
    }
}
'@
        $script:NativeOk = $true
    } catch { $script:NativeOk = $false; $script:NativeError = $_.Exception.Message }
}

function Set-DarkTitleBar($Window) {
    # Ciemny pasek tytułu (Windows 10 20H1+ / 11); bez obsługi – okno zostaje z jasnym paskiem
    if (-not $script:NativeOk) { return }
    try {
        $hwnd = (New-Object System.Windows.Interop.WindowInteropHelper $Window).Handle
        if ($hwnd -eq [IntPtr]::Zero) { return }
        $on = 1
        if ([ServerReviewNative.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$on, 4) -ne 0) { [void][ServerReviewNative.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$on, 4) }
        $caption = 0x001D1712   # #12171D jako COLORREF (0x00BBGGRR) – Windows 11
        [void][ServerReviewNative.Dwm]::DwmSetWindowAttribute($hwnd, 35, [ref]$caption, 4)
    } catch { }
}

function New-UiElement([string]$Xaml) {
    # Ładuje XAML z wstrzykniętym motywem: zasoby muszą istnieć w chwili parsowania (StaticResource),
    # dlatego słownik motywu trafia na początek <Root.Resources> korzenia dokumentu.
    if (-not $script:ThemeDoc) { $script:ThemeDoc = New-Object System.Xml.XmlDocument; $script:ThemeDoc.LoadXml($script:ThemeXaml) }
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml($Xaml)
    $root = $doc.DocumentElement
    $resName = $root.LocalName + '.Resources'
    $existing = $null
    foreach ($child in @($root.ChildNodes)) { if ($child.LocalName -eq $resName) { $existing = $child } }
    $dictionary = $doc.ImportNode($script:ThemeDoc.DocumentElement, $true)
    if ($existing) {
        foreach ($child in @($existing.ChildNodes)) { [void]$dictionary.AppendChild($child) }
        [void]$root.RemoveChild($existing)
    }
    $resources = $doc.CreateElement($resName, $root.NamespaceURI)
    [void]$resources.AppendChild($dictionary)
    [void]$root.PrependChild($resources)
    [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $doc))
}
function Get-NamedElements($Root, [string]$Xaml) {
    # Słownik kontrolek z atrybutem x:Name (nazwy wprost z tekstu XAML)
    $h = @{}
    foreach ($m in [regex]::Matches($Xaml, 'x:Name="([^"]+)"')) { $n = $m.Groups[1].Value; if (-not $h.ContainsKey($n)) { $el = $Root.FindName($n); if ($el) { $h[$n] = $el } } }
    $h
}
function Get-Glyph([string]$Code) { if ($Code) { [string][char][Convert]::ToInt32($Code, 16) } else { '' } }
function New-GlyphBlock([string]$Code, [double]$Size = 13, [string]$Color = '') {
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = Get-Glyph $Code
    $t.FontFamily = New-Object System.Windows.Media.FontFamily 'Segoe Fluent Icons, Segoe MDL2 Assets'
    $t.FontSize = $Size
    $t.VerticalAlignment = 'Center'
    if ($Color) { $t.Foreground = Brush $Color }
    $t
}
function New-IconContent([string]$Text, [string]$Icon, [double]$IconSize = 13) {
    if (-not $Icon) { return $Text }
    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.Orientation = 'Horizontal'
    $g = New-GlyphBlock -Code $Icon -Size $IconSize
    if ($Text) { $g.Margin = '0,0,8,0' }
    [void]$sp.Children.Add($g)
    if ($Text) { $t = New-Object System.Windows.Controls.TextBlock; $t.Text = $Text; $t.VerticalAlignment = 'Center'; [void]$sp.Children.Add($t) }
    $sp
}
function New-MenuItem([string]$Text, [string]$Icon = '', [scriptblock]$Action, [switch]$Danger, [bool]$Enabled = $true) {
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header = $Text
    if ($Icon) { $mi.Icon = New-GlyphBlock -Code $Icon -Size 13 -Color $(if ($Danger) { '#FF8A95' } else { '#8791A5' }) }
    if ($Danger) { $mi.Foreground = Brush '#FF8A95' }
    $mi.IsEnabled = $Enabled
    if ($Action) { $mi.Tag = $Action; $mi.Add_Click({ param($s, $e) Invoke-UiAction 'Menu' $s.Tag }) }
    $mi
}
function New-MenuSeparator {
    $sep = New-Object System.Windows.Controls.Separator
    try { $sep.Style = $window.FindResource('MenuSeparator') } catch { }
    $sep
}

function Invoke-UiAction([string]$Module, [scriptblock]$Action) {
    # Każda akcja z interfejsu: błąd trafia do dziennika i powiadomienia zamiast do niewidocznej konsoli
    try { $null = & $Action }
    catch {
        Write-Log "Błąd: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR' $Module
        Show-Toast "Błąd: $(Get-ShortText $_.Exception.Message 160)" 'crit' 6
    }
}

# Opóźnione filtrowanie (pola „Filtruj …”): przeliczenie po ~220 ms od ostatniego znaku, nie po każdym
$script:FilterPending = @{}
$script:FilterTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:FilterTimer.Interval = [TimeSpan]::FromMilliseconds(220)
$script:FilterTimer.Add_Tick({
    $script:FilterTimer.Stop()
    foreach ($k in @($script:FilterPending.Keys)) { $a = $script:FilterPending[$k]; $script:FilterPending.Remove($k); Invoke-UiAction 'Filtr' $a }
})
function Request-Filter([string]$Key, [scriptblock]$Action) { $script:FilterPending[$Key] = $Action; $script:FilterTimer.Stop(); $script:FilterTimer.Start() }

$script:DialogTones = @{
    info = @{ Back = '#1A2640'; Fore = '#8CB0FF'; Icon = 'E946' }
    ok   = @{ Back = '#15291F'; Fore = '#5EE3AE'; Icon = 'E930' }
    warn = @{ Back = '#2E2616'; Fore = '#FFC46B'; Icon = 'E7BA' }
    crit = @{ Back = '#2E1A1E'; Fore = '#FF7A86'; Icon = 'EA39' }
}
$script:DialogEvents = @{
    Ok     = {
        param($s, $e)
        $w = [System.Windows.Window]::GetWindow($s)
        if (-not $w) { return }
        if ($w.Tag.Validate) {
            $ok = $false
            try { $ok = [bool](& $w.Tag.Validate $w) } catch { $ok = $false; Show-Toast "Błąd: $($_.Exception.Message)" 'crit' }
            if (-not $ok) { return }
        }
        Close-Dialog -Window $w -Ok $true
    }
    Cancel = { param($s, $e) $w = [System.Windows.Window]::GetWindow($s); if ($w) { Close-Dialog -Window $w -Ok $false } }
}
function New-Dialog {
    param(
        [Parameter(Mandatory)][string]$Title, [string]$Subtitle = '', [string]$Body = '<Grid/>',
        [ValidateSet('info', 'ok', 'warn', 'crit')][string]$Tone = 'info', [string]$Icon = '', [double]$Width = 480,
        [string]$OkText = 'OK', [string]$CancelText = 'Anuluj', [switch]$NoCancel, [switch]$Danger, [scriptblock]$Validate
    )
    $w = New-UiElement ($script:DialogXaml.Replace('<!--BODY-->', $Body))
    $w.Title = $Title
    $w.Width = $Width
    $tone = $script:DialogTones[$Tone]
    $w.FindName('dlgIconTile').Background = Brush $tone.Back
    $ib = $w.FindName('dlgIcon'); $ib.Foreground = Brush $tone.Fore; $ib.Text = Get-Glyph $(if ($Icon) { $Icon } else { $tone.Icon })
    $w.FindName('dlgTitle').Text = $Title
    $sub = $w.FindName('dlgSubtitle'); if ($Subtitle) { $sub.Text = $Subtitle } else { $sub.Visibility = 'Collapsed' }
    $ok = $w.FindName('btnOk'); $ok.Content = $OkText
    if ($Danger) { $ok.Style = $w.FindResource('DangerPrimaryButton') }
    $cancel = $w.FindName('btnCancel'); $cancel.Content = $CancelText
    if ($NoCancel) { $cancel.Visibility = 'Collapsed'; $ok.IsCancel = $true }
    $ok.Add_Click($script:DialogEvents.Ok)
    $cancel.Add_Click($script:DialogEvents.Cancel)
    $w.Tag = @{ Result = $false; Modal = $false; Validate = $Validate }
    $w
}
function Invoke-Dialog([System.Windows.Window]$Window) {
    # Okno modalne nad oknem głównym; w czasie blokady programu czeka na odblokowanie (np. wynik skanu w tle)
    if (-not ($Window.Tag -is [hashtable])) { $Window.Tag = @{} }
    if ($script:UnlockState.Locked -and -not $Window.Tag['LockScreen']) { Wait-Unlocked }
    if ($script:UnlockState.Emergency -and -not $Window.Tag['LockScreen']) { $Window.Tag['Result'] = $false; return $false }
    if (-not $Window.Tag['LockScreen']) { Register-IdleActivity -Window $Window }
    $Window.Tag['Result'] = $false
    # $window i $Window to w PowerShell ta sama zmienna (parametr) – okno główne bierzemy z zakresu skryptu
    $main = $script:window
    if ($main -and $main.IsVisible -and -not [object]::ReferenceEquals($main, $Window)) { $Window.Owner = $main }
    else { $Window.WindowStartupLocation = 'CenterScreen' }
    $Window.Add_SourceInitialized({ param($s, $e) Set-DarkTitleBar $s })
    $Window.Tag['Modal'] = $true
    [void]$Window.ShowDialog()
    [bool]$Window.Tag['Result']
}
function Close-Dialog($Window, [bool]$Ok) {
    $Window.Tag['Result'] = $Ok
    if ($Window.Tag['Modal']) { try { $Window.DialogResult = $Ok } catch { try { $Window.Close() } catch { } } }
    else { try { $Window.Close() } catch { } }
}
function Show-Message([string]$Text, [string]$Title = 'Przegląd serwerów', [ValidateSet('info', 'ok', 'warn', 'crit')][string]$Tone = 'info') {
    if ($script:Headless -or -not $window) { Write-Log "$Title`: $Text" $(if ($Tone -eq 'crit') { 'ERROR' } elseif ($Tone -eq 'warn') { 'WARN' } else { 'INFO' }); return }
    $body = '<ScrollViewer MaxHeight="420" VerticalScrollBarVisibility="Auto"><TextBlock x:Name="msgText" TextWrapping="Wrap" Foreground="#C9D0DC" LineHeight="19"/></ScrollViewer>'
    $w = New-Dialog -Title $Title -Body $body -Tone $Tone -NoCancel -Width 520
    $w.FindName('msgText').Text = $Text
    [void](Invoke-Dialog $w)
}
function Confirm-Action([string]$Text, [string]$Title = 'Potwierdzenie', [string]$ConfirmText = 'Tak', [string]$CancelText = 'Anuluj', [switch]$Danger, [string]$Tone = 'warn') {
    if ($script:Headless) { return $false }
    $body = '<ScrollViewer MaxHeight="420" VerticalScrollBarVisibility="Auto"><TextBlock x:Name="msgText" TextWrapping="Wrap" Foreground="#C9D0DC" LineHeight="19"/></ScrollViewer>'
    $w = New-Dialog -Title $Title -Body $body -Tone $Tone -OkText $ConfirmText -CancelText $CancelText -Danger:$Danger -Width 520
    $w.FindName('msgText').Text = $Text
    Invoke-Dialog $w
}
function Show-Msg([string]$Text, [string]$Icon = 'Information', [string]$Buttons = 'OK') {
    # Zgodność ze starszym kodem: MessageBox → okna w motywie programu
    $tone = switch ($Icon) { 'Error' { 'crit' } 'Warning' { 'warn' } default { 'info' } }
    if ($Buttons -eq 'YesNo') { if (Confirm-Action -Text $Text -Title 'Przegląd serwerów' -Tone $tone) { 'Yes' } else { 'No' } }
    else { Show-Message -Text $Text -Tone $tone; 'OK' }
}

function Show-Toast {
    # Krótkie powiadomienie w prawym dolnym rogu okna (znika samo)
    param([Parameter(Mandatory)][string]$Text, [ValidateSet('info', 'ok', 'warn', 'crit')][string]$Tone = 'info', [int]$Seconds = 4)
    if ($script:Headless -or -not $ui -or -not $ui['toastHost']) { return }
    try {
        $tone = $script:DialogTones[$Tone]
        $b = New-Object System.Windows.Controls.Border
        $b.Background = Brush '#1E2530'; $b.BorderBrush = Brush '#2F3846'; $b.BorderThickness = 1
        $b.CornerRadius = New-Object System.Windows.CornerRadius 9
        $b.Padding = '14,10'; $b.Margin = '0,8,0,0'; $b.MaxWidth = 440; $b.HorizontalAlignment = 'Right'
        $fx = New-Object System.Windows.Media.Effects.DropShadowEffect; $fx.BlurRadius = 18; $fx.ShadowDepth = 3; $fx.Opacity = 0.45; $fx.Color = [System.Windows.Media.Colors]::Black
        $b.Effect = $fx
        $sp = New-Object System.Windows.Controls.StackPanel; $sp.Orientation = 'Horizontal'
        $ic = New-GlyphBlock -Code $tone.Icon -Size 15 -Color $tone.Fore; $ic.Margin = '0,0,10,0'
        $tx = New-Object System.Windows.Controls.TextBlock; $tx.Text = $Text; $tx.TextWrapping = 'Wrap'; $tx.MaxWidth = 380; $tx.Foreground = Brush '#E4E8EF'; $tx.VerticalAlignment = 'Center'
        [void]$sp.Children.Add($ic); [void]$sp.Children.Add($tx); $b.Child = $sp
        $hostPanel = $ui.toastHost
        while ($hostPanel.Children.Count -ge 4) { $hostPanel.Children.RemoveAt(0) }
        [void]$hostPanel.Children.Add($b)
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromSeconds([Math]::Max(2, $Seconds))
        $timer.Tag = $b
        $timer.Add_Tick({ param($s, $e) $s.Stop(); $t = $s.Tag; if ($ui.toastHost.Children.Contains($t)) { $ui.toastHost.Children.Remove($t) } })
        $timer.Start()
    } catch { }
}
#endregion

#region ── Blokada programu (PIN) ───────────────────────────────────────────────
# Wzorowane na AD-ManagerDiamond: ekran PIN przy starcie (opcjonalnie), blokada przyciskiem z kłódką, Ctrl+Shift+L
# albo po bezczynności. Zabezpieczenie przed osobą postronną przy odblokowanej stacji, nie przed administratorem komputera
# (skrypt i settings.json to zwykłe pliki). PIN (4–8 cyfr) ustawia się w oknie Ustawienia; w settings.json jest tylko
# sól i skrót PBKDF2. Bez ustawionego PIN-u blokada jest wyłączona. Skan w tle trwa także w czasie blokady.
$script:UnlockMaxAttempts = 5
$script:UnlockCooldownSec = 30
$script:UnlockExitConfirmSec = 10
# Locked – program zablokowany; Emergency – zamknięcie awaryjne z ekranu blokady; Hidden – okna, których zawartość ukryto
$script:UnlockState = @{ Locked = $false; Emergency = $false; Hidden = @() }
# Blokada po bezczynności: Last – ostatnia aktywność w oknach programu (UTC), Pos – ostatnia pozycja kursora
$script:IdleLock = @{ Timer = $null; Last = [datetime]::UtcNow; Pos = $null }

function Test-PinConfigured { [bool]$script:LockCfg.Hash -and [int]$script:LockCfg.Length -ge 4 }
function Get-PinHash([string]$Pin, [string]$Salt) {
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Pin, [Convert]::FromBase64String($Salt), 20000)
    try { [Convert]::ToBase64String($kdf.GetBytes(32)) } finally { $kdf.Dispose() }
}
function Test-UnlockPin([string]$Pin) {
    if (-not $Pin -or -not (Test-PinConfigured)) { return $false }
    try { (Get-PinHash $Pin $script:LockCfg.Salt) -ceq $script:LockCfg.Hash } catch { $false }
}
function Set-LockPin([string]$Pin) {
    # Pusty PIN = wyłączenie blokady
    if (-not $Pin) { $script:LockCfg.Hash = ''; $script:LockCfg.Salt = ''; $script:LockCfg.Length = 0; return }
    $salt = New-Object byte[] 16
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($salt) } finally { $rng.Dispose() }
    $script:LockCfg.Salt = [Convert]::ToBase64String($salt)
    $script:LockCfg.Hash = Get-PinHash $Pin $script:LockCfg.Salt
    $script:LockCfg.Length = $Pin.Length
}

$script:UnlockEvents = @{
    Key     = { param($s, $e) Add-UnlockKey -Window ([System.Windows.Window]::GetWindow($s)) -Key ([string]$s.Tag) }
    KeyDown = {
        param($s, $e)
        # Cyfry z górnego rzędu (bez Shift) i z klawiatury numerycznej; Backspace kasuje cyfrę, Esc i Delete wszystkie
        $k = [string]$e.Key
        $key = ''
        if ($k -match '^NumPad(\d)$') { $key = $Matches[1] }
        elseif ($k -match '^D(\d)$' -and -not ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift)) { $key = $Matches[1] }
        elseif ($k -eq 'Back') { $key = 'Back' }
        elseif ($k -eq 'Escape' -or $k -eq 'Delete') { $key = 'Clear' }
        if (-not $key) { return }
        $e.Handled = $true
        Add-UnlockKey -Window $s -Key $key
    }
    Close   = { param($s, $e) Close-Dialog -Window ([System.Windows.Window]::GetWindow($s)) -Ok $false }
    Exit    = { param($s, $e) Request-UnlockExit -Window ([System.Windows.Window]::GetWindow($s)) }
    # Okno blokady zamyka poprawny PIN albo potwierdzone zamknięcie awaryjne; krzyżyk i Alt+F4 działają jak „Zakończ awaryjnie”
    Closing = {
        param($s, $e)
        if ($s.Tag.Mode -ne 'Lock' -or $s.Tag.Result -or $script:UnlockState.Emergency) { return }
        if ([datetime]::UtcNow -lt $s.Tag.ExitArmed) {
            if ($s.Tag.ExitTimer) { $s.Tag.ExitTimer.Stop() }
            $script:UnlockState.Emergency = $true
            return
        }
        $e.Cancel = $true
        Request-UnlockExit -Window $s
    }
    # Aktywność w oknach programu (klawisz, kliknięcie, kółko myszy) odsuwa blokadę po bezczynności
    Activity = { param($s, $e) $script:IdleLock.Last = [datetime]::UtcNow }
}

function New-UnlockWindow {
    # -Mode: Start (przy uruchomieniu), Lock (blokada w trakcie pracy), Verify (potwierdzenie PIN-em, np. przed zmianą PIN-u)
    param([ValidateSet('Start', 'Lock', 'Verify')][string]$Mode = 'Start', [string]$Hint = '')
    $w = New-UiElement $script:UnlockXaml
    $w.Title = switch ($Mode) { 'Lock' { 'Przegląd serwerów – zablokowany' } 'Verify' { 'Przegląd serwerów – potwierdź PIN' } default { 'Przegląd serwerów – odblokowanie' } }
    if ($Hint) { $w.FindName('lockHint').Text = $Hint }
    elseif ($Mode -eq 'Lock') { $w.FindName('lockHint').Text = 'Program zablokowany – wpisz PIN' }
    if ($Mode -eq 'Lock') {
        # Krzyżyk nie zamyka okna blokady, więc bez PIN-u program można zamknąć tylko tym przyciskiem (z potwierdzeniem)
        $w.FindName('lockClose').Visibility = 'Collapsed'
        $exit = $w.FindName('lockExit')
        $exit.Visibility = 'Visible'
        $exit.Content = New-IconContent -Text 'Zakończ awaryjnie' -Icon 'E7E8' -IconSize 12
        $exit.Add_Click($script:UnlockEvents.Exit)
    } elseif ($Mode -eq 'Verify') { $w.FindName('lockClose').Content = 'Anuluj' }
    $w.FindName('lockIcon').Text = Get-Glyph 'E72E'
    $dots = $w.FindName('lockDots')
    for ($i = 0; $i -lt [int]$script:LockCfg.Length; $i++) {
        $d = New-Object System.Windows.Shapes.Ellipse
        $d.Width = 14; $d.Height = 14; $d.StrokeThickness = 2
        $d.Margin = New-Object System.Windows.Thickness(7, 0, 7, 0)
        [void]$dots.Children.Add($d)
    }
    $pad = $w.FindName('lockPad')
    foreach ($key in '1', '2', '3', '4', '5', '6', '7', '8', '9', 'Clear', '0', 'Back') {
        $b = New-Object System.Windows.Controls.Button
        $b.Tag = $key; $b.Height = 46; $b.Margin = New-Object System.Windows.Thickness(4)
        $b.Focusable = $false   # spacja ani Enter nie „klikają” ponownie ostatnio użytego przycisku
        if ($key -match '^\d$') { $b.Content = $key; $b.FontSize = 18 }
        else {
            $b.Content = New-GlyphBlock -Code $(if ($key -eq 'Back') { 'E750' } else { 'E894' }) -Size 15
            $b.ToolTip = $(if ($key -eq 'Back') { 'Usuń ostatnią cyfrę (Backspace)' } else { 'Wyczyść (Esc)' })
        }
        $b.Add_Click($script:UnlockEvents.Key)
        [void]$pad.Children.Add($b)
    }
    $w.FindName('lockClose').Add_Click($script:UnlockEvents.Close)
    $w.Add_PreviewKeyDown($script:UnlockEvents.KeyDown)
    $w.Add_Closing($script:UnlockEvents.Closing)
    $w.Tag = @{ Result = $false; Modal = $false; Pin = ''; Attempts = 0; Failed = 0; Error = $false; Locked = $false; Mode = $Mode; LockScreen = ($Mode -eq 'Lock'); CooldownEnd = [datetime]::MinValue; ExitArmed = [datetime]::MinValue; ExitTimer = $null }
    Update-UnlockView -Window $w
    $w
}
function Update-UnlockView($Window) {
    $st = $Window.Tag
    $i = 0
    foreach ($d in $Window.FindName('lockDots').Children) {
        $filled = $i -lt $st.Pin.Length
        $color = if ($st.Error) { '#FF7A86' } elseif ($filled) { '#8CB0FF' } else { '#3A4556' }
        $d.Stroke = Brush $color
        $d.Fill = $(if ($filled) { Brush $color } else { [System.Windows.Media.Brushes]::Transparent })
        $i++
    }
}
function Add-UnlockKey($Window, [string]$Key) {
    # Cyfra, 'Back' albo 'Clear'; po wpisaniu pełnego PIN-u od razu sprawdzenie
    $st = $Window.Tag
    if ($st.Locked) { return }
    if ($st.Error) { $st.Error = $false }
    $len = [int]$script:LockCfg.Length
    switch -Regex ($Key) {
        '^\d$'    { if ($st.Pin.Length -lt $len) { $st.Pin += $Key } }
        '^Back$'  { if ($st.Pin.Length) { $st.Pin = $st.Pin.Substring(0, $st.Pin.Length - 1) } }
        '^Clear$' { $st.Pin = '' }
    }
    $msg = $Window.FindName('lockMsg')
    if ($st.Pin.Length -lt $len) { Update-UnlockView -Window $Window; return }
    if (Test-UnlockPin $st.Pin) {
        $st.Pin = ''
        if ($st.Mode -eq 'Lock') { Restore-AfterLock }   # odblokowanie od razu – wstrzymane okna mogą się pokazać
        Close-Dialog -Window $Window -Ok $true
        return
    }
    $st.Attempts++; $st.Failed++
    $st.Pin = ''; $st.Error = $true
    $left = $script:UnlockMaxAttempts - $st.Attempts
    Update-UnlockView -Window $Window
    if ($left -le 0 -and $st.Mode -eq 'Lock') {
        # Blokada w trakcie pracy: przerwa zamiast zamknięcia programu (skan w tle trwa dalej)
        $st.Locked = $true
        $st.CooldownEnd = (Get-Date).AddSeconds($script:UnlockCooldownSec)
        $Window.FindName('lockPad').IsEnabled = $false
        [void](Update-UnlockCooldown -Window $Window)
        $t = New-Object System.Windows.Threading.DispatcherTimer
        $t.Interval = [TimeSpan]::FromMilliseconds(250); $t.Tag = $Window
        $t.Add_Tick({ param($s, $e) if (-not (Update-UnlockCooldown -Window $s.Tag)) { $s.Stop() } })
        $t.Start()
        return
    }
    if ($left -le 0) {
        $msg.Text = $(if ($st.Mode -eq 'Start') { 'Zbyt wiele błędnych prób – program zostanie zamknięty.' } else { 'Zbyt wiele błędnych prób.' })
        $st.Locked = $true
        $Window.FindName('lockPad').IsEnabled = $false
        $t = New-Object System.Windows.Threading.DispatcherTimer
        $t.Interval = [TimeSpan]::FromMilliseconds(1500); $t.Tag = $Window
        $t.Add_Tick({ param($s, $e) $s.Stop(); Close-Dialog -Window $s.Tag -Ok $false })
        $t.Start()
        return
    }
    $msg.Text = 'Nieprawidłowy PIN. Pozostało prób: {0}' -f $left
}
function Update-UnlockCooldown($Window) {
    # Odliczanie przerwy po wyczerpaniu prób; $false, gdy przerwa minęła (klawiatura znów aktywna)
    $st = $Window.Tag
    $left = ($st.CooldownEnd - (Get-Date)).TotalSeconds
    $msg = $Window.FindName('lockMsg')
    if ($left -gt 0) { $msg.Text = 'Zbyt wiele błędnych prób. Spróbuj ponownie za {0} s.' -f [int][Math]::Ceiling($left); return $true }
    $st.Locked = $false; $st.Attempts = 0; $st.Error = $false; $msg.Text = ''
    $Window.FindName('lockPad').IsEnabled = $true
    Update-UnlockView -Window $Window
    $false
}
function Request-UnlockExit($Window) {
    # Zamknięcie awaryjne z ekranu blokady: pierwsze kliknięcie uzbraja przycisk, drugie w ciągu kilku sekund zamyka program bez PIN-u
    $st = $Window.Tag
    $exit = $Window.FindName('lockExit'); $note = $Window.FindName('lockExitMsg')
    if ([datetime]::UtcNow -lt $st.ExitArmed) {
        if ($st.ExitTimer) { $st.ExitTimer.Stop() }
        $script:UnlockState.Emergency = $true
        Close-Dialog -Window $Window -Ok $false
        return
    }
    $st.ExitArmed = [datetime]::UtcNow.AddSeconds($script:UnlockExitConfirmSec)
    $exit.Content = New-IconContent -Text 'Potwierdź zamknięcie' -Icon 'E7BA' -IconSize 12
    $note.Text = 'Program zostanie zamknięty bez odblokowania, a trwający skan przerwany. Kliknij ponownie (przycisk albo krzyżyk okna), aby potwierdzić.'
    $note.Visibility = 'Visible'
    if (-not $st.ExitTimer) {
        $t = New-Object System.Windows.Threading.DispatcherTimer
        $t.Interval = [TimeSpan]::FromSeconds($script:UnlockExitConfirmSec); $t.Tag = $Window
        $t.Add_Tick({ param($s, $e) $s.Stop(); Reset-UnlockExit -Window $s.Tag })
        $st.ExitTimer = $t
    }
    $st.ExitTimer.Stop(); $st.ExitTimer.Start()
}
function Reset-UnlockExit($Window) {
    $Window.Tag.ExitArmed = [datetime]::MinValue
    $Window.FindName('lockExit').Content = New-IconContent -Text 'Zakończ awaryjnie' -Icon 'E7E8' -IconSize 12
    $note = $Window.FindName('lockExitMsg'); $note.Text = ''; $note.Visibility = 'Collapsed'
}
function Unlock-AtStart {
    # $true: można uruchomić program (PIN poprawny, blokada wyłączona albo PIN nie jest wymagany przy starcie)
    if (-not (Test-PinConfigured) -or -not $script:LockCfg.RequireAtStart) { return $true }
    $ok = Invoke-Dialog (New-UnlockWindow -Mode 'Start')
    if (-not $ok) { Write-Log 'Uruchomienie przerwane – nie podano poprawnego PIN-u.' 'WARN' 'Blokada' }
    $ok
}
function Confirm-Pin([string]$Hint) {
    if (-not (Test-PinConfigured)) { return $true }
    Invoke-Dialog (New-UnlockWindow -Mode 'Verify' -Hint $Hint)
}
function Restore-AfterLock {
    # Koniec blokady: zawartość okna głównego i otwartych okien z powrotem (wywołanie wielokrotne bez skutków)
    $script:UnlockState.Locked = $false
    $script:IdleLock.Last = [datetime]::UtcNow
    if ($window -and $window.Content) { $window.Content.Visibility = 'Visible' }
    foreach ($c in @($script:UnlockState.Hidden)) { try { $c.Visibility = 'Visible' } catch { } }
    $script:UnlockState.Hidden = @()
}
function Lock-Program {
    <#
        Blokada w trakcie pracy: zawartość okna głównego (i okien już otwartych, np. ustawień) ukryta, nad nimi okno PIN.
        Okna głównego nie da się ukryć – jest pokazane przez ShowDialog, a ukrycie okna modalnego kończy ShowDialog (i program).
        Skan w tle trwa; okna, które chcą się pokazać w tym czasie, czekają na odblokowanie (Invoke-Dialog).
    #>
    param([int]$IdleMinutes = 0)
    if (-not (Test-PinConfigured) -or $script:UnlockState.Locked -or $script:UnlockState.Emergency -or -not $window) { return }
    $script:UnlockState.Locked = $true
    Write-Log $(if ($IdleMinutes) { "Program zablokowany po $IdleMinutes min bez aktywności." } else { 'Program zablokowany.' }) 'INFO' 'Blokada'
    if ($window.Content) { $window.Content.Visibility = 'Hidden' }
    $script:UnlockState.Hidden = @(foreach ($ow in @($window.OwnedWindows)) {
        $c = $ow.Content
        if ($c -is [System.Windows.UIElement] -and $c.Visibility -eq 'Visible') { $c.Visibility = 'Hidden'; $c }
    })
    $w = New-UnlockWindow -Mode 'Lock'
    try { [void](Invoke-Dialog $w) }
    finally {
        if ($w.Tag.ExitTimer) { $w.Tag.ExitTimer.Stop() }
        if (-not $script:UnlockState.Emergency) { Restore-AfterLock }
    }
    if ($script:UnlockState.Emergency) { Close-ProgramEmergency; return }
    $n = [int]$w.Tag.Failed
    Write-Log ('Program odblokowany{0}.' -f $(if ($n) { " (nieudane próby: $n)" } else { '' })) $(if ($n) { 'WARN' } else { 'INFO' }) 'Blokada'
}
function Close-ProgramEmergency {
    # Zamknięcie awaryjne z ekranu blokady: okna zamykane bez pytań, skan przerywany przy zamykaniu okna głównego
    $busy = @($script:Ops).Count
    Write-Log ('Zamknięcie awaryjne z ekranu blokady (bez PIN-u){0}.' -f $(if ($busy) { ' – przerwano skan' } else { '' })) 'WARN' 'Blokada'
    if (-not $window) { return }
    foreach ($ow in @($window.OwnedWindows)) { try { $ow.Close() } catch { } }
    try { $window.Close() } catch { }
}
function Wait-Unlocked {
    # Okno otwierane w czasie blokady czeka na odblokowanie; okno programu dalej reaguje (zagnieżdżona pętla komunikatów)
    if (-not $script:UnlockState.Locked) { return }
    $frame = New-Object System.Windows.Threading.DispatcherFrame
    $t = New-Object System.Windows.Threading.DispatcherTimer
    $t.Interval = [TimeSpan]::FromMilliseconds(200); $t.Tag = $frame
    $t.Add_Tick({ param($s, $e) if (-not $script:UnlockState.Locked -or $script:UnlockState.Emergency) { $s.Stop(); $s.Tag.Continue = $false } })
    $t.Start()
    [System.Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Register-IdleActivity([System.Windows.Window]$Window) {
    foreach ($ev in [System.Windows.UIElement]::PreviewKeyDownEvent, [System.Windows.UIElement]::PreviewMouseDownEvent, [System.Windows.UIElement]::PreviewMouseWheelEvent) {
        $Window.AddHandler($ev, ($script:UnlockEvents.Activity -as $ev.HandlerType), $true)
    }
}
function Test-ProgramActive {
    # Czy któreś okno programu jest aktywne – ruch myszy w innym programie się nie liczy
    if (-not $window) { return $false }
    if ($window.IsActive) { return $true }
    foreach ($ow in @($window.OwnedWindows)) { if ($ow.IsActive) { return $true } }
    $false
}
function Test-IdleLock {
    # Takt licznika bezczynności (co 15 s); ruch kursora nad aktywnym oknem programu też jest aktywnością
    $st = $script:IdleLock
    $now = [datetime]::UtcNow
    $limit = 0; try { $limit = [int]$Config.LockIdleMinutes } catch { }
    if (-not (Test-PinConfigured) -or $limit -le 0 -or $script:UnlockState.Locked -or -not $window -or -not $window.IsVisible) { $st.Last = $now; return }
    $pos = $null; try { $pos = [System.Windows.Forms.Control]::MousePosition } catch { }
    if ($null -ne $pos -and $null -ne $st.Pos -and $pos -ne $st.Pos -and (Test-ProgramActive)) { $st.Last = $now }
    $st.Pos = $pos
    if (($now - $st.Last).TotalMinutes -ge $limit) { Lock-Program -IdleMinutes $limit }
}
function Start-IdleLock {
    $st = $script:IdleLock
    $st.Last = [datetime]::UtcNow
    if (-not $st.Timer) {
        $t = New-Object System.Windows.Threading.DispatcherTimer
        $t.Interval = [TimeSpan]::FromSeconds(15)
        $t.Add_Tick({ try { Test-IdleLock } catch { Write-Log "Błąd blokady po bezczynności: $($_.Exception.Message)" 'ERROR' 'Blokada' } })
        $st.Timer = $t
    }
    $st.Timer.Start()
}
function Show-SetPinDialog {
    # Nowy PIN (4–8 cyfr) wpisany dwa razy; zwraca PIN albo $null po anulowaniu
    $body = @'
<StackPanel>
  <TextBlock Text="Nowy PIN (4–8 cyfr)" Foreground="#8791A5" FontSize="12" Margin="0,0,0,5"/>
  <PasswordBox x:Name="pin1" MaxLength="8"/>
  <TextBlock Text="Powtórz PIN" Foreground="#8791A5" FontSize="12" Margin="0,12,0,5"/>
  <PasswordBox x:Name="pin2" MaxLength="8"/>
  <TextBlock x:Name="pinMsg" Foreground="#FF7A86" FontSize="12" TextWrapping="Wrap" Margin="0,10,0,0"/>
</StackPanel>
'@
    $validate = {
        param($w)
        $a = $w.FindName('pin1').Password; $b = $w.FindName('pin2').Password
        $m = $w.FindName('pinMsg')
        if ($a -notmatch '^\d{4,8}$') { $m.Text = 'PIN musi mieć od 4 do 8 cyfr.'; return $false }
        if ($a -ne $b) { $m.Text = 'Wpisane PIN-y różnią się.'; return $false }
        $true
    }
    $w = New-Dialog -Title 'PIN blokady programu' -Subtitle 'Odblokowuje program po blokadzie (przycisk z kłódką, Ctrl+Shift+L, bezczynność) i – opcjonalnie – przy uruchomieniu.' -Body $body -Icon 'E72E' -OkText 'Ustaw PIN' -Validate $validate -Width 440
    $w.Add_ContentRendered({ param($s, $e) [void]$s.FindName('pin1').Focus() })
    if (Invoke-Dialog $w) { $w.FindName('pin1').Password } else { $null }
}
#endregion

#region ── Stan programu i lista serwerów ────────────────────────────────────────
$script:Servers        = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
$script:ServerIndex    = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
$script:Data           = @{}
$script:AllIssues      = @()
$script:Cred           = $null
$script:CurrentServer  = $null
$script:CurrentSection = 'Issues'
$script:PendingSection = $null
$script:Refreshing     = $false
$script:FreshScan      = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)   # serwery z wynikiem z bieżącej sesji (wczytywanie z dysku ich nie nadpisze)
$script:FullCache      = New-Object System.Collections.Specialized.OrderedDictionary   # pełne dane ostatnio oglądanych serwerów (LRU)
$script:FullCacheSize  = 6
# Sekcje o dużej liczbie wierszy: po analizie trzymane w pamięci tylko wiersze oznaczone (_Flagged); pełne dane wczytywane
# z migawki przy otwarciu serwera. Przy kilkuset serwerach to setki MB mniej w procesie programu.
$script:HeavyKeys = @('Software', 'Connections', 'Folders', 'SecurityEvents', 'Events', 'Listening', 'Services', 'Tasks', 'AuditPolicy', 'Updates', 'Exposure', 'Autostart', 'Persistence')

function Get-ServerItem([string]$Name) {
    $it = $null
    if ($Name -and $script:ServerIndex.TryGetValue($Name, [ref]$it)) { return $it }
    $null
}
function New-ServerItem([string]$Name, [string]$OS) {
    $disp = Get-DisplayName $Name
    [pscustomobject]@{
        Name = $Name; Display = $disp
        Sub = $(if ($OS) { $OS -replace '^(Microsoft )?Windows Server ', 'Windows Server ' } else { 'jeszcze nie skanowano' })
        Color = '#4A5263'; Crit = 0; Warn = 0; CritVis = 'Collapsed'; WarnVis = 'Collapsed'
        Kind = ''; KindVis = 'Collapsed'; Status = 'none'; HvHost = ''
        _Search = ("$Name $OS").ToLowerInvariant()
    }
}
function Add-ServerEntry([string]$Name, [string]$OS) {
    # Zwraca $true, gdy dodano. Duplikaty po nazwie krótkiej (SRV01 = srv01.firma.local) są pomijane.
    $Name = "$Name".Trim().Trim('"', "'")   # CSV z Export-Csv ma wartości w cudzysłowach (także nagłówek "Name")
    if (-not $Name -or $Name -in 'Name', 'ComputerName', 'DNSHostName', 'HostName', 'Server', 'Serwer') { return $false }
    if (Get-ServerItem $Name) { return $false }
    $disp = Get-DisplayName $Name
    foreach ($it in $script:Servers) { if ($it.Display -eq $disp -and -not (Test-IpAddress $Name)) { return $false } }
    $item = New-ServerItem $Name $OS
    $script:Servers.Add($item)
    $script:ServerIndex[$Name] = $item
    $true
}
function Remove-ServerEntries([object[]]$Items) {
    foreach ($it in @($Items)) {
        if (-not $it) { continue }
        [void]$script:Servers.Remove($it)
        [void]$script:ServerIndex.Remove($it.Name)
        $script:Data.Remove($it.Name)
        $script:FullCache.Remove($it.Name)
        if ($script:CurrentServer -eq $it.Name) { $script:CurrentServer = $null }
    }
}
function Save-ServerList {
    # Plik spoza .txt (np. CSV z inwentaryzacji podany w -ServerListFile) nie jest nadpisywany – lista trafia do servers.txt
    $target = $Config.ServerListFile
    if ([IO.Path]::GetExtension($target) -ne '.txt') {
        $target = Join-Path $Base 'servers.txt'
        if (-not $script:ListRedirected) { Write-Log "Lista serwerów z $($Config.ServerListFile) nie jest nadpisywana – zmiany zapisuję w $target" 'WARN' 'Lista'; $script:ListRedirected = $true }
        $Config.ServerListFile = $target
    }
    try { Set-Content -LiteralPath $target -Value @($script:Servers | ForEach-Object { $_.Name }) -Encoding UTF8 -ErrorAction Stop }
    catch { Write-Log "Nie zapisano listy serwerów ($target): $($_.Exception.Message)" 'ERROR' 'Lista'; Show-Toast 'Nie zapisano listy serwerów – szczegóły w dzienniku' 'crit' }
    if ($ui) { $ui.txtServerCount.Text = "$($script:Servers.Count)" }
}
function Import-ServerFile([string]$Path) {
    $n = 0
    foreach ($l in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $l = "$l".Trim()
        if (-not $l -or $l.StartsWith('#')) { continue }
        if (Add-ServerEntry (($l -split '[,;\s]+')[0])) { $n++ }
    }
    $n
}
function Get-ServersFromAD {
    # Aktywne konta komputerów z systemem Windows Server (Linux dołączony do domeny przez realmd/SSSD też ma „Server” w nazwie
    # systemu – dlatego filtr na „Windows*”), bez nazw wirtualnych klastra (CNO/VCO), logujące się w ostatnich N dniach
    $s = New-Object System.DirectoryServices.DirectorySearcher
    if ($Config.AdSearchBase) { $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($Config.AdSearchBase)") }
    $s.Filter = '(&(objectCategory=computer)(|(operatingSystem=Windows Server*)(operatingSystem=Hyper-V Server*)(operatingSystem=Azure Stack HCI*)(operatingSystem=Windows Storage Server*))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(servicePrincipalName=MSClusterVirtualServer/*)))'
    $s.PageSize = 1000
    [void]$s.PropertiesToLoad.AddRange([string[]]@('dnshostname', 'name', 'operatingsystem', 'lastlogontimestamp'))
    $cut = (Get-Date).AddDays(-[int]$Config.AdInactiveDays)
    $res = $s.FindAll()
    try {
        foreach ($r in $res) {
            $llt = if ($r.Properties['lastlogontimestamp'].Count) { [datetime]::FromFileTime([int64]$r.Properties['lastlogontimestamp'][0]) } else { [datetime]::MinValue }
            if ($llt -lt $cut) { continue }
            $n = if ($r.Properties['dnshostname'].Count) { $r.Properties['dnshostname'][0] } else { $r.Properties['name'][0] }
            [pscustomobject]@{ Name = "$n"; OS = "$($r.Properties['operatingsystem'][0])" }
        }
    } finally { $res.Dispose(); $s.Dispose() }
}

function Get-DataSystem($D) {
    # System z bieżących danych albo – dla serwera bez połączenia – z ostatniej udanej migawki
    if (-not $D) { return $null }
    if ($D.PSObject.Properties['System'] -and $D.System) { return $D.System }
    if ($D.PSObject.Properties['_Last'] -and $D._Last -and $D._Last.System) { return $D._Last.System }
    $null
}
function Update-ServerItem([string]$Name) {
    $it = Get-ServerItem $Name
    $d  = $script:Data[$Name]
    if (-not $it -or -not $d) { return }
    $c = [int]$d._Crit; $w = [int]$d._Warn
    $it.Crit = $c; $it.Warn = $w
    $it.CritVis = if ($c) { 'Visible' } else { 'Collapsed' }
    $it.WarnVis = if ($w) { 'Visible' } else { 'Collapsed' }
    $s = Get-DataSystem $d
    $it.Kind = ''; $it.HvHost = ''
    if ($s) {
        if ($s.IsHyperV) { $it.Kind = 'HV' }
        elseif ($s.PSObject.Properties['IsVirtual'] -and $s.IsVirtual) { $it.Kind = 'VM' }
        if ($s.PSObject.Properties['HvHost'] -and $s.HvHost) { $it.HvHost = Get-DisplayName "$($s.HvHost)" }
    }
    $it.KindVis = if ($it.Kind) { 'Visible' } else { 'Collapsed' }
    $os = if ($s) { "$($s.OS)" -replace '^Microsoft Windows Server ', 'WS ' -replace ' (Standard|Datacenter|Essentials|Evaluation).*$', '' } else { '' }
    if ($d.PSObject.Properties['Unsupported'] -and $d.Unsupported) {
        $it.Status = 'skipped'; $it.Color = '#5E6779'; $it.Sub = "$($d.Unsupported)"
    } elseif ($d.Offline) {
        # kolor wg najpoważniejszego problemu: maszyna wyłączona od dawna (info) albo gość niedostępnego hosta (ostrzeżenie) to nie czerwień
        $it.Status = 'offline'; $it.Color = if ($c) { '#FF5C6C' } elseif ($w) { '#FFB547' } else { '#8791A5' }
        $cls = if ($d.PSObject.Properties['Diag'] -and $d.Diag) { "$($d.Diag.Class)" } else { '' }
        $why = switch ($cls) { 'Dns' { 'brak w DNS' } 'Offline' { 'nie odpowiada' } 'WinRM' { 'WinRM nie działa' } 'Firewall' { 'zapora blokuje WinRM' } 'Auth' { 'odmowa dostępu' } 'Kerberos' { 'błąd Kerberos' } 'TrustedHosts' { 'wymaga TrustedHosts' } 'Timeout' { 'limit czasu' } 'Remote' { 'błąd zbierania danych' } default { 'brak połączenia' } }
        $vm = Find-VmForServer $Name $d
        if ($vm -and "$($vm.Row.State)" -ne 'Running') { $why = "VM $(Get-VmStateText "$($vm.Row.State)") na $($vm.HostDisplay)" }
        elseif (-not $vm -and $cls -notin 'Timeout', 'Remote') {
            $hk = Find-ServerKey (Get-LastHvHost $d)
            if ($hk -and $hk -ne $Name -and (Test-NetworkDown $script:Data[$hk])) { $why = "host $(Get-DisplayName $hk) nie odpowiada" }
        }
        $it.Sub = $why + $(if ($os) { " · $os" })
    } else {
        $it.Status = 'ok'
        $it.Color = if ($c) { '#FF5C6C' } elseif ($w) { '#FFB547' } else { '#34D399' }
        $sub = "$os, uptime $([math]::Round([double]$d.System.UptimeDays)) dni"
        if ($it.HvHost) { $sub += " · na $($it.HvHost)" }
        elseif ($d.System.IsHyperV -and $d.System.PSObject.Properties['HvVmTotal']) { $sub += " · VM: $($d.System.HvVmRunning)/$($d.System.HvVmTotal)" }
        $it.Sub = $sub
    }
    $it._Search = ("$($it.Name) $($it.Sub) $os $($it.HvHost)").ToLowerInvariant()
}
function Refresh-ServerList {
    if (-not $ui) { return }
    $script:Refreshing = $true
    try { $ui.lstServers.Items.Refresh() } finally { $script:Refreshing = $false }
    $ui.txtServerCount.Text = "$($script:Servers.Count)"
}
function Update-ServerFilter {
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:Servers)
    if (-not $view) { return }
    $t = $ui.txtServerFilter.Text.Trim().ToLowerInvariant()
    $mode = if ($ui.sfProblems.IsChecked) { 'problems' } elseif ($ui.sfOffline.IsChecked) { 'offline' } elseif ($ui.sfHosts.IsChecked) { 'hosts' } elseif ($ui.sfVms.IsChecked) { 'vms' } elseif ($ui.sfNew.IsChecked) { 'new' } else { '' }
    if (-not $t -and -not $mode) { $view.Filter = $null; return }
    $view.Filter = [Predicate[object]]({
        param($o)
        switch ($mode) {
            'problems' { if (-not ($o.Crit -or $o.Warn)) { return $false } }
            'offline'  { if ($o.Status -ne 'offline') { return $false } }
            'hosts'    { if ($o.Kind -ne 'HV') { return $false } }
            'vms'      { if ($o.Kind -ne 'VM') { return $false } }
            'new'      { if ($o.Status -ne 'none') { return $false } }
        }
        if ($t) { return "$($o._Search)".Contains($t) }
        $true
    }.GetNewClosure())
}

function New-SlimData($D) {
    # Kopia danych serwera bez dużych sekcji (zostają wiersze oznaczone – raport i podsumowania); pełne dane: Get-ServerFull
    $h = [ordered]@{}
    $fl = @{}
    foreach ($p in $D.PSObject.Properties) {
        if ($script:HeavyKeys -contains $p.Name) {
            $rows = @($p.Value | Where-Object { $_ -and "$($_.Flag)" -and "$($_.Flag)" -ne 'muted' })
            if ($rows.Count) { $fl[$p.Name] = $rows }
            $h[$p.Name] = @()
        } else { $h[$p.Name] = $p.Value }
    }
    $h['_Slim'] = $true
    $h['_Flagged'] = $fl
    [pscustomobject]$h
}
function Set-FullCache([string]$Name, $D) {
    if ($script:FullCache.Contains($Name)) { $script:FullCache.Remove($Name) }
    $script:FullCache.Add($Name, $D)
    while ($script:FullCache.Count -gt $script:FullCacheSize) { $script:FullCache.RemoveAt(0) }
}
function Register-ServerData([string]$Name, $D, $Prev) {
    # Analiza (problemy, flagi wierszy, zmiany), podział na aktywne/wyciszone, lżejsza kopia w pamięci, odświeżenie pozycji listy
    $all = Invoke-ServerAnalysis -Name $Name -D $D -Prev $Prev
    $D | Add-Member -NotePropertyName _AllIssues -NotePropertyValue @($all) -Force
    Split-ServerIssues $Name $D
    $full = -not $D.Offline -and -not ($D.PSObject.Properties['Unsupported'] -and $D.Unsupported) -and -not $D.PSObject.Properties['_Slim']
    if ($full -and $D.PSObject.Properties['_File'] -and $D._File) {
        if ($Name -eq $script:CurrentServer) { Set-FullCache $Name $D } else { $script:FullCache.Remove($Name) }
        $script:Data[$Name] = New-SlimData $D
    } else {
        $script:Data[$Name] = $D
        $script:FullCache.Remove($Name)
    }
    Update-ServerItem $Name
}
function Get-ServerFull([string]$Name) {
    # Pełne dane serwera do widoku szczegółów i pełnego raportu: z pamięci podręcznej albo z migawki na dysku (z ponowną analizą)
    $d = $script:Data[$Name]
    if (-not $d -or -not $d.PSObject.Properties['_Slim']) { return $d }
    if ($script:FullCache.Contains($Name)) {
        $c = $script:FullCache[$Name]
        if ($c -and "$($c._File)" -eq "$($d._File)") { Set-FullCache $Name $c; return $c }
    }
    $full = $null
    if ($d._File -and (Test-Path -LiteralPath $d._File)) { $full = Read-Snapshot $d._File }
    if (-not $full) { return $d }
    $prev = $null
    if ($d.PSObject.Properties['_PrevFile'] -and $d._PrevFile -and (Test-Path -LiteralPath $d._PrevFile)) { $prev = Read-Snapshot $d._PrevFile }
    foreach ($k in 'ScannedAt', '_File', '_PrevFile', '_ScanNote', '_ManualDiag') { if ($d.PSObject.Properties[$k]) { $full | Add-Member -NotePropertyName $k -NotePropertyValue $d.$k -Force } }
    $all = Invoke-ServerAnalysis -Name $Name -D $full -Prev $prev
    $full | Add-Member -NotePropertyName _AllIssues -NotePropertyValue @($all) -Force
    Split-ServerIssues $Name $full
    Set-FullCache $Name $full
    $full
}
#endregion

#region ── Sortowanie tabel ────────────────────────────────────────────────────
# Kolumny generowane z obiektów PowerShell mają typ object, więc DataGrid wyłącza im sortowanie (CanUserSort = false),
# a domyślne porównanie i tak rzuca wyjątek przy typach mieszanych z JSON (np. Int32 12 i Decimal 12.5 w jednej kolumnie).
# Dlatego sortujemy sami: klik w nagłówek – rosnąco → malejąco → kolejność oryginalna, Shift+klik – kolejna kolumna.
# Sortowanie jest pamiętane osobno dla każdej tabeli i sekcji, więc przetrwa odświeżenie w trakcie skanu i zmianę serwera.
$script:GridSort = @{}   # klucz tabeli (np. 'detail:Disks') -> lista @{ Path = właściwość; Desc = $true/$false }
# kolumny z poziomem ważności sortujemy wg wagi, a nie alfabetycznie (rosnąco = najpierw najpoważniejsze)
$script:SeverityOrder = @{ 'Krytyczny' = 0; 'Krytyczne' = 0; 'Błąd' = 1; 'Ostrzeżenie' = 2; 'Uwaga' = 2; 'Info' = 3; 'OK' = 4 }

function Get-SortKeys($Rows, [string]$Path) {
    # Klucze sortowania całej kolumny (jedno wywołanie na kolumnę – wywołanie funkcji na każdą komórkę było za wolne):
    # E = 1 dla pustych (zawsze na końcu), C = 0 liczba / 1 tekst, N = wartość liczbowa,
    # T = tekst z liczbami dopełnionymi zerami do 20 cyfr, żeby porównywały się jak liczby (10.0.2 < 10.0.10, 10.0.0.5 < 10.0.0.12)
    $cnt = $Rows.Count
    $k = @{ E = New-Object 'int[]' $cnt; C = New-Object 'int[]' $cnt; N = New-Object 'double[]' $cnt; T = New-Object 'string[]' $cnt }
    $bySeverity = $Path -in 'Severity', 'Level', 'Status'
    $inv = [Globalization.CultureInfo]::InvariantCulture
    for ($i = 0; $i -lt $cnt; $i++) {
        $v = $Rows[$i].$Path
        $k.T[$i] = ''
        if ($null -eq $v) { $k.E[$i] = 1; continue }
        if ($bySeverity -and $script:SeverityOrder.ContainsKey("$v")) { $k.N[$i] = $script:SeverityOrder["$v"]; continue }
        if ($v -is [datetime]) { $k.N[$i] = $v.Ticks; continue }
        $tc = [int][Type]::GetTypeCode($v.GetType())
        if ($tc -ge 5 -and $tc -le 15) { $k.N[$i] = [double]$v; continue }   # typy liczbowe: SByte … Decimal
        $s = "$v".Trim()
        if (-not $s) { $k.E[$i] = 1; continue }
        # tylko liczby całkowite: „7.10” to wersja (porządek naturalny w kluczu tekstowym), nie liczba 7,1
        if ($s -match '^-?\d{1,15}$') { $k.N[$i] = [double]::Parse($s, $inv); continue }
        $k.C[$i] = 1
        $k.T[$i] = ($s -replace '\d+', '0000000000000000000$&') -replace '(?<!\d)0*(?=\d{20}(?!\d))', ''
    }
    $k
}
function Get-SortedRows($Rows, $Sort) {
    # zawsze zwraca NOWĄ tablicę – Update-GridOrder przestawia potem jej elementy w miejscu
    $Rows = [object[]]@($Rows)
    $Sort = @($Sort | Where-Object { $_ -and $_.Path })
    if ($Rows.Count -lt 2 -or -not $Sort.Count) { return , ([object[]]$Rows.Clone()) }
    $keys  = @(foreach ($s in $Sort) { Get-SortKeys $Rows $s.Path })
    if ($script:NativeOk) {
        # Sortowanie w kodzie natywnym (kilkadziesiąt razy szybciej przy tysiącach wierszy); te same klucze i reguły
        $n = $Sort.Count
        $E = New-Object 'int[][]' $n; $Cc = New-Object 'int[][]' $n; $N = New-Object 'double[][]' $n; $T = New-Object 'string[][]' $n; $desc = New-Object 'bool[]' $n
        for ($j = 0; $j -lt $n; $j++) { $E[$j] = $keys[$j].E; $Cc[$j] = $keys[$j].C; $N[$j] = $keys[$j].N; $T[$j] = $keys[$j].T; $desc[$j] = [bool]$Sort[$j].Desc }
        $idx = [ServerReviewNative.Sorter]::Order($E, $Cc, $N, $T, $desc)
        $out = New-Object 'object[]' $Rows.Count
        for ($i = 0; $i -lt $idx.Length; $i++) { $out[$i] = $Rows[$idx[$i]] }
        return , $out
    }
    $keyed = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $h = [ordered]@{ Row = $Rows[$i]; I = $i }
        for ($j = 0; $j -lt $keys.Count; $j++) {
            $k = $keys[$j]
            $h["E$j"] = $k.E[$i]; $h["C$j"] = $k.C[$i]; $h["N$j"] = $k.N[$i]; $h["T$j"] = $k.T[$i]
        }
        $keyed.Add([pscustomobject]$h)
    }
    $props = New-Object System.Collections.Generic.List[object]
    for ($j = 0; $j -lt $Sort.Count; $j++) {
        $desc = [bool]$Sort[$j].Desc
        $props.Add(@{ Expression = "E$j"; Descending = $false })   # puste na końcu niezależnie od kierunku
        foreach ($k in "C$j", "N$j", "T$j") { $props.Add(@{ Expression = $k; Descending = $desc }) }
    }
    $props.Add(@{ Expression = 'I'; Descending = $false })          # Sort-Object nie jest stabilny – remisy w kolejności oryginalnej
    return , @($keyed | Sort-Object -Property $props.ToArray() | ForEach-Object { $_.Row })
}
function Get-GridSort($Grid) {
    $st = $Grid.Tag
    if ($st -is [hashtable]) { @($script:GridSort[$st.Key] | Where-Object { $_ }) } else { @() }
}
function Get-SortDirection($Sort, [string]$Path) {
    $s = @($Sort | Where-Object { $_.Path -eq $Path })[0]
    if (-not $Path -or -not $s) { $null }
    elseif ($s.Desc) { [System.ComponentModel.ListSortDirection]::Descending }
    else { [System.ComponentModel.ListSortDirection]::Ascending }
}
function Update-GridSortGlyphs($Grid) {
    $sort = @(Get-GridSort $Grid)
    foreach ($c in @($Grid.Columns)) { $c.SortDirection = Get-SortDirection $sort $c.SortMemberPath }
}
function Set-GridRows($Grid, [string]$SortKey, $Rows) {
    # $Rows = kolejność oryginalna; do tabeli trafia jej kopia ułożona wg zapamiętanego sortowania
    $orig  = [object[]]@($Rows)
    $items = Get-SortedRows $orig @($script:GridSort[$SortKey] | Where-Object { $_ })
    $Grid.Tag = @{ Key = $SortKey; Rows = $orig; Items = $items }   # przed ItemsSource – korzysta z niego AutoGeneratingColumn
    $Grid.ItemsSource = $items
    Update-GridSortGlyphs $Grid   # zmiana ItemsSource czyści strzałki kolumn zdefiniowanych w XAML
}
function Update-GridOrder($Grid) {
    $st = $Grid.Tag
    if (-not ($st -is [hashtable]) -or $null -eq $st.Items) { return }
    $sorted = Get-SortedRows $st.Rows @(Get-GridSort $Grid)
    # przestawiamy elementy w tej samej tablicy: tabela zachowuje kolumny (i ich szerokości), filtr oraz zaznaczenie
    [Array]::Copy($sorted, $st.Items, $st.Items.Length)
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($st.Items)
    if ($view) { $view.Refresh() }
    Update-GridSortGlyphs $Grid
}
function Invoke-GridSort($Grid, $Column) {
    $st   = $Grid.Tag
    $path = "$($Column.SortMemberPath)"
    if (-not ($st -is [hashtable]) -or -not $path) { return }
    $cur  = @(Get-GridSort $Grid)
    $old  = @($cur | Where-Object { $_.Path -eq $path })[0]
    # kolejne kliknięcia: rosnąco → malejąco → bez sortowania (kolejność z kolektora / domyślna)
    $step = if (-not $old) { @{ Path = $path; Desc = $false } } elseif (-not $old.Desc) { @{ Path = $path; Desc = $true } } else { $null }
    if ([System.Windows.Input.Keyboard]::Modifiers.HasFlag([System.Windows.Input.ModifierKeys]::Shift)) {
        # Shift+klik: zmienia tylko tę kolumnę, pozostałe kolumny sortowania zostają
        $new = @(foreach ($s in $cur) { if ($s.Path -ne $path) { $s } elseif ($step) { $step } })
        if (-not $old -and $step) { $new += $step }
    } else {
        $new = @(if ($step) { $step })
    }
    $script:GridSort[$st.Key] = $new
    Update-GridOrder $Grid
}
function Get-ClickedRowItem($e) {
    # element wiersza, w który kliknięto; dwuklik w nagłówek (np. szybka zmiana kierunku sortowania) lub pasek przewijania nie otwiera serwera
    $o = $e.OriginalSource
    while ($o) {
        if ($o -is [System.Windows.Controls.DataGridRow]) { return $o.Item }
        if ($o -is [System.Windows.Controls.Primitives.DataGridColumnHeader] -or $o -is [System.Windows.Controls.Primitives.ScrollBar] -or $o -is [System.Windows.Controls.DataGrid]) { return $null }
        $o = if ($o -is [System.Windows.Media.Visual]) { [System.Windows.Media.VisualTreeHelper]::GetParent($o) } else { [System.Windows.LogicalTreeHelper]::GetParent($o) }
    }
    $null
}
#endregion

#region ── Widok ogólny ─────────────────────────────────────────────────────────
function Get-AvailabilityText([string]$Name) {
    if (-not $script:AvailStats) { return '' }
    $st = $script:AvailStats[$Name.ToLowerInvariant()]
    if (-not $st -or -not $st.Seen) { return '' }
    '{0}/{1} ({2}%)' -f $st.Ok, $st.Seen, [math]::Round(100.0 * $st.Ok / $st.Seen)
}
function Get-OverviewData([bool]$ShowIgnored = $false) {
    # Problemy i wiersze tabeli „Stan serwerów” – wspólne dla widoku, raportu HTML i trybu bez okna
    $showIgnored = $ShowIgnored
    $all = New-Object System.Collections.Generic.List[object]
    $sum = New-Object System.Collections.Generic.List[object]
    $online = 0; $offline = 0; $crit = 0; $warn = 0; $ign = 0
    foreach ($it in $script:Servers) {
        $d = $script:Data[$it.Name]
        if (-not $d) { continue }
        foreach ($i in @($(if ($showIgnored) { $d._Ignored } else { $d._Issues }))) { if ($i) { $all.Add($i) } }
        $crit += [int]$d._Crit; $warn += [int]$d._Warn; $ign += @($d._Ignored).Count
        $st = if ($script:AvailStats) { $script:AvailStats[$it.Name.ToLowerInvariant()] } else { $null }
        $base = [ordered]@{ Key = $it.Name; Server = $it.Display; Status = ''; Kind = $it.Kind; OS = ''; HvHost = $it.HvHost; UptimeDays = $null; CPU = $null; RAM = $null; MinDiskPct = $null; PatchDays = $null
                            Crit = [int]$d._Crit; Warn = [int]$d._Warn; Availability = (Get-AvailabilityText $it.Name); LastOk = $(if ($st) { $st.LastOk } else { '' }); ScanSec = $null; Scanned = $d.ScannedAt; Flag = '' }
        if ($d.PSObject.Properties['Unsupported'] -and $d.Unsupported) {
            $base.Status = 'Pominięty'; $base.Flag = 'muted'; $base.OS = "$($d.Unsupported)"
        } elseif ($d.Offline) {
            $offline++
            $s = Get-DataSystem $d
            $base.Status = 'Brak połączenia'; $base.Flag = $(if ($d._Crit) { 'crit' } else { 'warn' })
            $base.OS = $(if ($d.PSObject.Properties['Diag'] -and $d.Diag) { "$($d.Diag.Cause)" } else { Get-ShortText $d.Error 120 })
            if ($s -and -not $base.HvHost -and $s.PSObject.Properties['HvHost'] -and $s.HvHost) { $base.HvHost = Get-DisplayName "$($s.HvHost)" }
        } else {
            $online++
            $s = $d.System
            $base.Status = 'OK'; $base.OS = "$($s.OS)" -replace '^Microsoft ', ''
            $base.UptimeDays = $s.UptimeDays; $base.CPU = $s.CpuLoad; $base.RAM = $s.RamUsedPct
            $base.MinDiskPct = (@($d.Disks) | Where-Object { $_ } | Measure-Object FreePct -Minimum).Minimum
            $base.PatchDays = $(if ($s.LastHotfixDays -ge 0) { $s.LastHotfixDays } else { $null })
            $base.ScanSec = $d.DurationSec
            $base.Flag = $(if ($d._Crit) { 'crit' } elseif ($d._Warn) { 'warn' } else { '' })
        }
        $sum.Add([pscustomobject]$base)
    }
    if (-not $showIgnored) {
        foreach ($i in @($script:ClusterIssues)) { if ($i) { $all.Add($i); if ($i.Rank -eq 0) { $crit++ } elseif ($i.Rank -eq 1) { $warn++ } } }
        $sc = Get-StationClockIssue
        if ($sc -and -not (Test-IssueIgnored '(stacja)' $sc.IssueKey)) { $all.Add($sc); $warn++ }
        $sn = $script:StationNetIssue
        if ($sn -and -not (Test-IssueIgnored '(stacja)' $sn.IssueKey)) { $all.Add($sn); $crit++ }
    }
    $hosts = 0; $vmRun = 0; $vmAll = 0
    foreach ($d in $script:Data.Values) { if ($d -and -not $d.Offline -and $d.PSObject.Properties['System'] -and $d.System -and $d.System.IsHyperV) { $hosts++; $vmRun += [int]$d.System.HvVmRunning; $vmAll += [int]$d.System.HvVmTotal } }
    @{
        Issues  = (Get-SortedRows ([object[]]$all.ToArray()) @(@{ Path = 'Rank'; Desc = $false }, @{ Path = 'Server'; Desc = $false }))
        Servers = (Get-SortedRows ([object[]]$sum.ToArray()) @(@{ Path = 'Crit'; Desc = $true }, @{ Path = 'Warn'; Desc = $true }, @{ Path = 'Server'; Desc = $false }))
        Online = $online; Offline = $offline; Crit = $crit; Warn = $warn; Ignored = $ign; Hosts = $hosts; VmRun = $vmRun; VmAll = $vmAll
    }
}
function Update-Overview {
    $showIgnored = [bool]$ui.chkIgnored.IsChecked
    $o = Get-OverviewData $showIgnored
    $script:AllIssues = $o.Issues
    Set-GridRows $ui.gridIssues 'issues' $script:AllIssues
    Update-IssueFilter
    $ui.txtIssuesTitle.Text = if ($showIgnored) { 'Wyciszone problemy' } else { 'Wykryte problemy' }
    $ui.chkIgnored.Content = if ($o.Ignored) { "Wyciszone ($($o.Ignored))" } else { 'Wyciszone' }
    $ui.gridServers.Columns.Clear()
    Set-GridRows $ui.gridServers 'servers' $o.Servers
    $ui.tTotal.Text   = "$($script:Servers.Count)"
    $ui.tOnline.Text  = "$($o.Online)"
    $ui.tOffline.Text = "$($o.Offline)"
    $ui.tOffline.Foreground = Brush $(if ($o.Offline) { '#FF7A86' } else { '#E4E8EF' })
    $ui.tCrit.Text    = "$($o.Crit)"
    $ui.tWarn.Text    = "$($o.Warn)"
    $ui.tHv.Text = if ($o.Hosts) { "$($o.Hosts) / $($o.VmRun)" } else { '0' }
    $ui.tileHv.ToolTip = "Hosty Hyper-V: $($o.Hosts), maszyny działające: $($o.VmRun) z $($o.VmAll) – kliknij, aby otworzyć widok Hyper-V"
}
function Update-IssueFilter {
    if ($null -eq $ui.gridIssues.ItemsSource) { return }
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridIssues.ItemsSource)
    if (-not $view) { return }
    $t = $ui.txtIssueFilter.Text.Trim().ToLowerInvariant()
    $rank = if ($ui.rbSevCrit.IsChecked) { 0 } elseif ($ui.rbSevWarn.IsChecked) { 1 } elseif ($ui.rbSevInfo.IsChecked) { 2 } else { -1 }
    if (-not $t -and $rank -lt 0) { $view.Filter = $null }
    else {
        $view.Filter = [Predicate[object]]({
            param($o)
            if ($rank -ge 0 -and $o.Rank -ne $rank) { return $false }
            if ($t) { return "$($o._Search)".Contains($t) }
            $true
        }.GetNewClosure())
    }
    $ui.txtIssuesCount.Text = "$(@($view).Count) z $(@($ui.gridIssues.ItemsSource).Count)"
}
#endregion

#region ── Widok Hyper-V (wszystkie hosty i maszyny) ────────────────────────────
function Get-ServerByGuest([hashtable]$ByDisplay, $Row) {
    $g = "$($Row.PSObject.Properties['GuestFQDN'].Value)"
    if ($g) { $it = $ByDisplay[(Get-DisplayName $g)]; if ($it) { return $it } }
    $ByDisplay["$($Row.Name)".ToUpperInvariant()]
}
function Get-VmData {
    if (-not $script:VmIndex) { Update-VmIndex }
    $byDisplay = @{}
    foreach ($it in $script:Servers) { if (-not $byDisplay.ContainsKey($it.Display)) { $byDisplay[$it.Display] = $it } }
    # Hosty
    $hosts = New-Object System.Collections.Generic.List[object]
    $oldCp = 0; $cpuSum = 0; $ramSum = 0.0; $run = 0; $tot = 0
    foreach ($it in $script:Servers) {
        $d = $script:Data[$it.Name]
        if (-not $d -or $d.Offline -or -not $d.PSObject.Properties['System'] -or -not $d.System -or -not $d.System.IsHyperV) { continue }
        $s = $d.System
        $lp = [int]$s.HvLogicalCpus; $vr = [int]$s.HvVcpuRunning; $ram = [double]$s.RamGB; $as = [double]$s.HvRamAssignedGB
        $ratio = if ($lp) { [math]::Round($vr / $lp, 2) } else { $null }
        $pct = if ($ram) { [math]::Round($as / $ram * 100) } else { $null }
        $cp = @($d.Checkpoints | Where-Object { $_ -and "$($_.Type)" -notlike '*Replica' -and [double]$_.AgeDays -gt $Config.CheckpointWarnDays }).Count   # jak w analizie
        $oldCp += $cp; $cpuSum += $vr; $ramSum += $as; $run += [int]$s.HvVmRunning; $tot += [int]$s.HvVmTotal
        $flag = if ($d._Crit) { 'crit' } elseif (($ratio -and $ratio -gt $Config.VcpuRatioWarn) -or ($pct -and $pct -ge $Config.HostRamWarnPct)) { 'warn' } else { '' }
        $hosts.Add([pscustomobject]@{
            Key = $it.Name; Host = $it.Display; HvCluster = $(if ($s.PSObject.Properties['HvCluster']) { "$($s.HvCluster)" } else { '' })
            Vms = "$($s.HvVmRunning) / $($s.HvVmTotal)"; VCpuRatio = $(if ($ratio) { "$vr / $lp ($ratio : 1)" } else { '' }); RamPct = $pct
            HvRamAssignedGB = $as; RamGB = $ram; Checkpoints = $cp; Crit = [int]$d._Crit; Warn = [int]$d._Warn; Scanned = $d.ScannedAt; Flag = $flag
        })
    }
    # Maszyny
    $vms = New-Object System.Collections.Generic.List[object]
    $linux = 0
    foreach ($e in @($script:VmIndex.All)) {
        $r = $e.Row
        $lin = "$($r.PSObject.Properties['Linux'].Value)" -eq 'Tak'
        $rpl = "$($r.PSObject.Properties['ReplicationMode'].Value)" -match 'Replica'
        if ($lin) { $linux++ }
        $srv = if ($rpl) { $null } else { Get-ServerByGuest $byDisplay $r }
        $gst = if ($rpl) { 'replika (Hyper-V Replica)' } elseif ($lin) { 'Linux – nie skanujemy' } elseif (-not $srv) { '' } else { switch ($srv.Status) { 'ok' { "OK$(if ($srv.Crit) { ", krytyczne: $($srv.Crit)" } elseif ($srv.Warn) { ", ostrzeżenia: $($srv.Warn)" })" } 'offline' { 'Brak połączenia' } 'skipped' { 'Pominięty' } default { 'Nieskanowany' } } }
        $flag = "$($r.Flag)"
        if (-not $flag -and $srv -and $srv.Status -eq 'offline' -and "$($r.State)" -eq 'Running') { $flag = 'warn' }
        $vms.Add([pscustomobject]@{
            Host = $e.HostDisplay; VM = $r.Name; State = "$($r.State)"; Heartbeat = "$($r.Heartbeat)"; UptimeDays = $r.UptimeDays; CPU = $r.CPU; MemGB = $r.MemGB
            DynamicMem = $r.DynamicMem; Gen = $r.Gen; Version = "$($r.Version)"; Replication = "$($r.Replication)"; Checkpoints = $r.PSObject.Properties['Checkpoints'].Value
            DisksGB = $r.DisksGB; GuestOS = "$($r.PSObject.Properties['GuestOS'].Value)"; GuestFQDN = "$($r.PSObject.Properties['GuestFQDN'].Value)"; GuestIP = "$($r.PSObject.Properties['GuestIP'].Value)"
            OnList = $(if ($srv) { 'Tak' } else { '' }); GuestStatus = $gst; Flag = $(if (($lin -or $rpl) -and -not $flag) { 'muted' } else { $flag })
            _HostKey = $e.Host; _ServerKey = $(if ($srv) { $srv.Name } else { '' }); _Linux = ($lin -or $rpl)
            _Search = ("$($e.HostDisplay) $($r.Name) $($r.State) $($r.PSObject.Properties['GuestOS'].Value) $($r.PSObject.Properties['GuestFQDN'].Value) $($r.PSObject.Properties['GuestIP'].Value) $gst").ToLowerInvariant()
        })
    }
    @{ Hosts = [object[]]$hosts.ToArray(); Vms = (Get-SortedRows ([object[]]$vms.ToArray()) @(@{ Path = 'Host'; Desc = $false }, @{ Path = 'VM'; Desc = $false })); Run = $run; Total = $tot; Cpu = $cpuSum; Ram = $ramSum; OldCheckpoints = $oldCp; Linux = $linux }
}
function Update-VmView {
    $v = Get-VmData
    $ui.gridHosts.Columns.Clear()
    Set-GridRows $ui.gridHosts 'vmhosts' $v.Hosts
    $ui.gridVms.Columns.Clear()
    Set-GridRows $ui.gridVms 'vms' $v.Vms
    Update-VmFilter
    $ui.vHosts.Text = "$(@($v.Hosts).Count)"
    $ui.vVms.Text = "$($v.Run) / $($v.Total)"
    $ui.vCpu.Text = "$($v.Cpu)"
    $ui.vRam.Text = "$([math]::Round($v.Ram))"
    $ui.vCheckpoints.Text = "$($v.OldCheckpoints)"
    $ui.vLinux.Text = "$($v.Linux)"
}
function Update-VmFilter {
    if ($null -eq $ui.gridVms.ItemsSource) { return }
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridVms.ItemsSource)
    if (-not $view) { return }
    $t = $ui.txtVmFilter.Text.Trim().ToLowerInvariant()
    $mode = if ($ui.vfRunning.IsChecked) { 'run' } elseif ($ui.vfOff.IsChecked) { 'off' } elseif ($ui.vfProblems.IsChecked) { 'prob' } elseif ($ui.vfNotListed.IsChecked) { 'nl' } else { '' }
    if (-not $t -and -not $mode) { $view.Filter = $null }
    else {
        $view.Filter = [Predicate[object]]({
            param($o)
            switch ($mode) {
                'run'  { if ($o.State -ne 'Running') { return $false } }
                'off'  { if ($o.State -eq 'Running') { return $false } }
                'prob' { if ($o.Flag -notin 'warn', 'crit') { return $false } }
                'nl'   { if ($o.OnList -or $o._Linux) { return $false } }
            }
            if ($t) { return "$($o._Search)".Contains($t) }
            $true
        }.GetNewClosure())
    }
    $ui.txtVmCount.Text = "$(@($view).Count) z $(@($ui.gridVms.ItemsSource).Count)"
}
function Add-VmsToList {
    # Maszyny Windows spoza listy (zaznaczone albo wszystkie widoczne) → lista serwerów; Linux pomijany
    $sel = @($ui.gridVms.SelectedItems)
    if (-not $sel.Count) { $sel = @([System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridVms.ItemsSource)) }
    $cand = @($sel | Where-Object { $_ -and -not $_.OnList -and -not $_._Linux })
    if (-not $cand.Count) { Show-Toast 'Brak maszyn Windows spoza listy wśród wybranych.' 'info'; return }
    $names = @($cand | ForEach-Object { if ($_.GuestFQDN) { $_.GuestFQDN } else { $_.VM } } | Sort-Object -Unique)
    $unknown = @($cand | Where-Object { -not $_.GuestOS }).Count
    $txt = "Dodać do listy serwerów maszyny ($($names.Count)): $(Join-Short $names 12)?"
    if ($unknown) { $txt += "`n`nU $unknown maszyn system gościa jest nieznany (np. maszyna wyłączona) – jeśli to Linux, zostanie rozpoznany i pominięty po skanie hosta." }
    if (-not (Confirm-Action -Text $txt -Title 'Dodaj maszyny do listy' -ConfirmText 'Dodaj' -Tone 'info')) { return }
    $n = 0
    foreach ($x in $names) { if (Add-ServerEntry $x) { $n++ } }
    Save-ServerList
    Write-Log "Dodano do listy maszyny wirtualne: $n ($(Join-Short $names 10))" 'OK' 'Lista'
    Show-Toast "Dodano maszyn: $n" 'ok'
    Refresh-ServerList
    Request-UiRefresh -All
}
#endregion

#region ── Widok serwera ────────────────────────────────────────────────────────
function Add-Chip([string]$Text, [string]$Kind = '', [string]$Tip = '') {
    $fg, $bg = switch ($Kind) {
        'warn' { '#FFC46B', '#26FFB547' }
        'crit' { '#FF7A86', '#26FF5C6C' }
        'ok'   { '#5EE3AE', '#2034D399' }
        'info' { '#8CB0FF', '#1E2A44' }
        default { '#C3CAD6', '#1E252F' }
    }
    $b = New-Object System.Windows.Controls.Border
    $b.CornerRadius = New-Object System.Windows.CornerRadius 7
    $b.Padding = New-Object System.Windows.Thickness -ArgumentList 10, 3, 10, 3
    $b.Margin  = New-Object System.Windows.Thickness -ArgumentList 0, 0, 6, 6
    $b.Background = Brush $bg
    if ($Tip) { $b.ToolTip = $Tip }
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = $Text; $tb.FontSize = 12; $tb.Foreground = Brush $fg
    $b.Child = $tb
    [void]$ui.dChips.Children.Add($b)
}
function Get-MetricColor($v) { if ($v -ge 90) { '#FF5C6C' } elseif ($v -ge 75) { '#FFB547' } else { '#34D399' } }

function Get-StatusFlag([string]$Status) { switch ($Status) { 'Błąd' { 'crit' } 'Krytyczne' { 'crit' } 'Uwaga' { 'warn' } 'Info' { 'info' } default { '' } } }
function Get-DiagnosticsRows([string]$Name, $D) {
    # Sekcja „Diagnoza połączenia”: przyczyna, zalecenie, stan maszyny na hoście Hyper-V i wyniki prób ze stacji
    $dg = $null
    if ($D.PSObject.Properties['_ManualDiag'] -and $D._ManualDiag) { $dg = $D._ManualDiag }
    elseif ($D.PSObject.Properties['Diag'] -and $D.Diag) { $dg = $D.Diag }
    $rows = New-Object System.Collections.Generic.List[object]
    if ($dg) {
        $rows.Add([pscustomobject]@{ Check = 'Przyczyna'; Value = "$($dg.Cause)"; Status = $(if ($D.Offline) { 'Błąd' } else { 'Info' }); Flag = $(if ($D.Offline) { 'crit' } else { 'info' }) })
        if ($dg.Remedy) { $rows.Add([pscustomobject]@{ Check = 'Zalecenie'; Value = "$($dg.Remedy)"; Status = 'Info'; Flag = 'info' }) }
        if ($dg.Notes) { $rows.Add([pscustomobject]@{ Check = 'Uwagi'; Value = "$($dg.Notes)"; Status = 'Uwaga'; Flag = 'warn' }) }
    }
    $vm = Find-VmForServer $Name $D
    if ($vm) {
        $st = "$($vm.Row.State)"
        $rows.Add([pscustomobject]@{ Check = 'Maszyna wirtualna na hoście'; Value = "$($vm.Row.Name) na $($vm.HostDisplay): $(Get-VmStateText $st)$(if ("$($vm.Row.Heartbeat)") { ", heartbeat: $($vm.Row.Heartbeat)" }) (dane z $($vm.ScannedAt))"; Status = $(if ($st -ne 'Running') { 'Uwaga' } else { 'Info' }); Flag = $(if ($st -ne 'Running') { 'warn' } else { 'info' }) })
    } elseif ($D.Offline -and ($lh = Get-LastHvHost $D)) {
        # maszyny nie ma w danych żadnego dostępnego hosta – pokaż host z ostatnich danych gościa i jego stan
        $hk = Find-ServerKey $lh
        $hd = $hk -and (Test-NetworkDown $script:Data[$hk])
        $rows.Add([pscustomobject]@{ Check = 'Host Hyper-V (wg ostatnich danych)'; Value = "$(Get-DisplayName $lh)$(if ($hd) { ' – też nie odpowiada' } elseif ($hk -and $script:Data[$hk] -and $script:Data[$hk].Offline) { ' – skan hosta też się nie udał (przyczyna w szczegółach hosta)' } elseif (-not $hk) { ' – nie ma go na liście serwerów (dodaj go, żeby widzieć stan maszyny)' } else { ' – maszyny nie ma na tym hoście (przeniesiona albo usunięta?)' })"; Status = $(if ($hd) { 'Uwaga' } else { 'Info' }); Flag = $(if ($hd) { 'warn' } else { 'info' }) })
    }
    if ($D.PSObject.Properties['_Last'] -and $D._Last) {
        $ls = $D._Last
        $rows.Add([pscustomobject]@{ Check = 'Ostatnie udane dane'; Value = "$($ls.ScannedAt)$(if ($ls.System) { " – $($ls.System.OS)$(if ($ls.IPv4) { ", $($ls.IPv4)" })" })"; Status = 'Info'; Flag = '' })
    }
    if ($dg) {
        foreach ($c in @($dg.Checks)) { if ($c) { $rows.Add([pscustomobject]@{ Check = "$($c.Check)"; Value = "$($c.PSObject.Properties['Value'].Value)$($c.PSObject.Properties['Result'].Value)"; Status = "$($c.Status)"; Flag = (Get-StatusFlag "$($c.Status)") }) } }
        $rows.Add([pscustomobject]@{ Check = 'Czas diagnozy'; Value = "$($dg.DurationSec) s"; Status = ''; Flag = '' })
    }
    [object[]]$rows.ToArray()
}
function Get-SectionRows($D, [string]$Key, [string]$Name = $script:CurrentServer) {
    switch ($Key) {
        'Issues' {
            # aktywne problemy, a na końcu wyciszone (wyszarzone) – prawy klik przywraca
            @(foreach ($i in @($D._Issues) + @($D._Ignored)) {
                if (-not $i) { continue }
                [pscustomobject]@{ Severity = $(if ($i.Ignored) { "$($i.Severity) (wyciszony)" } else { $i.Severity }); Category = $i.Category; Message = $i.Message; Flag = $(if ($i.Ignored) { 'muted' } else { $i.Flag }); _Issue = $i }
            })
        }
        'Changes'     { @($D._Changes | Where-Object { $_ }) }
        'Diagnostics' { @(Get-DiagnosticsRows $Name $D) }
        'History'     { @(Get-AvailabilityHistory $Name) }
        'HvHost'      { @($D._HvHost | Where-Object { $_ }) }
        'System'  {
            if ($D.System) {
                foreach ($p in $D.System.PSObject.Properties) {
                    $v = if ($p.Value -is [bool]) { if ($p.Value) { 'Tak' } else { 'Nie' } } else { "$($p.Value)" }
                    $f = if (($p.Name -eq 'PendingReboot' -and $p.Value) -or ($p.Name -eq 'UptimeDays' -and $p.Value -gt $Config.UptimeWarnDays) -or
                             ($p.Name -eq 'LastHotfixDays' -and $p.Value -gt $Config.PatchWarnDays) -or
                             ($p.Name -eq 'CommitUsedPct' -and "$($p.Value)" -ne '' -and $p.Value -ge $Config.CommitWarnPct) -or
                             ($p.Name -eq 'ResourceExhaustion' -and $p.Value -gt 0) -or
                             ($p.Name -eq 'TimeOffsetSec' -and "$($p.Value)" -ne '' -and [math]::Abs([double]$p.Value - $script:StationOffset) -ge $Config.TimeSkewWarnSec)) { 'warn' } else { '' }
                    [pscustomobject]@{ Property = (Get-Header $p.Name); Value = $v; Flag = $f }
                }
            }
        }
        default {
            $rows = @($D.$Key | Where-Object { $null -ne $_ })
            # lekka kopia danych: z dużych sekcji zostały tylko wiersze oznaczone
            if (-not $rows.Count -and $D.PSObject.Properties['_Slim'] -and $D._Flagged -and $D._Flagged.ContainsKey($Key)) { $rows = @($D._Flagged[$Key]) }
            $rows
        }
    }
}
function Test-SectionShown($D, [string]$Key) {
    if ($D.PSObject.Properties['Unsupported'] -and $D.Unsupported) { return ($Key -in 'Issues', 'History') }
    if ($D.Offline) { return ($Key -in 'Issues', 'Diagnostics', 'History') }
    if ($Key -eq 'Diagnostics') { return [bool]($D.PSObject.Properties['_ManualDiag'] -and $D._ManualDiag) }
    if (@($D.Skipped) -contains $Key) { return $false }                     # pominięta w ustawieniach skanu
    if ($Key -in 'HyperV', 'Checkpoints', 'VMStorage', 'HvHost' -and -not $D.System.IsHyperV) { return $false }
    if ($Key -eq 'LocalUsers' -and $D.System.IsDC) { return $false }
    if ($Key -eq 'DomainController' -and -not $D.System.IsDC) { return $false }
    if ($Key -eq 'Cluster' -and -not ($D.System.PSObject.Properties['HvCluster'] -and $D.System.HvCluster) -and -not @($D.PSObject.Properties['Cluster'].Value | Where-Object { $_ }).Count) { return $false }
    if ($Key -in 'Downtime', 'Timings' -and -not $D.PSObject.Properties[$Key]) { return $false }   # starsze migawki
    $true
}
function Get-WorstFlag($Rows) {
    $f = @($Rows | ForEach-Object { "$($_.Flag)" })
    if ($f -contains 'crit') { 'crit' } elseif ($f -contains 'warn') { 'warn' } elseif ($f -contains 'info') { 'info' } else { '' }
}

function Show-ServerDetail([string]$Name) {
    $script:CurrentServer = $Name
    $ui.dChips.Children.Clear()
    $item = if ($Name) { Get-ServerItem $Name } else { $null }
    $ui.btnRescan.IsEnabled = [bool]$item -and -not (Get-Operation 'Scan')
    $ui.btnDiag.IsEnabled = [bool]$item
    $d = if ($Name) { $script:Data[$Name] } else { $null }
    $ui.dCpu.Text = '–'; $ui.dRam.Text = '–'; $ui.pCpu.Value = 0; $ui.pRam.Value = 0; $ui.dCrit.Text = '0'; $ui.dWarn.Text = '0'
    $clear = { $ui.lstSections.ItemsSource = $null; $ui.gridDetail.ItemsSource = $null; $ui.gridDetail.Tag = $null; $ui.dSectionTitle.Text = ''; $ui.dSectionCount.Text = ''; $ui.dRowDetail.Text = '' }
    if (-not $item) { $ui.dName.Text = 'Wybierz serwer z listy po lewej'; $ui.dOS.Text = ''; & $clear; return }
    $ui.dName.Text = $item.Display
    if (-not $d) { $ui.dOS.Text = "$Name – jeszcze nie skanowano. Użyj przycisku Skanuj ponownie."; & $clear; return }
    if (-not $d.Offline -and $d.PSObject.Properties['_Slim']) {
        $old = $window.Cursor; $window.Cursor = [System.Windows.Input.Cursors]::Wait
        try { $d = Get-ServerFull $Name } finally { $window.Cursor = $old }
    }
    $ui.dCrit.Text = "$($d._Crit)"; $ui.dWarn.Text = "$($d._Warn)"
    $av = if ($script:AvailStats) { $script:AvailStats[$Name.ToLowerInvariant()] } else { $null }
    if ($d.PSObject.Properties['Unsupported'] -and $d.Unsupported) {
        $ui.dOS.Text = "$Name – $($d.Unsupported)"
        Add-Chip 'Nie skanujemy' ''
    } elseif ($d.Offline) {
        $ls = Get-DataSystem $d
        $ui.dOS.Text = "$Name – brak połączenia$(if ($ls) { " (ostatnio: $($ls.OS))" })"
        $cause = if ($d.PSObject.Properties['Diag'] -and $d.Diag) { "$($d.Diag.Cause)" } else { Get-ShortText $d.Error 120 }
        Add-Chip "Próba: $($d.ScannedAt)" 'crit'
        Add-Chip (Get-ShortText $cause 90) 'crit' $cause
        if ($av -and $av.FailSince) { Add-Chip "Bez połączenia od $($av.FailSince)" 'warn' }
        if ($av -and $av.LastOk) { Add-Chip "Ostatni udany skan $($av.LastOk)" }
        elseif ($d.PSObject.Properties['_Last'] -and $d._Last) { Add-Chip "Ostatnie dane z $($d._Last.ScannedAt)" }
        $vm = Find-VmForServer $Name $d
        if ($vm) { Add-Chip "VM $($vm.Row.Name) na $($vm.HostDisplay): $(Get-VmStateText "$($vm.Row.State)")" $(if ("$($vm.Row.State)" -ne 'Running') { 'warn' } else { 'info' }) }
        if ($d.PSObject.Properties['Diag'] -and $d.Diag -and $d.Diag.Ip) { Add-Chip "IP $($d.Diag.Ip)" }
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
        if ($s.IsHyperV) { Add-Chip "Host Hyper-V, maszyny $(if ($s.PSObject.Properties['HvVmTotal']) { "$($s.HvVmRunning)/$($s.HvVmTotal)" } else { @($d.HyperV).Count })" 'info' }
        if ($s.PSObject.Properties['HvCluster'] -and $s.HvCluster) { Add-Chip "Klaster $($s.HvCluster)" 'info' $s.HvClusterNodes }
        if ($s.PSObject.Properties['HvHost'] -and $s.HvHost) { Add-Chip "VM na $(Get-DisplayName "$($s.HvHost)")" 'info' "Maszyna $($s.HvVmName) na hoście $($s.HvHost)" }
        elseif ($s.PSObject.Properties['Hypervisor'] -and $s.Hypervisor) { Add-Chip "Maszyna wirtualna ($($s.Hypervisor))" 'info' }
        if ($s.AV) { Add-Chip "$($s.AV)" }
        if ($s.PSObject.Properties['TimeOffsetSec'] -and "$($s.TimeOffsetSec)" -ne '') { $o = [math]::Round([double]$s.TimeOffsetSec - $script:StationOffset, 1); Add-Chip "Czas $(if ($o -gt 0) { '+' })$o s" $(if ([math]::Abs($o) -ge $Config.TimeSkewWarnSec) { 'warn' } else { '' }) }
        if (@($d.Skipped | Where-Object { $_ }).Count) { Add-Chip "Pominięte sekcje: $(@($d.Skipped | Where-Object { $_ }).Count)" }
        if (@($d._Ignored).Count) { Add-Chip "Wyciszone problemy: $(@($d._Ignored).Count)" }
        if ($av -and $av.Seen) { Add-Chip "Dostępność 30 dni: $(Get-AvailabilityText $Name)" $(if ($av.Ok -lt $av.Seen) { 'warn' } else { 'ok' }) }
        Add-Chip "$($s.Cores) vCPU, $($s.RamGB) GB RAM"
        Add-Chip "Skan $($d.ScannedAt), $($d.DurationSec) s" '' $(Join-Short (@($d.Timings) | Select-Object -First 5 | ForEach-Object { "$($_.Section) $($_.Sec) s" }) 5)
        $ui.dCpu.Text = "$($s.CpuLoad)%"; $ui.pCpu.Value = [double]$s.CpuLoad; $ui.pCpu.Foreground = Brush (Get-MetricColor $s.CpuLoad)
        $ui.dRam.Text = "$($s.RamUsedPct)%"; $ui.pRam.Value = [double]$s.RamUsedPct; $ui.pRam.Foreground = Brush (Get-MetricColor $s.RamUsedPct)
    }

    $nav = New-Object System.Collections.Generic.List[object]
    foreach ($sec in $script:Sections) {
        if (-not (Test-SectionShown $d $sec.Key)) { continue }
        $rows = @(Get-SectionRows $d $sec.Key $Name)
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
    Set-GridRows $ui.gridDetail "detail:$($sel.Key)" $rows   # sortowanie zapamiętane dla tej sekcji (także po zmianie serwera)
    $ui.dEmpty.Visibility = if ($rows.Count) { 'Collapsed' } else { 'Visible' }
    $ui.dRowDetail.Text = ''
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
        foreach ($p in $o.PSObject.Properties) { if ($p.Name -notlike '_*' -and "$($p.Value)".IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
        $false
    }.GetNewClosure())
}
function Select-Server([string]$Key, [string]$Section) {
    $item = Get-ServerItem $Key
    if (-not $item) { return }
    $ui.txtServerFilter.Text = ''
    if (-not $ui.sfAll.IsChecked) { $ui.sfAll.IsChecked = $true }
    # filtr listy od razu, nie po opóźnieniu – inaczej serwera spoza starego filtra nie da się zaznaczyć
    $script:FilterPending.Remove('servers'); Update-ServerFilter
    $script:PendingSection = $Section
    $script:Refreshing = $true   # bez obsługi SelectionChanged – szczegóły pokazujemy niżej raz
    try { $ui.lstServers.SelectedItems.Clear(); $ui.lstServers.SelectedItem = $item } finally { $script:Refreshing = $false }
    $ui.lstServers.ScrollIntoView($item)
    if ($ui.rbServer.IsChecked) { Show-ServerDetail $Key } else { $script:CurrentServer = $Key; $ui.rbServer.IsChecked = $true }
}
#endregion

#region ── Silnik operacji w tle (skan, wczytywanie migawek, diagnostyka) ───────
# Pule wątków jak w AD-ManagerDiamond: każdy serwer to osobne zadanie (PowerShell w puli), więc ma własny limit czasu,
# a wynik – razem z zapisem migawki, parsowaniem JSON i diagnostyką niedostępności – przygotowuje wątek tła.
# Wątek okna (timer) tylko odbiera gotowe obiekty, z budżetem czasu na takt, i odświeża widoki co ~1,5 s.
#   Remote – skan i diagnostyka (do ThrottleLimit naraz), Local – wczytywanie migawek z dysku (kilka wątków).
$script:Ops       = New-Object System.Collections.ArrayList
$script:Pools     = @{ Remote = $null; Local = $null }
$script:Abandoned = New-Object System.Collections.ArrayList
$script:AbandonAfterSec = 15
$script:OpId      = 0
$script:InTick    = $false
$script:UiDirty   = @{ List = $false; Overview = $false; Vms = $false; Detail = $false }
$script:LastUiRefresh = [Diagnostics.Stopwatch]::StartNew()

function New-EnginePool([int]$Max) {
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    try { $iss.ExecutionPolicy = [Microsoft.PowerShell.ExecutionPolicy]::Bypass } catch { }
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, [Math]::Max(1, $Max), $iss, $Host)
    $pool.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $pool.Open()
    $pool
}
function Get-EnginePool([string]$Kind) {
    $max = if ($Kind -eq 'Local') { [Math]::Max(2, [Math]::Min(6, [Environment]::ProcessorCount)) } else { [int]$Config.ThrottleLimit }
    if (-not $script:Pools[$Kind]) { $script:Pools[$Kind] = New-EnginePool $max }
    else { try { [void]$script:Pools[$Kind].SetMaxRunspaces($max) } catch { } }
    $script:Pools[$Kind]
}
function Get-Operation([string]$Kind) { @($script:Ops | Where-Object { $_.Kind -eq $Kind })[0] }

function Start-Operation {
    <#
        -Items: @(@{ Target; Opt }) – jedno zadanie na element (Opt trafia do wątku jako $Opt)
        -TimeoutSec: limit jednego zadania liczony od chwili, gdy zadanie faktycznie ruszyło (nie od kolejki)
        -OnResult { param($op, $r) } po każdym wyniku, -OnComplete { param($op) } po wszystkich (także po przerwaniu)
    #>
    param([string]$Kind, [string]$Name, [object[]]$Items, [string]$Pool = 'Remote', [int]$TimeoutSec = 0, [int]$TotalTimeoutSec = 0,
          [scriptblock]$OnResult, [scriptblock]$OnComplete, [hashtable]$State = @{})
    $pl = Get-EnginePool $Pool
    $script:OpId++
    $op = @{
        Id = $script:OpId; Kind = $Kind; Name = $Name; Items = New-Object System.Collections.ArrayList; Total = @($Items).Count; Done = 0; Failed = 0
        Cancelled = $false; CancelAt = $null; CancelReason = ''; Started = Get-Date; TimeoutSec = $TimeoutSec; TotalTimeoutSec = $TotalTimeoutSec
        OnResult = $OnResult; OnComplete = $OnComplete; State = $State
        Sync = [hashtable]::Synchronized(@{ Started = [hashtable]::Synchronized(@{}) })
    }
    foreach ($x in @($Items)) {
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $pl
        [void]$ps.AddScript($script:WorkerScript).AddArgument($Kind).AddArgument($x.Target).AddArgument($x.Opt).AddArgument($op.Sync)
        [void]$op.Items.Add(@{ Target = $x.Target; PS = $ps; Handle = $ps.BeginInvoke(); Finished = $false; Stopping = $false; StopAt = $null; TimedOut = $false })
    }
    [void]$script:Ops.Add($op)
    if ($script:EngineTimer) { $script:EngineTimer.Start() }
    Update-StatusBar
    $op
}
function Stop-Operation($Op, [string]$Reason = 'Przerwano') {
    # Zadania, które nie zareagują (np. zablokowane wywołanie WMI), po AbandonAfterSec są porzucane (Update-Operations)
    if ($Op.Cancelled) { return }
    $Op.Cancelled = $true; $Op.CancelAt = Get-Date; $Op.CancelReason = $Reason
    foreach ($it in $Op.Items) { if (-not $it.Finished -and -not $it.Handle.IsCompleted) { try { [void]$it.PS.BeginStop($null, $null) } catch { } } }
    Write-Log "$($Op.Name) – przerywanie: $Reason" 'WARN' $Op.Name
    Update-StatusBar
}
function Stop-AllOperations([string]$Reason = 'Przerwano') { foreach ($op in @($script:Ops)) { Stop-Operation $op $Reason } }

function Get-ItemResult($Op, $Item) {
    $r = $null
    try { $out = $Item.PS.EndInvoke($Item.Handle); if ($out -and $out.Count) { $r = $out[0] } } catch { }
    if (-not $r) {
        $msg = if ($Item.TimedOut) { "Przekroczono limit czasu jednego serwera ($($Op.TimeoutSec) s)" } elseif ($Op.Cancelled) { $Op.CancelReason }
               elseif ($Item.PS.Streams.Error.Count) { "$($Item.PS.Streams.Error[0].Exception.Message)" } else { 'Zadanie nie zwróciło wyniku.' }
        $id = if ($Item.TimedOut) { 'SrTimeout' } elseif ($Op.Cancelled) { 'SrCancelled' } else { 'SrNoResult' }
        $st = $Op.Sync.Started[$Item.Target]
        $r = [pscustomobject]@{ Mode = $Op.Kind; Name = $Item.Target; Ok = $false; Data = $null; Prev = $null; Last = $null; Error = $msg; ErrorId = $id; ErrorCode = ''
                                Diag = $null; SnapFile = ''; SnapError = ''; LatestFile = ''; PrevFile = ''; ScannedAt = ''; ReceivedUtc = $null
                                DurationSec = $(if ($st) { [math]::Round(([DateTime]::UtcNow - $st).TotalSeconds, 1) } else { 0 }) }
    }
    try { $Item.PS.Dispose() } catch { }
    $r
}
function Complete-OperationItem($Op, $Item, $Result) {
    $Item.Finished = $true
    $Op.Done++
    if (-not $Result.Ok) { $Op.Failed++ }
    if ($Op.OnResult) {
        try { $null = & $Op.OnResult $Op $Result }
        catch { Write-Log "Błąd obsługi wyniku ($($Result.Name)): $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR' $Op.Name }
    }
}
function Update-Operations {
    # Takt silnika (wątek okna albo pętla trybu bez okna): odbiór wyników z budżetem czasu, limity czasu, porzucanie zawieszonych zadań
    if ($script:InTick) { return }
    $script:InTick = $true
    $budget = [Diagnostics.Stopwatch]::StartNew()
    try {
        foreach ($a in @($script:Abandoned)) { if ($a.Handle.IsCompleted) { try { [void]$a.PS.EndInvoke($a.Handle) } catch { }; try { $a.PS.Dispose() } catch { }; $script:Abandoned.Remove($a) } }
        foreach ($op in @($script:Ops)) {
            if (-not $op.Cancelled -and $op.TotalTimeoutSec -gt 0 -and ((Get-Date) - $op.Started).TotalSeconds -gt $op.TotalTimeoutSec) { Stop-Operation $op "Przekroczono limit czasu całego skanu ($($op.TotalTimeoutSec) s)" }
            $abandon = $op.Cancelled -and $op.CancelAt -and ((Get-Date) - $op.CancelAt).TotalSeconds -ge $script:AbandonAfterSec
            foreach ($it in $op.Items) {
                if ($it.Finished) { continue }
                if ($budget.ElapsedMilliseconds -gt 300) { break }   # reszta wyników w kolejnym takcie – okno ma reagować
                if ($it.Handle.IsCompleted) { Complete-OperationItem $op $it (Get-ItemResult $op $it); continue }
                if ($abandon -or ($it.Stopping -and ((Get-Date) - $it.StopAt).TotalSeconds -ge $script:AbandonAfterSec)) {
                    [void]$script:Abandoned.Add(@{ PS = $it.PS; Handle = $it.Handle })
                    $st = $op.Sync.Started[$it.Target]
                    $r = [pscustomobject]@{ Mode = $op.Kind; Name = $it.Target; Ok = $false; Data = $null; Prev = $null; Last = $null
                                            Error = $(if ($it.TimedOut) { "Przekroczono limit czasu jednego serwera ($($op.TimeoutSec) s); zadanie nie odpowiedziało na przerwanie" } else { "$($op.CancelReason) (zadanie porzucone)" })
                                            ErrorId = $(if ($it.TimedOut) { 'SrTimeout' } else { 'SrCancelled' }); ErrorCode = ''; Diag = $null; SnapFile = ''; SnapError = ''; LatestFile = ''; PrevFile = ''; ScannedAt = ''; ReceivedUtc = $null
                                            DurationSec = $(if ($st) { [math]::Round(([DateTime]::UtcNow - $st).TotalSeconds, 1) } else { 0 }) }
                    Complete-OperationItem $op $it $r
                    continue
                }
                if ($op.TimeoutSec -gt 0 -and -not $it.Stopping) {
                    $st = $op.Sync.Started[$it.Target]
                    if ($st -and ([DateTime]::UtcNow - $st).TotalSeconds -gt $op.TimeoutSec) {
                        $it.Stopping = $true; $it.TimedOut = $true; $it.StopAt = Get-Date
                        try { [void]$it.PS.BeginStop($null, $null) } catch { }
                    }
                }
            }
            if ($op.Done -ge $op.Total) {
                [void]$script:Ops.Remove($op)
                if ($op.OnComplete) {
                    try { $null = & $op.OnComplete $op }
                    catch { Write-Log "Błąd po zakończeniu operacji: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR' $op.Name }
                }
            }
        }
    }
    catch { Write-Log "Błąd silnika operacji: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR' 'Program' }
    finally {
        $script:InTick = $false
        if ($script:Ops.Count -eq 0 -and $script:EngineTimer -and -not $script:Abandoned.Count) { $script:EngineTimer.Stop() }
    }
    if (-not $script:Headless) {
        Update-StatusBar
        if ($script:LastUiRefresh.ElapsedMilliseconds -ge 1500 -or $script:Ops.Count -eq 0) { Invoke-UiRefresh }
        # Okna z wynikami – dopiero po zwolnieniu taktu (okno modalne nie wstrzymuje odbioru wyników pozostałych serwerów)
        # DispatcherTimer wznawia się dopiero po powrocie z Tick – bez ponownego uzbrojenia okno modalne (i blokada PIN-em
        # czekająca na odblokowanie) zatrzymałoby odbiór wyników i limity czasu serwerów
        if ($script:PendingDialogs.Count -and $script:EngineTimer -and $script:EngineTimer.IsEnabled) { $script:EngineTimer.Stop(); $script:EngineTimer.Start() }
        while ($script:PendingDialogs.Count) {
            $pd = $script:PendingDialogs[0]; $script:PendingDialogs.RemoveAt(0)
            Show-Message $pd.Text $pd.Title $pd.Tone
        }
    }
}

function Request-UiRefresh([switch]$All, [switch]$List, [switch]$Detail) {
    if ($All) { foreach ($k in @($script:UiDirty.Keys)) { $script:UiDirty[$k] = $true } }
    else { $script:UiDirty.Overview = $true; $script:UiDirty.Vms = $true; if ($List) { $script:UiDirty.List = $true }; if ($Detail) { $script:UiDirty.Detail = $true } }
    if (-not $script:Ops.Count) { Invoke-UiRefresh }
}
function Invoke-UiRefresh {
    # Odświeżenie widoków, które się zmieniły – tylko widocznych (pozostałe przy przełączeniu widoku)
    if ($script:Headless -or -not $ui) { return }
    $script:LastUiRefresh.Restart()
    try {
        if ($script:UiDirty.List) { Refresh-ServerList; $script:UiDirty.List = $false }
        if ($script:UiDirty.Overview -and $ui.viewOverview.Visibility -eq 'Visible') { Update-Overview; $script:UiDirty.Overview = $false }
        if ($script:UiDirty.Vms -and $ui.viewVms.Visibility -eq 'Visible') { Update-VmView; $script:UiDirty.Vms = $false }
        if ($script:UiDirty.Detail -and $ui.viewServer.Visibility -eq 'Visible') { Show-ServerDetail $script:CurrentServer; $script:UiDirty.Detail = $false }
    } catch { Write-Log "Błąd odświeżania widoku: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR' 'Program' }
}
function Update-StatusBar {
    if ($script:Headless -or -not $ui) { return }
    $ops = @($script:Ops)
    if (-not $ops.Count) {
        $ui.statusDot.Fill = Brush '#5EE3AE'
        $ui.prg.Visibility = 'Collapsed'
        $ui.btnCancelOps.Visibility = 'Collapsed'
        Set-ScanUi $false
        return
    }
    $total = 0; $done = 0
    $parts = foreach ($op in $ops) {
        $total += $op.Total; $done += $op.Done
        $el = [int]((Get-Date) - $op.Started).TotalSeconds
        $running = $op.Sync.Started.Count - $op.Done   # Count bez wyliczania kluczy – wątki tła dopisują je w tym czasie
        $t = '{0}: {1} z {2}' -f $op.Name, $op.Done, $op.Total
        if ($op.Kind -eq 'Scan') { $t += ", w toku $([Math]::Max(0, $running))" }
        if ($op.Failed) { $t += ", bez danych: $($op.Failed)" }
        if ($op.Cancelled) { $t += ' – przerywanie…' }
        "$t, $el s"
    }
    $ui.txtStatus.Text = (@($parts) -join '   •   ')
    $ui.statusDot.Fill = Brush '#4C7DF0'
    $ui.prg.Visibility = 'Visible'
    $ui.prg.Value = if ($total) { [double]$done / $total * 100 } else { 0 }
    $ui.btnCancelOps.Visibility = 'Visible'
    Set-ScanUi ([bool](Get-Operation 'Scan'))
}
function Set-ScanUi([bool]$On) {
    if (-not $ui) { return }
    $ui.btnScanText.Text = if ($On) { 'Przerwij skan' } else { 'Skanuj wszystkie' }
    $ui.btnScanIcon.Text = Get-Glyph $(if ($On) { 'E71A' } else { 'E768' })
    $ui.btnAD.IsEnabled = -not $On
    $ui.btnFile.IsEnabled = -not $On
    $ui.btnCred.IsEnabled = -not $On
    $ui.btnRescan.IsEnabled = (-not $On) -and [bool]$script:CurrentServer
}

# ── Skan ──
function Get-ScanOrder([string[]]$Targets) {
    # Hosty Hyper-V i serwery, które ostatnio skanowały się najdłużej – na początek kolejki (nie wydłużają końcówki skanu)
    @($Targets | Sort-Object @{ e = { $d = $script:Data[$_]; if ($d -and $d.PSObject.Properties['System'] -and $d.System -and $d.System.IsHyperV) { 0 } else { 1 } } }, @{ e = { $d = $script:Data[$_]; if ($d -and $d.PSObject.Properties['DurationSec'] -and $d.DurationSec) { -[double]$d.DurationSec } else { 0 } } })
}
function Start-Scan([string[]]$Targets, $RetryOf) {
    # -RetryOf: stan skanu, po którym ponawiamy serwery z błędem chwilowym (liczniki trafiają do niego)
    if (Get-Operation 'Scan') { Show-Toast 'Skan już trwa – poczekaj na jego zakończenie albo go przerwij.' 'warn'; return }
    $Targets = @($Targets | Where-Object { $_ } | Select-Object -Unique)
    if (-not $Targets.Count) { Show-Message 'Lista serwerów jest pusta. Dodaj serwery ręcznie, z pliku lub z Active Directory.' 'Przegląd serwerów' 'warn'; return }
    $days = 0
    if ($RetryOf) { $days = $RetryOf.Days }
    elseif ($ui -and $ui.txtDays) {
        if (-not [int]::TryParse($ui.txtDays.Text, [ref]$days) -or $days -lt 1 -or $days -gt 180) { $days = $Config.EventDays; $ui.txtDays.Text = "$days" }
    } else { $days = $Config.EventDays }
    # Linux (rozpoznany na hoście Hyper-V) nie jest skanowany
    $linux = @($Targets | Where-Object { Test-LinuxGuest $_ })
    foreach ($n in $linux) { Register-ServerData $n ([pscustomobject]@{ Unsupported = 'Linux (wg hosta Hyper-V) – nie skanujemy'; Offline = $false; ScannedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm') }) $null }
    if ($linux.Count) { Write-Log "Pominięto maszyny z Linuksem: $(Join-Short ($linux | ForEach-Object { Get-DisplayName $_ }) 10)" 'INFO' 'Skan' }
    $Targets = @($Targets | Where-Object { $linux -notcontains $_ })
    if (-not $Targets.Count) { Request-UiRefresh -List; return }

    # folder skanu: znacznik czasu (kolejność migawek = kolejność nazw); dwa skany w tej samej sekundzie dostają przyrostek _2, _3…
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $snapDir = Join-Path $Config.SnapshotDir $stamp
    for ($n = 2; Test-Path -LiteralPath $snapDir; $n++) { $snapDir = Join-Path $Config.SnapshotDir "$($stamp)_$n" }
    try { New-Item -ItemType Directory -Force -Path $snapDir -ErrorAction Stop | Out-Null }
    catch { Write-Log "Nie można utworzyć folderu migawek $snapDir`: $($_.Exception.Message)" 'ERROR' 'Skan'; Show-Message "Nie można utworzyć folderu migawek:`n$snapDir`n`n$($_.Exception.Message)" 'Skan' 'crit'; return }
    $skipList = [string[]]@($Config.SkipSections | Where-Object { $_ })
    $collectorText = $Collector.ToString()
    $collectorArgs = @($days, [string[]]$Config.Folders, [int]$Config.MaxEvents, [bool]$Config.IncludeWarnings, $skipList, [int[]]@($Config.ExposedPorts))
    $items = foreach ($t in (Get-ScanOrder $Targets)) {
        $last = Get-LastOnlineSnapshot $t
        @{ Target = $t; Opt = @{
            CollectorText = $collectorText; CollectorArgs = $collectorArgs; Credential = $script:Cred; ConnectTimeoutSec = [int]$Config.ConnectTimeoutSec
            SnapDir = $snapDir; SafeName = (Get-SafeName $t); Compress = [bool]$Config.CompressSnapshots; ArrayKeys = [string[]]$script:ArrayKeys
            PrevFile = $last; LastOnlineFile = $last; DiagPorts = [int[]]@($Config.DiagPorts); DiagTimeoutMs = [int]$Config.DiagTimeoutMs; Days = $days
            Preflight = [bool]$Config.Preflight
        } }
        $it = Get-ServerItem $t
        if ($it) { $it.Color = '#4C7DF0'; $it.Sub = $(if ($RetryOf) { 'ponowna próba…' } else { 'w kolejce do skanu…' }) }
    }
    $state = @{ SnapDir = $snapDir; Ok = 0; Offline = 0; Timeout = 0; Cancelled = 0; AuthFails = 0; Days = $days; Targets = $Targets; RetryOf = $RetryOf }
    $who = if ($script:Cred) { $script:Cred.UserName } else { "$env:USERDOMAIN\$env:USERNAME" }
    if ($RetryOf) { Write-Log ("Ponowna próba dla {0} serwerów z błędem, który może być chwilowy: {1}" -f $Targets.Count, (Join-Short ($Targets | ForEach-Object { Get-DisplayName $_ }) 10)) 'INFO' 'Skan' }
    else { Write-Log ("Skan – start: {0} serwerów (równolegle {1}, limit {2} s na serwer, zdarzenia z {3} dni{4}), konto {5}" -f $Targets.Count, $Config.ThrottleLimit, $Config.ServerTimeoutSec, $days, $(if ($skipList.Count) { ", pominięte sekcje: $($skipList.Count)" } else { '' }), $who) 'INFO' 'Skan' }
    [void](Start-Operation -Kind 'Scan' -Name $(if ($RetryOf) { 'Ponowna próba' } else { 'Skan' }) -Items @($items) -Pool 'Remote' -TimeoutSec ([int]$Config.ServerTimeoutSec) -TotalTimeoutSec ([int]$Config.ScanTimeoutSec) -State $state `
        -OnResult { param($op, $r) Receive-ScanResult $op $r } -OnComplete { param($op) Complete-Scan $op })
    Request-UiRefresh -List
}
function Get-NowText { Get-Date -Format 'yyyy-MM-dd HH:mm' }
function Receive-ScanResult($Op, $R) {
    $name = $R.Name
    $st = $Op.State
    $prevData = $script:Data[$name]
    if ($R.Ok) {
        $d = $R.Data
        $d | Add-Member -NotePropertyName ScannedAt -NotePropertyValue (Get-NowText) -Force
        $d | Add-Member -NotePropertyName _File -NotePropertyValue "$($R.SnapFile)" -Force
        $d | Add-Member -NotePropertyName _PrevFile -NotePropertyValue "$($R.PrevFile)" -Force
        if ($R.SnapFile) { Add-SnapshotIndexEntry $name $R.SnapFile $false }
        if ($R.SnapError) { Write-Log "[$(Get-DisplayName $name)] Nie zapisano migawki: $($R.SnapError)" 'ERROR' 'Skan' }
        [void]$script:FreshScan.Add($name)
        Register-ServerData $name $d $R.Prev
        $dd = $script:Data[$name]
        $st.Ok++
        $slow = Join-Short (@($d.Timings) | Select-Object -First 2 | ForEach-Object { "$($_.Section) $($_.Sec) s" }) 2
        Write-Log ("[{0}] OK – {1} s; krytyczne {2}, ostrzeżenia {3}{4}{5}" -f (Get-DisplayName $name), $d.DurationSec, $dd._Crit, $dd._Warn, $(if ($slow) { "; najdłużej: $slow" }), $(if (@($d.Errors).Count) { "; nie zebrano sekcji: $(@($d.Errors).Count)" })) 'OK' 'Skan'
        if (@($d.PSObject.Properties['Truncated'].Value).Count) { Write-Log "[$(Get-DisplayName $name)] Osiągnięto limit pobieranych zdarzeń: $(@($d.Truncated) -join '; ') – zwiększ limit w Ustawieniach" 'WARN' 'Skan' }
        Add-AvailabilityRecord $name 'OK' $d.DurationSec $dd._Crit $dd._Warn '' ''
        $st.AuthFails = 0
    }
    elseif ($R.ErrorId -eq 'SrCancelled') {
        # Przerwany skan nie zmienia danych serwera (to nie jest niedostępność)
        $st.Cancelled++
        Update-ServerItem $name
        if (-not $prevData) { $it = Get-ServerItem $name; if ($it) { $it.Color = '#4A5263'; $it.Sub = 'skan przerwany' } }
    }
    elseif ($R.ErrorId -eq 'SrTimeout') {
        $st.Timeout++
        $note = "Skan $(Get-NowText) przerwano po przekroczeniu limitu czasu ($($Config.ServerTimeoutSec) s)"
        if ($prevData -and -not $prevData.Offline -and -not ($prevData.PSObject.Properties['Unsupported'] -and $prevData.Unsupported)) {
            # zostają poprzednie dane z ostrzeżeniem (nie „brak połączenia”)
            $note += " – pokazane dane z $($prevData.ScannedAt)"
            $prevData | Add-Member -NotePropertyName _ScanNote -NotePropertyValue $note -Force
            $i = New-Issue $name 'Ostrzeżenie' 'Skan' $note 'History'
            $prevData | Add-Member -NotePropertyName _AllIssues -NotePropertyValue @(@(@($prevData._AllIssues | Where-Object { $_ -and ($_.Category -ne 'Skan' -or $_.Section -ne 'History') }) + $i) | Sort-Object Rank) -Force
            Split-ServerIssues $name $prevData
            if ($script:FullCache.Contains($name)) { $script:FullCache[$name] | Add-Member -NotePropertyName _ScanNote -NotePropertyValue $note -Force; $script:FullCache.Remove($name) }
            Update-ServerItem $name
        } else {
            $dg = Get-WinRmErrorInfo -Message $R.Error -ErrorId 'SrTimeout'
            $d = [pscustomobject]@{ Offline = $true; Error = $R.Error; ErrorId = 'SrTimeout'; Diag = [pscustomobject]@{ Class = 'Timeout'; Cause = $dg.Cause; Remedy = $dg.Remedy; Notes = ''; Ip = ''; Checks = @(); DurationSec = 0 }; ScannedAt = (Get-NowText) }
            Register-ServerData $name $d $null
        }
        Write-Log "[$(Get-DisplayName $name)] $($R.Error)" 'WARN' 'Skan'
        if (-not $st.RetryOf) { Add-AvailabilityRecord $name 'Limit czasu' $R.DurationSec 0 0 'Timeout' $R.Error }   # porażka skanu już zapisana przez skan główny
    }
    else {
        $st.Offline++
        $last = $R.Last
        if (-not $last -and $prevData -and $prevData.PSObject.Properties['_Last']) { $last = $prevData._Last }
        $d = [pscustomobject]@{ Offline = $true; Error = $R.Error; ErrorId = $R.ErrorId; ErrorCode = $R.ErrorCode; Diag = $R.Diag; _Last = $last; ScannedAt = (Get-NowText); _File = "$($R.SnapFile)"; DurationSec = $R.DurationSec }
        if ($R.SnapFile) { Add-SnapshotIndexEntry $name $R.SnapFile $true }
        [void]$script:FreshScan.Add($name)
        Register-ServerData $name $d $null
        $cls = if ($R.Diag) { "$($R.Diag.Class)" } else { '' }
        $cause = if ($R.Diag) { "$($R.Diag.Cause)" } else { Get-ShortText $R.Error 200 }
        Write-Log ("[{0}] Brak połączenia – {1}{2}{3}" -f (Get-DisplayName $name), $cause, $(if ($R.Diag -and $R.Diag.Ports) { " (porty: $($R.Diag.Ports))" }), $(if ($R.Diag -and $R.Diag.Notes) { "; $($R.Diag.Notes)" })) $(if ($cls -eq 'Remote') { 'WARN' } else { 'ERROR' }) 'Skan'
        if (-not $st.RetryOf) { Add-AvailabilityRecord $name $(if ($cls -eq 'Remote') { 'Błąd zbierania danych' } else { 'Brak połączenia' }) $R.DurationSec 0 0 $cls $cause }
        # Ochrona konta: kilka odmów logowania z rzędu bez żadnego sukcesu = złe hasło – przerwij, zanim konto zostanie zablokowane w domenie
        if ($cls -eq 'Auth' -and $script:Cred) {
            $st.AuthFails++
            if ($st.AuthFails -ge 3 -and $st.Ok -eq 0 -and -not $Op.Cancelled) {
                Stop-Operation $Op 'Przerwano: kolejne serwery odrzucają poświadczenia (ochrona przed zablokowaniem konta)'
                [void]$script:PendingDialogs.Add(@{ Text = "Trzy kolejne serwery odrzuciły poświadczenia konta $($script:Cred.UserName), a żaden ich nie przyjął. Skan przerwano, żeby nie zablokować konta w domenie.`n`nSprawdź hasło (przycisk Konto) i uruchom skan ponownie."; Title = 'Skan przerwany'; Tone = 'crit' })
            }
        }
    }
    $script:UiDirty.List = $true; $script:UiDirty.Overview = $true; $script:UiDirty.Vms = $true
    if ($name -eq $script:CurrentServer) { $script:UiDirty.Detail = $true }
}
function Update-OfflineAnalysis {
    # Po skanie/wczytaniu: dane hostów Hyper-V są świeże – ponowna analiza niedostępnych serwerów (stan ich maszyn wirtualnych)
    foreach ($k in @($script:Data.Keys)) {
        $d = $script:Data[$k]
        if ($d -and $d.Offline) { Register-ServerData $k $d $null }
    }
}
function Test-TransientFailure($D) {
    # Błąd, który może zniknąć za chwilę: serwer w trakcie restartu, WinRM jeszcze nie wystartował (usługa z opóźnionym startem),
    # chwilowy błąd sieci lub limit powłok. DNS, zapora, uprawnienia i Kerberos nie miną same – nie ponawiamy (ochrona konta).
    if (-not $D -or -not $D.Offline -or "$($D.ErrorId)" -in 'SrCancelled', 'SrTimeout', 'CollectorFatal', 'ParseError', 'NoData') { return $false }
    $cls = if ($D.PSObject.Properties['Diag'] -and $D.Diag) { "$($D.Diag.Class)" } else { '' }
    $cls -in '', 'Offline', 'WinRM', 'Network', 'Unknown', 'Limit'
}
function Complete-Scan($Op) {
    $st = $Op.State
    $el = [int]((Get-Date) - $Op.Started).TotalSeconds
    try { if ((Test-Path -LiteralPath $st.SnapDir) -and -not (Get-ChildItem -LiteralPath $st.SnapDir -Force)) { Remove-Item -LiteralPath $st.SnapDir -Force } } catch { }
    Remove-OldSnapshots
    Update-VmIndex
    Update-OfflineAnalysis
    Update-StationClock
    foreach ($t in @($st.Targets)) { Update-ServerItem $t }
    $retry = @()
    if ($st.RetryOf) {
        # wynik ponownej próby: serwery, które teraz odpowiedziały, przechodzą do udanych w liczniku skanu głównego
        $p = $st.RetryOf
        $p.Ok += $st.Ok; $p.Timeout += $st.Timeout; $p.Offline = [Math]::Max(0, $p.Offline - $st.Ok - $st.Timeout)
        $script:LastScanState = $p
        $msg = "Ponowna próba zakończona w $el s: odpowiedziało $($st.Ok) z $($st.Targets.Count)$(if ($st.Offline) { ", nadal bez połączenia $($st.Offline)" })"
    } else {
        $script:LastScanState = $st
        if (-not $Op.Cancelled) { Update-StationNetwork $st }
        if ($Config.RetryFailed -and -not $Op.Cancelled -and -not $script:StationNetIssue) { $retry = @($st.Targets | Where-Object { $script:FreshScan.Contains($_) -and (Test-TransientFailure $script:Data[$_]) }) }
        $msg = "Skan zakończony w $el s: $($st.Ok) OK, bez połączenia $($st.Offline)$(if ($st.Timeout) { ", limit czasu $($st.Timeout)" })$(if ($st.Cancelled) { ", przerwane $($st.Cancelled)" })$(if ($retry.Count) { "; ponowna próba: $($retry.Count)" })"
    }
    Write-Log $msg $(if ($st.Offline -or $st.Timeout -or $Op.Cancelled) { 'WARN' } else { 'OK' }) 'Skan'
    if (-not $script:Headless) {
        $ui.txtStatus.Text = $msg
        $ui.txtLastScan.Text = "Ostatni skan: $(Get-NowText)"
        Show-Toast $msg $(if ($Op.Cancelled) { 'warn' } elseif ($st.Offline) { 'warn' } else { 'ok' }) 6
        Request-UiRefresh -All
    }
    if ($retry.Count) { Start-Scan $retry $st }
    Invoke-PendingReanalysis
}
function Invoke-PendingReanalysis {
    # ustawienia zmienione w trakcie skanu/wczytywania – ponowna analiza po zakończeniu operacji
    if ($script:ReanalyzePending -and -not (Get-Operation 'Scan') -and -not (Get-Operation 'Load')) { $script:ReanalyzePending = $false; Start-SnapshotLoad -Reanalyze }
}
$script:ReanalyzePending = $false

# ── Wczytywanie wyników z dysku (start programu, ponowna analiza po zmianie ustawień) ──
function Start-SnapshotLoad([switch]$Reanalyze) {
    if (Get-Operation 'Load') { return }
    Update-SnapshotIndex
    $items = foreach ($it in @($script:Servers)) {
        $files = @(Get-SnapshotEntries $it.Name | ForEach-Object { @{ Path = $_.Path; Offline = $_.Offline } })
        if (-not $files.Count) { continue }
        if ($files.Count -gt 6) { $files = $files[0..5] }
        # serwer niedostępny od wielu skanów: dołącz ostatnią udaną migawkę (ostatnie znane dane, host Hyper-V gościa)
        $on = Get-LastOnlineSnapshot $it.Name
        if ($on -and @($files | ForEach-Object { $_.Path }) -notcontains $on) { $files += @{ Path = $on; Offline = $false } }
        @{ Target = $it.Name; Opt = @{ Files = $files; ArrayKeys = [string[]]$script:ArrayKeys } }
    }
    $items = @($items)
    if (-not $items.Count) { return }
    if ($Reanalyze) { $script:FreshScan.Clear() }
    if (-not $script:Headless) { $ui.txtStatus.Text = "Wczytywanie wyników z dysku: 0 z $($items.Count)…" }
    [void](Start-Operation -Kind 'Load' -Name $(if ($Reanalyze) { 'Ponowna analiza' } else { 'Wczytywanie wyników' }) -Items $items -Pool 'Local' -State @{ Last = $null; Bad = 0; Reanalyze = [bool]$Reanalyze } `
        -OnResult { param($op, $r) Receive-LoadResult $op $r } -OnComplete { param($op) Complete-Load $op })
}
function Receive-LoadResult($Op, $R) {
    $name = $R.Name
    if ($R.Error) { Write-Log "[$(Get-DisplayName $name)] $($R.Error)" 'WARN' 'Migawki' }
    if (-not $R.Ok -or -not $R.Data) { $Op.State.Bad++; return }
    if ($script:FreshScan.Contains($name)) { return }   # w tej sesji jest już nowszy wynik skanu
    $d = $R.Data
    $d | Add-Member -NotePropertyName ScannedAt -NotePropertyValue $R.ScannedAt -Force
    $d | Add-Member -NotePropertyName _File -NotePropertyValue "$($R.LatestFile)" -Force
    $d | Add-Member -NotePropertyName _PrevFile -NotePropertyValue "$($R.PrevFile)" -Force
    if ($d.Offline) { $d | Add-Member -NotePropertyName _Last -NotePropertyValue $R.Last -Force }
    Register-ServerData $name $d $R.Prev
    if (-not $Op.State.Last -or [string]::CompareOrdinal($R.ScannedAt, $Op.State.Last) -gt 0) { $Op.State.Last = $R.ScannedAt }
    $script:UiDirty.List = $true; $script:UiDirty.Overview = $true; $script:UiDirty.Vms = $true
    if ($name -eq $script:CurrentServer) { $script:UiDirty.Detail = $true }
}
function Complete-Load($Op) {
    Update-VmIndex
    Update-OfflineAnalysis
    Update-StationClock
    $el = [math]::Round(((Get-Date) - $Op.Started).TotalSeconds, 1)
    $off = @($script:Data.Values | Where-Object { $_ -and $_.Offline }).Count
    Write-Log ("{0}: {1} serwerów w {2} s{3}{4}" -f $Op.Name, ($Op.Done - $Op.State.Bad), $el, $(if ($off) { ", bez połączenia przy ostatniej próbie: $off" }), $(if ($Op.State.Bad) { ", nieczytelne: $($Op.State.Bad)" })) 'INFO' 'Migawki'
    if (-not $script:Headless) {
        if ($Op.State.Last) { $ui.txtLastScan.Text = "Wyniki z ostatniego skanu: $($Op.State.Last)" }
        $ui.txtStatus.Text = "Wczytano wyniki $($Op.Done - $Op.State.Bad) serwerów"
        Request-UiRefresh -All
    }
    Invoke-PendingReanalysis
}

# ── Diagnostyka połączenia na żądanie ──
function Start-Diagnostics([string[]]$Targets) {
    $Targets = @($Targets | Where-Object { $_ } | Select-Object -Unique)
    if (-not $Targets.Count) { return }
    $items = foreach ($t in $Targets) {
        $d = $script:Data[$t]
        @{ Target = $t; Opt = @{ ErrorText = $(if ($d -and $d.Offline) { "$($d.Error)" } else { '' }); ErrorId = $(if ($d -and $d.Offline) { "$($d.ErrorId)" } else { '' }); ErrorCode = ''; DiagPorts = [int[]]@($Config.DiagPorts); DiagTimeoutMs = [int]$Config.DiagTimeoutMs } }
    }
    Write-Log "Diagnostyka połączenia: $(Join-Short ($Targets | ForEach-Object { Get-DisplayName $_ }) 8)" 'INFO' 'Diagnoza'
    [void](Start-Operation -Kind 'Diag' -Name 'Diagnoza' -Items @($items) -Pool 'Remote' -TimeoutSec 120 -State @{ Single = ($Targets.Count -eq 1) } `
        -OnResult { param($op, $r) Receive-DiagResult $op $r } -OnComplete { param($op) Request-UiRefresh -All })
}
function Receive-DiagResult($Op, $R) {
    $name = $R.Name
    if (-not $R.Ok -or -not $R.Diag) { Write-Log "[$(Get-DisplayName $name)] Diagnoza nie powiodła się: $($R.Error)" 'ERROR' 'Diagnoza'; return }
    $dg = $R.Diag
    $d = $script:Data[$name]
    if ($d) {
        if ($d.Offline) { $d | Add-Member -NotePropertyName Diag -NotePropertyValue $dg -Force; Register-ServerData $name $d $null }
        else {
            $d | Add-Member -NotePropertyName _ManualDiag -NotePropertyValue $dg -Force
            if ($script:FullCache.Contains($name)) { $script:FullCache[$name] | Add-Member -NotePropertyName _ManualDiag -NotePropertyValue $dg -Force }
        }
    }
    $okWinRm = $dg.Ports -match '5985 otwarty'
    Write-Log ("[{0}] Diagnoza: {1} – {2}; porty: {3}{4}" -f (Get-DisplayName $name), $(if ($okWinRm -and -not ($d -and $d.Offline)) { 'WinRM osiągalny' } else { $dg.Class }), $dg.Cause, $dg.Ports, $(if ($dg.Notes) { "; $($dg.Notes)" })) $(if ($okWinRm) { 'OK' } else { 'WARN' }) 'Diagnoza'
    if ($Op.State.Single -and -not $script:Headless) {
        $lines = @($dg.Checks | ForEach-Object { "• $($_.Check): $($_.PSObject.Properties['Value'].Value)" })
        $txt = "Przyczyna: $($dg.Cause)`n$(if ($dg.Remedy) { "Zalecenie: $($dg.Remedy)`n" })$(if ($dg.Notes) { "Uwagi: $($dg.Notes)`n" })`n$($lines -join "`n")"
        [void]$script:PendingDialogs.Add(@{ Text = $txt; Title = "Diagnoza połączenia – $(Get-DisplayName $name)"; Tone = $(if ($okWinRm -and -not ($d -and $d.Offline)) { 'ok' } else { 'warn' }) })
    }
    if ($name -eq $script:CurrentServer) { $script:CurrentSection = 'Diagnostics'; $script:UiDirty.Detail = $true }
}
$script:PendingDialogs = New-Object System.Collections.ArrayList
#endregion

#region ── Raport HTML ──────────────────────────────────────────────────────────
# Podsumowanie (domyślne): problemy, stan serwerów, niedostępność z diagnozą, Hyper-V, a dla każdego serwera jego problemy
# i wiersze wymagające uwagi – mały plik także przy kilkuset serwerach. Pełny: wszystkie sekcje każdego serwera (wczytywane
# kolejno z migawek, do 500 wierszy na sekcję). Zapis strumieniowy – bez budowania całego dokumentu w pamięci.
function HtmlEnc($s) { [System.Net.WebUtility]::HtmlEncode("$s") }
function Write-HtmlTable([System.IO.TextWriter]$W, $Rows, [int]$Cap = 0) {
    $Rows = @($Rows | Where-Object { $null -ne $_ })
    if (-not $Rows.Count) { $W.Write('<p class="muted">Brak pozycji</p>'); return }
    $cols = @($Rows[0].PSObject.Properties.Name | Where-Object { $_ -notin 'Flag', 'Key' -and $_ -notlike '_*' })
    $W.Write('<div class="wrap"><table><thead><tr>')
    foreach ($c in $cols) { $W.Write('<th>'); $W.Write([System.Net.WebUtility]::HtmlEncode((Get-Header $c))); $W.Write('</th>') }
    $W.Write('</tr></thead><tbody>')
    $n = 0
    foreach ($r in $Rows) {
        if ($Cap -gt 0 -and $n -ge $Cap) { break }
        $n++
        $W.Write('<tr class="'); $W.Write("$($r.Flag)"); $W.Write('">')
        foreach ($c in $cols) { $W.Write('<td>'); $W.Write([System.Net.WebUtility]::HtmlEncode("$($r.$c)")); $W.Write('</td>') }
        $W.Write('</tr>')
    }
    $W.Write('</tbody></table></div>')
    if ($Cap -gt 0 -and $Rows.Count -gt $Cap) { $W.Write("<p class=""muted"">… i $($Rows.Count - $Cap) kolejnych wierszy (pełna lista w programie)</p>") }
}
function Write-HtmlIssues([System.IO.TextWriter]$W, $Issues, [switch]$WithServer) {
    $Issues = @($Issues | Where-Object { $_ })
    if (-not $Issues.Count) { $W.Write('<p class="muted">Brak problemów</p>'); return }
    $W.Write('<div class="wrap"><table><thead><tr><th>Poziom</th>')
    if ($WithServer) { $W.Write('<th>Serwer</th>') }
    $W.Write('<th>Kategoria</th><th>Opis</th></tr></thead><tbody>')
    foreach ($i in $Issues) {
        $W.Write("<tr><td><span class=""pill p-$($i.Flag)"">$(HtmlEnc $i.Severity)</span></td>")
        if ($WithServer) { $W.Write("<td>$(HtmlEnc $i.Server)</td>") }
        $W.Write("<td>$(HtmlEnc $i.Category)</td><td>$(HtmlEnc $i.Message)</td></tr>")
    }
    $W.Write('</tbody></table></div>')
}
function Export-HtmlReport {
    param([ValidateSet('Summary', 'Full')][string]$Mode = 'Summary', [string]$Path = '', [switch]$NoOpen)
    if (-not $script:Data.Count) { Show-Message 'Brak danych. Najpierw wykonaj skan.' 'Raport HTML' 'warn'; return $null }
    if (-not $Path) {
        New-Item -ItemType Directory -Force -Path $Config.ReportDir | Out-Null
        $Path = Join-Path $Config.ReportDir ('Przeglad_serwerow_{0:yyyyMMdd_HHmm}{1}.html' -f (Get-Date), $(if ($Mode -eq 'Full') { '_pelny' } else { '' }))
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $o = Get-OverviewData $false
    $v = Get-VmData
    $css = @'
:root{--bg:#0f1318;--panel:#161b22;--line:#242b36;--text:#e4e8ef;--muted:#8791a5;--crit:#ff7a86;--warn:#ffc46b;--info:#8cc0ff;--ok:#4fd1a1}
@media (prefers-color-scheme:light){:root{--bg:#f4f6f9;--panel:#fff;--line:#e2e6ee;--text:#1a1f29;--muted:#667085;--crit:#d92d3f;--warn:#b86e00;--info:#2463c9;--ok:#138a5e}}
*{box-sizing:border-box}body{margin:0;padding:32px;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}h3{font-size:14px;margin:22px 0 8px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:28px;font-weight:600}
.wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:12.5px}th{text-align:left;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word;max-width:640px}tr:last-child td{border-bottom:0}
tr.crit td{color:var(--crit)}tr.warn td{color:var(--warn)}tr.info td{color:var(--info)}tr.muted td{color:var(--muted)}
.pill{display:inline-block;padding:1px 9px;border-radius:9px;font-size:11.5px;font-weight:600;white-space:nowrap}
.p-crit{color:var(--crit);background:color-mix(in srgb,var(--crit) 16%,transparent)}.p-warn{color:var(--warn);background:color-mix(in srgb,var(--warn) 16%,transparent)}.p-info{color:var(--info);background:color-mix(in srgb,var(--info) 16%,transparent)}
details{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:10px 0;padding:0 18px}
details>div{padding-bottom:18px}summary{cursor:pointer;padding:14px 0;font-weight:600;font-size:15px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:10px}
button{font:inherit;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:7px;padding:6px 14px;cursor:pointer;margin-right:6px}
@media print{details{break-inside:avoid}button{display:none}}
'@
    $enc = New-Object System.Text.UTF8Encoding $true
    $w = New-Object System.IO.StreamWriter($Path, $false, $enc)
    try {
        $now = Get-Date -Format 'yyyy-MM-dd HH:mm'
        $w.Write("<!DOCTYPE html><html lang=""pl""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width,initial-scale=1""><title>Przegląd serwerów $now</title><style>$css</style></head><body>")
        $w.Write("<h1>Przegląd serwerów</h1><div class=""muted"">Wygenerowano $now przez $(HtmlEnc "$env:USERDOMAIN\$env:USERNAME"), domena $(HtmlEnc $env:USERDNSDOMAIN) – raport $(if ($Mode -eq 'Full') { 'pełny' } else { 'podsumowanie' }), wersja programu $script:AppVersion</div>")
        $tiles = @(@('Serwery', $script:Data.Count, ''), @('Odpowiada', $o.Online, 'var(--ok)'), @('Bez połączenia', $o.Offline, 'var(--crit)'), @('Krytyczne', $o.Crit, 'var(--crit)'), @('Ostrzeżenia', $o.Warn, 'var(--warn)'), @('Hyper-V: hosty / VM', "$($o.Hosts) / $($o.VmRun)", 'var(--info)'))
        $w.Write('<div class="tiles">')
        foreach ($t in $tiles) { $w.Write("<div class=""tile""><span class=""muted"">$($t[0])</span><b style=""color:$($t[2])"">$($t[1])</b></div>") }
        $w.Write('</div><h2>Wykryte problemy</h2>')
        Write-HtmlIssues $w $o.Issues -WithServer
        $w.Write('<h2>Stan serwerów</h2>')
        Write-HtmlTable $w $o.Servers
        # Niedostępność z diagnozą
        $off = @(foreach ($it in $script:Servers) {
            $d = $script:Data[$it.Name]
            if (-not $d -or -not $d.Offline) { continue }
            $dg = if ($d.PSObject.Properties['Diag']) { $d.Diag } else { $null }
            $vm = Find-VmForServer $it.Name $d
            $st = if ($script:AvailStats) { $script:AvailStats[$it.Name.ToLowerInvariant()] } else { $null }
            [pscustomobject]@{
                Server = $it.Display; Status = $(if ($dg) { Get-DiagClassText "$($dg.Class)" } else { '' }); Reason = $(if ($dg) { "$($dg.Cause)" } else { Get-ShortText $d.Error 200 })
                Note = $(if ($dg) { (@($dg.Notes, $dg.Remedy) | Where-Object { $_ }) -join ' ' } else { '' })
                Ports = $(if ($dg) { "$($dg.Ports)" } else { '' }); HvHost = $(if ($vm) { "$($vm.HostDisplay): $(Get-VmStateText "$($vm.Row.State)")" } else { '' })
                LastOk = $(if ($st) { $st.LastOk } else { '' }); Scanned = $d.ScannedAt; Flag = $(if ($d._Crit) { 'crit' } else { 'warn' })
            }
        })
        if ($off.Count) { $w.Write("<h2>Niedostępne serwery – diagnoza <span class=""muted"">($($off.Count))</span></h2>"); Write-HtmlTable $w $off }
        if (@($v.Hosts).Count) {
            $w.Write("<h2>Hyper-V: hosty <span class=""muted"">($(@($v.Hosts).Count))</span></h2>")
            Write-HtmlTable $w $v.Hosts
            $vmRows = if ($Mode -eq 'Full') { @($v.Vms) } else { @($v.Vms | Where-Object { $_.Flag -in 'crit', 'warn' -or ($_.OnList -ne 'Tak' -and -not $_._Linux) }) }
            $w.Write("<h2>Maszyny wirtualne$(if ($Mode -ne 'Full') { ' – wymagające uwagi i spoza listy' }) <span class=""muted"">($($vmRows.Count) z $(@($v.Vms).Count))</span></h2>")
            Write-HtmlTable $w $vmRows
        }
        $w.Write('<h2>Szczegóły serwerów</h2>')
        $w.Write('<button onclick="document.querySelectorAll(''details'').forEach(d=>d.open=true)">Rozwiń wszystkie</button><button onclick="document.querySelectorAll(''details'').forEach(d=>d.open=false)">Zwiń wszystkie</button>')
        foreach ($it in $script:Servers) {
            $d = $script:Data[$it.Name]
            if (-not $d) { continue }
            if ($Mode -eq 'Full' -and -not $d.Offline) { $d = Get-ServerFull $it.Name }
            $os = if ($d.Offline) { 'brak połączenia' } elseif ($d.PSObject.Properties['Unsupported'] -and $d.Unsupported) { "$($d.Unsupported)" } else { "$($d.System.OS)" }
            $w.Write("<details><summary><span class=""dot"" style=""background:$($it.Color)""></span>$(HtmlEnc $it.Display) <span class=""muted"">$(HtmlEnc $os)</span>")
            if ($d._Crit) { $w.Write(" <span class=""pill p-crit"">$($d._Crit)</span>") }
            if ($d._Warn) { $w.Write(" <span class=""pill p-warn"">$($d._Warn)</span>") }
            $w.Write('</summary><div>')
            $w.Write('<h3>Problemy</h3>')
            Write-HtmlIssues $w $d._Issues
            if ($d.Offline) {
                $rows = @(Get-DiagnosticsRows $it.Name $d)
                if ($rows.Count) { $w.Write('<h3>Diagnoza połączenia</h3>'); Write-HtmlTable $w $rows }
            } elseif (-not ($d.PSObject.Properties['Unsupported'] -and $d.Unsupported)) {
                foreach ($sec in $script:Sections) {
                    if ($sec.Key -in 'Issues', 'History', 'Diagnostics') { continue }
                    if (-not (Test-SectionShown $d $sec.Key)) { continue }
                    $rows = @(Get-SectionRows $d $sec.Key $it.Name)
                    if ($Mode -ne 'Full') {
                        # podsumowanie: tylko wiersze oznaczone (wymagające uwagi); System i zmiany – w całości
                        if ($sec.Key -notin 'System', 'Changes', 'HvHost') { $rows = @($rows | Where-Object { "$($_.Flag)" -in 'crit', 'warn', 'info' }) }
                        if (-not $rows.Count -or $sec.Key -eq 'System') { continue }
                    }
                    $w.Write("<h3>$(HtmlEnc $sec.Header) <span class=""muted"">($($rows.Count))</span></h3>")
                    Write-HtmlTable $w $rows $(if ($Mode -eq 'Full') { 500 } else { 200 })
                }
            }
            $w.Write('</div></details>')
        }
        $w.Write('</body></html>')
    } finally { $w.Dispose() }
    $kb = [math]::Round((Get-Item -LiteralPath $Path).Length / 1KB)
    Write-Log "Raport HTML ($(if ($Mode -eq 'Full') { 'pełny' } else { 'podsumowanie' })): $Path ($kb KB, $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s)" 'OK' 'Raport'
    if (-not $NoOpen -and -not $script:Headless) {
        Show-Toast "Zapisano raport: $([IO.Path]::GetFileName($Path)) ($kb KB)" 'ok'
        try { Start-Process $Path } catch { Write-Log "Nie udało się otworzyć raportu: $($_.Exception.Message)" 'WARN' 'Raport' }
    }
    $Path
}
#endregion

#region ── Okno Ustawienia ─────────────────────────────────────────────────────
function New-SettingsDialog {
    $dlg = New-UiElement $script:SettingsXamlText
    $c = Get-NamedElements $dlg $script:SettingsXamlText
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
            $cb.Tag = $k; $cb.Margin = New-Object System.Windows.Thickness -ArgumentList 0, 3, 0, 3
            [void]$c.sSections.Children.Add($cb); $checks.Add($cb)
        }
    }
    $lastGroup = ''
    foreach ($d in $script:SettingDefs) {
        if ($d.Group -ne $lastGroup) {
            $lastGroup = $d.Group
            $gh = New-Object System.Windows.Controls.TextBlock
            $gh.Text = $d.Group; $gh.FontWeight = 'SemiBold'; $gh.Foreground = Brush '#8CB0FF'; $gh.FontSize = 12.5
            $gh.Margin = New-Object System.Windows.Thickness -ArgumentList 0, $(if ($c.sParams.Children.Count) { 18 } else { 4 }), 0, 6
            [void]$c.sParams.Children.Add($gh)
        }
        if ($d.Type -eq 'bool') {
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.Content = $d.Label; $cb.Margin = New-Object System.Windows.Thickness -ArgumentList 0, 6, 0, 6
            [void]$c.sParams.Children.Add($cb); $inputs[$d.Key] = $cb
        } elseif ($d.Type -in 'list', 'intlist') {
            $lb = New-Object System.Windows.Controls.TextBlock
            $lb.Text = $d.Label; $lb.Foreground = Brush '#C3CAD6'; $lb.TextWrapping = 'Wrap'
            $lb.Margin = New-Object System.Windows.Thickness -ArgumentList 0, 10, 0, 4
            $tb = New-Object System.Windows.Controls.TextBox
            $tb.Style = $dlg.FindResource('MultiText'); $tb.Height = 96
            [void]$c.sParams.Children.Add($lb); [void]$c.sParams.Children.Add($tb); $inputs[$d.Key] = $tb
        } elseif ($d.Type -eq 'string') {
            $lb = New-Object System.Windows.Controls.TextBlock
            $lb.Text = $d.Label; $lb.Foreground = Brush '#C3CAD6'; $lb.TextWrapping = 'Wrap'
            $lb.Margin = New-Object System.Windows.Thickness -ArgumentList 0, 8, 0, 4
            $tb = New-Object System.Windows.Controls.TextBox
            $tb.Tag = 'np. OU=Serwery,DC=firma,DC=local'
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
            $tb.ToolTip = "Zakres: $($d.Min)–$($d.Max)"
            [System.Windows.Controls.Grid]::SetColumn($tb, 1)
            [void]$g.Children.Add($lb); [void]$g.Children.Add($tb); [void]$c.sParams.Children.Add($g); $inputs[$d.Key] = $tb
        }
    }
    # stan okna trzymamy w zmiennej skryptu – handlery WPF wywołują funkcje skryptu i muszą go widzieć
    $script:SetDlg = @{ Dialog = $dlg; Controls = $c; Checks = $checks; Inputs = $inputs; Saved = $false; PinChanged = $false }
    $c.sAll.Add_Click({ foreach ($cb in $script:SetDlg.Checks) { $cb.IsChecked = $true } })
    $c.sNone.Add_Click({ foreach ($cb in $script:SetDlg.Checks) { $cb.IsChecked = $false } })
    $c.sDefaults.Add_Click({ Set-SettingsDialogValues $script:ConfigDefaults })
    $c.sSave.Add_Click({ Invoke-UiAction 'Ustawienia' { Save-SettingsDialog } })
    $c.sIgnored.Add_Click({ Invoke-UiAction 'Ustawienia' { Show-IgnoredIssuesDialog } })
    $c.sFolder.Add_Click({ try { Start-Process explorer.exe -ArgumentList "`"$Base`"" } catch { } })
    $c.sPinSet.Add_Click({ Invoke-UiAction 'Blokada' { Set-PinFromSettings } })
    $c.sPinClear.Add_Click({ Invoke-UiAction 'Blokada' { Clear-PinFromSettings } })
    $c.sPinAtStart.IsChecked = [bool]$script:LockCfg.RequireAtStart
    Update-PinState
    Set-SettingsDialogValues (Get-ConfigSnapshot)
    $dlg.Add_SourceInitialized({ param($s, $e) Set-DarkTitleBar $s })
    $dlg
}
function Update-PinState {
    $c = $script:SetDlg.Controls
    $on = Test-PinConfigured
    $c.sPinState.Text = if ($on) { "PIN ustawiony ($($script:LockCfg.Length) cyfr). Blokada: przycisk z kłódką, Ctrl+Shift+L, po bezczynności (ustawienie po prawej)." } else { 'PIN nie jest ustawiony – blokada programu jest wyłączona.' }
    $c.sPinSet.Content = if ($on) { 'Zmień PIN…' } else { 'Ustaw PIN…' }
    $c.sPinClear.IsEnabled = $on
    $c.sPinAtStart.IsEnabled = $on
}
function Set-PinFromSettings {
    if ((Test-PinConfigured) -and -not (Confirm-Pin 'Podaj obecny PIN, aby go zmienić')) { return }
    $pin = Show-SetPinDialog
    if (-not $pin) { return }
    Set-LockPin $pin
    $script:LockCfg.RequireAtStart = [bool]$script:SetDlg.Controls.sPinAtStart.IsChecked
    Save-UserSettings
    Write-Log 'Ustawiono nowy PIN blokady programu.' 'OK' 'Blokada'
    Update-PinState
    $btn = $ui['btnLock']; if ($btn) { $btn.Visibility = 'Visible' }
    Show-Toast 'Ustawiono PIN blokady.' 'ok'
}
function Clear-PinFromSettings {
    if (-not (Test-PinConfigured)) { return }
    if (-not (Confirm-Pin 'Podaj PIN, aby wyłączyć blokadę')) { return }
    Set-LockPin ''
    Save-UserSettings
    Write-Log 'Usunięto PIN – blokada programu wyłączona.' 'WARN' 'Blokada'
    Update-PinState
    $btn = $ui['btnLock']; if ($btn) { $btn.Visibility = 'Collapsed' }
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
        if ($d.Type -eq 'string') {
            $t = "$($ctl.Text)".Trim()
            if ($d.Key -eq 'AdSearchBase' -and $t -and $t -notmatch '^(OU|CN|DC)=') { $bad.Add("$($d.Label): podaj nazwę wyróżniającą, np. OU=Serwery,DC=firma,DC=local") }
            $V[$d.Key] = $t; continue
        }
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
    if ($V.ContainsKey('ServerTimeoutSec') -and $V.ContainsKey('ConnectTimeoutSec') -and $V.ServerTimeoutSec -le $V.ConnectTimeoutSec) { $bad.Add('Limit czasu jednego serwera musi być dłuższy niż limit nawiązania połączenia') }
    $V.SkipSections = [string[]]@($script:SetDlg.Checks | Where-Object { -not $_.IsChecked } | ForEach-Object { "$($_.Tag)" })
    if ($V.SkipSections.Count -ge $script:SetDlg.Checks.Count) { $bad.Add('Zaznacz co najmniej jedną sekcję do skanowania') }
    [pscustomobject]@{ Values = $V; Errors = $bad.ToArray() }
}
function Save-SettingsDialog {
    $r = Read-SettingsDialogValues
    if ($r.Errors.Count) { Show-Message ($r.Errors -join [Environment]::NewLine) 'Ustawienia' 'warn'; return }
    $before = Get-ConfigSnapshot
    Set-ConfigFromValues $r.Values
    $script:LockCfg.RequireAtStart = [bool]$script:SetDlg.Controls.sPinAtStart.IsChecked
    try { Save-UserSettings } catch { Show-Message "Nie udało się zapisać $($Config.SettingsFile): $($_.Exception.Message)" 'Ustawienia' 'crit'; return }
    # co się zmieniło – do dziennika (bez list, żeby wpis był czytelny)
    $chg = @(foreach ($d in $script:SettingDefs) { $a = "$(@($before[$d.Key]) -join ',')"; $b = "$(@($Config[$d.Key]) -join ',')"; if ($a -ne $b) { if ($d.Type -in 'list', 'intlist') { $d.Key } else { "$($d.Key): $a → $b" } } })
    if ((@($before.SkipSections) -join ',') -ne (@($Config.SkipSections) -join ',')) { $chg += "pominięte sekcje: $(@($Config.SkipSections).Count)" }
    Write-Log ("Zapisano ustawienia{0}" -f $(if ($chg.Count) { ': ' + ($chg -join '; ') } else { ' (bez zmian)' })) 'INFO' 'Ustawienia'
    $script:SetDlg.Saved = $true
    $script:SetDlg.Changed = [bool]$chg.Count
    $script:SetDlg.Dialog.Close()
}
function Update-SettingsButton {
    $n = @($Config.SkipSections | Where-Object { $_ }).Count
    $ui.txtSkipCount.Text = "$n"
    $ui.txtSkipCount.Visibility = if ($n) { 'Visible' } else { 'Collapsed' }
    $ui.btnSettings.ToolTip = if ($n) { "Ustawienia – pomijane sekcje skanu: $n" } else { 'Ustawienia (skanowane są wszystkie sekcje)' }
}
function Show-SettingsDialog {
    try { $dlg = New-SettingsDialog } catch { Show-Message "Nie udało się otworzyć okna ustawień: $($_.Exception.Message)" 'Ustawienia' 'crit'; return }
    $dlg.Tag = @{ Result = $false }
    if ($script:UnlockState.Locked) { Wait-Unlocked }
    Register-IdleActivity -Window $dlg
    $dlg.Owner = $window
    [void]$dlg.ShowDialog()
    if ($script:SetDlg -and $script:SetDlg.Saved) {
        $ui.txtDays.Text = "$($Config.EventDays)"
        Update-SettingsButton
        foreach ($k in 'Remote', 'Local') { if ($script:Pools[$k]) { [void](Get-EnginePool $k) } }   # nowy limit równoległości
        if ($script:SetDlg.Changed) {
            # nowe progi i reguły: ponowna analiza zapisanych wyników (w tle, z migawek) – po trwającym skanie, jeśli trwa
            if ((Get-Operation 'Scan') -or (Get-Operation 'Load')) {
                $script:ReanalyzePending = $true
                Show-Toast 'Zapisano ustawienia – nowe progi zostaną zastosowane po zakończeniu trwającej operacji.' 'ok' 5
            } else {
                Start-SnapshotLoad -Reanalyze
                Show-Toast 'Zapisano ustawienia – nowe progi są stosowane do wczytanych wyników.' 'ok' 5
            }
        } else { Show-Toast 'Zapisano ustawienia.' 'ok' }
    }
    $script:SetDlg = $null
}

# ── Wyciszone problemy ──
function Add-IgnoreRule($Issue, [switch]$AllServers) {
    if (-not $Issue -or -not $Issue.IssueKey) { return }
    $srv = if ($AllServers) { '*' } else { "$($Issue.ServerKey)" }
    $rule = [pscustomobject]@{ Server = $srv; Key = $Issue.IssueKey; Text = "$($Issue.Message)"; Added = (Get-Date -Format 'yyyy-MM-dd HH:mm'); By = "$env:USERDOMAIN\$env:USERNAME" }
    $Config.IgnoredIssues = @(@($Config.IgnoredIssues | Where-Object { $_ -and -not ($_.Key -eq $rule.Key -and $_.Server -eq $rule.Server) }) + $rule)
    Save-UserSettings
    Update-IgnoreRules
    Write-Log "Wyciszono problem $(if ($AllServers) { 'na wszystkich serwerach' } else { "na $(Get-DisplayName $srv)" }): $(Get-ShortText $Issue.Message 160)" 'INFO' 'Wyciszenia'
    Show-Toast 'Problem wyciszony – lista wyciszeń: Ustawienia → Wyciszone problemy, albo pole „Wyciszone” nad tabelą.' 'ok' 5
}
function Remove-IgnoreRule($Issue) {
    if (-not $Issue) { return }
    $before = @($Config.IgnoredIssues).Count
    $Config.IgnoredIssues = @($Config.IgnoredIssues | Where-Object { $_ -and -not ($_.Key -eq $Issue.IssueKey -and ($_.Server -eq '*' -or $_.Server -eq $Issue.ServerKey)) })
    if (@($Config.IgnoredIssues).Count -eq $before) { return }
    Save-UserSettings
    Update-IgnoreRules
    Write-Log "Przywrócono problem: $(Get-ShortText $Issue.Message 160)" 'INFO' 'Wyciszenia'
}
function Update-IgnoreRules {
    # Reguły wyciszeń zmieniają tylko podział problemów – bez ponownej analizy
    Update-IgnoreSet
    foreach ($k in @($script:Data.Keys)) { $d = $script:Data[$k]; if ($d -and $d.PSObject.Properties['_AllIssues']) { Split-ServerIssues $k $d; Update-ServerItem $k } }
    foreach ($k in @($script:FullCache.Keys)) { $d = $script:FullCache[$k]; if ($d -and $d.PSObject.Properties['_AllIssues']) { Split-ServerIssues $k $d } }
    Update-VmIndex
    Request-UiRefresh -All
}
function Update-IgnoredGrid {
    $rows = @($Config.IgnoredIssues | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Server = $(if ($_.Server -eq '*') { '* (wszystkie)' } else { Get-DisplayName $_.Server }); Text = $_.Text; Added = $_.Added; By = $_.By; _Rule = $_ } })
    $script:IgDlg.Grid.ItemsSource = $rows
    $script:IgDlg.Info.Text = "Reguł: $($rows.Count). Zaznacz reguły i kliknij «Usuń zaznaczone», aby problemy znów były zgłaszane."
}
function Show-IgnoredIssuesDialog {
    $body = @'
<Grid Height="380">
  <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <Border Style="{StaticResource Card}" Padding="1"><DataGrid x:Name="igGrid" Style="{StaticResource DarkGrid}"/></Border>
  <TextBlock x:Name="igInfo" Grid.Row="1" Foreground="#7B8496" FontSize="12" TextWrapping="Wrap" Margin="2,8,0,0"/>
</Grid>
'@
    $w = New-Dialog -Title 'Wyciszone problemy' -Subtitle 'Wyciszony problem nie liczy się do kafelków i list. Reguła „*” działa na wszystkich serwerach.' -Body $body -Icon 'E7BA' -OkText 'Zamknij' -NoCancel -Width 900
    $grid = $w.FindName('igGrid')
    $grid.Add_AutoGeneratingColumn({ param($s, $e) if ($e.PropertyName -like '_*') { $e.Cancel = $true; return }; $e.Column.Header = switch ($e.PropertyName) { 'Server' { 'Serwer' } 'Text' { 'Problem (przykład)' } 'Added' { 'Dodano' } 'By' { 'Kto' } default { $e.PropertyName } } })
    # (bez GetNewClosure – domknięcie nie widzi zmiennych i funkcji skryptu; stan okna w $script:IgDlg)
    $script:IgDlg = @{ Grid = $grid; Info = $w.FindName('igInfo') }
    Update-IgnoredGrid
    $del = New-Object System.Windows.Controls.Button
    $del.Content = 'Usuń zaznaczone'; $del.Style = $w.FindResource('DangerButton')
    $del.Add_Click({
        $sel = @($script:IgDlg.Grid.SelectedItems | ForEach-Object { $_._Rule })
        if (-not $sel.Count) { return }
        $Config.IgnoredIssues = @($Config.IgnoredIssues | Where-Object { $sel -notcontains $_ })
        Save-UserSettings
        Update-IgnoreRules
        Write-Log "Usunięto reguły wyciszeń: $($sel.Count)" 'INFO' 'Wyciszenia'
        Update-IgnoredGrid
    })
    [void]$w.FindName('dlgExtra').Children.Add($del)
    [void](Invoke-Dialog $w)
}
#endregion

#region ── Tryb bez okna (-Scan) ───────────────────────────────────────────────
function Get-InstanceMutexName([string]$Kind) {
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { $h = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Base.ToLowerInvariant()))).Replace('-', '').Substring(0, 16) } finally { $sha.Dispose() }
    "Local\ServerReview_${Kind}_$h"
}
function Enter-InstanceMutex([string]$Kind) {
    # Jedna instancja na folder danych (dwie kopie nadpisywałyby listę serwerów i sprzątały sobie migawki)
    $m = New-Object System.Threading.Mutex($false, (Get-InstanceMutexName $Kind))
    $got = $false
    try { $got = $m.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $got = $true }
    if ($got) { return $m }
    $m.Dispose()
    $null
}
function Wait-Operations { while ($script:Ops.Count -or $script:Abandoned.Count) { Update-Operations; if (-not $script:Ops.Count) { break }; Start-Sleep -Milliseconds 300 } }
function Invoke-HeadlessScan {
    $script:Headless = $true
    $mx = Enter-InstanceMutex 'Scan'
    if (-not $mx) { Write-Log 'Inny skan bez okna z tego folderu danych jeszcze trwa – kończę.' 'ERROR' 'Skan'; return 2 }
    try {
        Write-Log ("Przegląd serwerów {0} – skan bez okna (PowerShell {1}, {2}\{3}, raport: {4})" -f $script:AppVersion, $PSVersionTable.PSVersion, $env:USERDOMAIN, $env:USERNAME, $(if ($NoReport) { 'brak' } else { $ReportMode })) 'INFO' 'Program'
        if ($script:BaseFallback) { Write-Log $script:BaseFallback 'WARN' 'Program' }
        if ($script:SettingsWarning) { Write-Log $script:SettingsWarning 'WARN' 'Ustawienia' }
        if (-not (Test-Path -LiteralPath $Config.ServerListFile)) { Write-Log "Brak listy serwerów: $($Config.ServerListFile)" 'ERROR' 'Lista'; return 2 }
        [void](Import-ServerFile $Config.ServerListFile)
        if (-not $script:Servers.Count) { Write-Log 'Lista serwerów jest pusta.' 'ERROR' 'Lista'; return 2 }
        Initialize-AvailabilityStats
        Start-SnapshotLoad; Wait-Operations       # poprzednie wyniki: hosty Hyper-V (Linux, wyjaśnienie niedostępności), kolejność skanu
        $script:LastScanState = $null
        Start-Scan @($script:Servers | ForEach-Object { $_.Name }); Wait-Operations
        $st = $script:LastScanState
        if (-not $st) { Write-Log 'Skan się nie odbył.' 'ERROR' 'Skan'; return 2 }
        if (-not $NoReport) { try { [void](Export-HtmlReport -Mode $ReportMode -NoOpen) } catch { Write-Log "Nie utworzono raportu: $($_.Exception.Message)" 'ERROR' 'Raport' } }
        Remove-OldLogs
        if ($st.Offline -or $st.Timeout -or $st.Cancelled) { return 1 }   # Cancelled: limit czasu całego skanu
        return 0
    } catch { Write-Log "Błąd skanu bez okna: $($_.Exception.Message) [linia $($_.InvocationInfo.ScriptLineNumber)]" 'ERROR' 'Program'; return 2 }
    finally { try { $mx.ReleaseMutex() } catch { }; $mx.Dispose() }
}
if ($Scan) { exit (Invoke-HeadlessScan) }
#endregion

#region ── Okno główne ─────────────────────────────────────────────────────────
$script:InstanceMutex = Enter-InstanceMutex 'Gui'
if (-not $script:InstanceMutex) {
    # okna programu jeszcze nie ma – zwykły komunikat systemowy
    [void][System.Windows.MessageBox]::Show("Program jest już uruchomiony z tym folderem danych:`n$Base`n`nPrzełącz się do otwartego okna.", 'Przegląd serwerów', 'OK', 'Warning')
    return
}
Initialize-Native
$window = New-UiElement $script:MainXaml
$ui = Get-NamedElements $window $script:MainXaml
$ui.lstServers.ItemsSource = $script:Servers
$ui.logList.ItemsSource = $script:LogItems
$ui.txtDays.Text = "$($Config.EventDays)"
$ui.txtVersion.Text = "v$script:AppVersion"
$ui.txtSubtitle.Text = "Domena $(if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN.ToLowerInvariant() } else { '(stacja spoza domeny)' }), uruchomione jako $env:USERDOMAIN\$env:USERNAME"
$ui.btnCancelOps.Content = New-IconContent -Text 'Przerwij' -Icon 'E71A' -IconSize 11
$ui.btnLogCopy.Content = New-IconContent -Text '' -Icon 'E8C8' -IconSize 12
$ui.btnLogFile.Content = New-IconContent -Text '' -Icon 'E8E5' -IconSize 12
$ui.btnLogFolder.Content = New-IconContent -Text '' -Icon 'E838' -IconSize 12
$ui.btnLogClear.Content = New-IconContent -Text '' -Icon 'E894' -IconSize 12
$ui.btnLogHide.Content = New-IconContent -Text '' -Icon 'E70D' -IconSize 12
if (-not (Test-PinConfigured)) { $ui.btnLock.Visibility = 'Collapsed' }

# Rozmiar z ustawień, ale nie większy niż obszar roboczy ekranu (np. laptop 1366x768)
$work = [System.Windows.SystemParameters]::WorkArea
$window.Width = [Math]::Min([double]$script:UiState.WindowWidth, [Math]::Max(800, $work.Width))
$window.Height = [Math]::Min([double]$script:UiState.WindowHeight, [Math]::Max(600, $work.Height))
$window.MinWidth = [Math]::Min($window.MinWidth, $work.Width); $window.MinHeight = [Math]::Min($window.MinHeight, $work.Height)
if ($script:UiState.WindowMaximized) { $window.WindowState = 'Maximized' }

$script:EngineTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:EngineTimer.Interval = [TimeSpan]::FromMilliseconds(300)
$script:EngineTimer.Add_Tick({ Update-Operations })

function Update-CredLabel {
    if ($script:Cred) { $ui.txtCredUser.Text = $script:Cred.UserName; $ui.txtCredMode.Text = 'inne konto' }
    else { $ui.txtCredUser.Text = "$env:USERDOMAIN\$env:USERNAME"; $ui.txtCredMode.Text = 'bieżące konto' }
}
function Test-Credential([pscredential]$Cred) {
    # $true / $false – wynik sprawdzenia w domenie; $null – nie da się sprawdzić (konto lokalne, brak domeny)
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $user = $Cred.UserName; $dom = $env:USERDOMAIN
        if ($user -match '^([^\\]+)\\(.+)$') { $dom = $Matches[1]; $user = $Matches[2] } elseif ($user -match '^([^@]+)@(.+)$') { $user = $Matches[1]; $dom = $Matches[2] }
        if ($dom -in '.', $env:COMPUTERNAME) { return $null }
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $dom)
        try { return $ctx.ValidateCredentials($user, $Cred.GetNetworkCredential().Password, [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate) } finally { $ctx.Dispose() }
    } catch { return $null }
}
function Set-OtherCredential {
    $c = $null
    try { $c = Get-Credential -Message 'Konto z uprawnieniami administratora na serwerach' } catch { }
    if (-not $c) { return }
    # Jedna próba w domenie zamiast setek nieudanych logowań na serwerach (blokada konta)
    $ok = Test-Credential $c
    if ($ok -eq $false) { Write-Log "Odrzucono poświadczenia $($c.UserName) – błędne hasło lub konto zablokowane." 'ERROR' 'Konto'; Show-Message "Domena odrzuciła poświadczenia konta $($c.UserName) (błędne hasło, konto zablokowane lub wyłączone). Konto nie zostało zmienione." 'Konto' 'crit'; return }
    $script:Cred = $c
    Write-Log "Konto do połączeń: $($c.UserName)$(if ($null -eq $ok) { ' (nie sprawdzono w domenie)' } else { ' (sprawdzone w domenie)' })" 'INFO' 'Konto'
    Update-CredLabel
    Show-Toast "Konto: $($c.UserName)" 'ok'
}

function Set-LogVisible([bool]$Visible) {
    if (-not $Visible -and $script:UiState.LogVisible -and $ui.logRow.ActualHeight -gt 60) { $script:UiState.LogHeight = [int]$ui.logRow.ActualHeight }
    $script:UiState.LogVisible = $Visible
    if ($Visible) {
        $ui.logRow.Height = New-Object System.Windows.GridLength ([double][Math]::Max(90, [int]$script:UiState.LogHeight))
        $ui.logPanel.Visibility = 'Visible'; $ui.logSplitter.Visibility = 'Visible'
        $script:LogUnread = 0; Update-LogBadge
        if ($script:LogItems.Count) { $ui.logList.ScrollIntoView($script:LogItems[$script:LogItems.Count - 1]) }
    } else {
        $ui.logRow.Height = New-Object System.Windows.GridLength 0
        $ui.logPanel.Visibility = 'Collapsed'; $ui.logSplitter.Visibility = 'Collapsed'
    }
}
function Update-LogFilter {
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:LogItems)
    $t = $ui.txtLogFilter.Text.Trim().ToLowerInvariant()
    $lv = if ($ui.lfErr.IsChecked) { 2 } elseif ($ui.lfWarn.IsChecked) { 1 } else { 0 }
    if (-not $t -and -not $lv) { $view.Filter = $null; return }
    $view.Filter = [Predicate[object]]({
        param($o)
        if ($lv -eq 2 -and $o.Level -ne 'ERROR') { return $false }
        if ($lv -eq 1 -and $o.Level -notin 'WARN', 'ERROR') { return $false }
        if ($t) { return "$($o._Search)".Contains($t) }
        $true
    }.GetNewClosure())
}
function Show-View([string]$Name) {
    switch ($Name) { 'Overview' { $ui.rbOverview.IsChecked = $true } 'Vms' { $ui.rbVms.IsChecked = $true } 'Server' { $ui.rbServer.IsChecked = $true } }
}
function Get-SelectedServerNames { @($ui.lstServers.SelectedItems | ForEach-Object { $_.Name }) }
function Export-GridCsv($Grid, [string]$Name) {
    if ($null -eq $Grid.ItemsSource) { return }
    $rows = @([System.Windows.Data.CollectionViewSource]::GetDefaultView($Grid.ItemsSource))
    if (-not $rows.Count) { Show-Toast 'Brak wierszy do eksportu.' 'info'; return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = "$(Get-SafeName $Name)_$(Get-Date -Format yyyyMMdd_HHmm).csv"
    if ($dlg.ShowDialog($window) -ne $true) { return }
    Export-RowsToCsv $rows $dlg.FileName
    Write-Log "Eksport CSV ($($rows.Count) wierszy): $($dlg.FileName)" 'OK' 'Eksport'
    Show-Toast "Zapisano $($rows.Count) wierszy: $([IO.Path]::GetFileName($dlg.FileName))" 'ok'
}
#endregion

#region ── Zdarzenia interfejsu ─────────────────────────────────────────────────
$onAutoColumn = {
    param($src, $e)
    if ($e.PropertyName -in 'Flag', 'Key', 'Rows' -or $e.PropertyName -like '_*') { $e.Cancel = $true; return }
    $e.Column.Header = Get-Header $e.PropertyName
    $e.Column.MaxWidth = 900
    # właściwości obiektów PowerShell mają typ object, dla którego DataGrid wyłącza sortowanie – sortuje Invoke-GridSort
    $e.Column.CanUserSort = $true
    $e.Column.SortDirection = Get-SortDirection @(Get-GridSort $src) $e.Column.SortMemberPath
    if ($e.Column -is [System.Windows.Controls.DataGridTextColumn]) {
        $st = New-Object System.Windows.Style ([System.Windows.Controls.TextBlock])
        $st.Setters.Add((New-Object System.Windows.Setter -ArgumentList ([System.Windows.Controls.TextBlock]::TextTrimmingProperty), ([System.Windows.TextTrimming]::CharacterEllipsis)))
        $st.Setters.Add((New-Object System.Windows.Setter -ArgumentList ([System.Windows.FrameworkElement]::ToolTipProperty), (New-Object System.Windows.Data.Binding $e.PropertyName)))
        $e.Column.ElementStyle = $st
    }
}
foreach ($g in 'gridDetail', 'gridServers', 'gridHosts', 'gridVms') { $ui[$g].Add_AutoGeneratingColumn($onAutoColumn) }
$onGridSorting = {
    param($src, $e)
    $e.Handled = $true   # zawsze własne sortowanie – domyślne rzuca wyjątkiem przy mieszanych typach liczb
    try { Invoke-GridSort $src $e.Column } catch { Write-Log "Nie udało się posortować: $($_.Exception.Message)" 'WARN' 'Tabela' }
}
foreach ($g in 'gridDetail', 'gridServers', 'gridIssues', 'gridHosts', 'gridVms') { $ui[$g].Add_Sorting($onGridSorting) }

# Widoki
$ui.rbOverview.Add_Checked({ $ui.viewOverview.Visibility = 'Visible'; $ui.viewVms.Visibility = 'Collapsed'; $ui.viewServer.Visibility = 'Collapsed'; Invoke-UiAction 'Widok' { if ($script:UiDirty.Overview -or $null -eq $ui.gridIssues.ItemsSource) { Update-Overview; $script:UiDirty.Overview = $false } } })
$ui.rbVms.Add_Checked({ $ui.viewOverview.Visibility = 'Collapsed'; $ui.viewVms.Visibility = 'Visible'; $ui.viewServer.Visibility = 'Collapsed'; Invoke-UiAction 'Widok' { Update-VmView; $script:UiDirty.Vms = $false } })
$ui.rbServer.Add_Checked({ $ui.viewOverview.Visibility = 'Collapsed'; $ui.viewVms.Visibility = 'Collapsed'; $ui.viewServer.Visibility = 'Visible'; Invoke-UiAction 'Widok' { Show-ServerDetail $script:CurrentServer; $script:UiDirty.Detail = $false } })

# Filtry (z opóźnieniem – bez przeliczania po każdym znaku)
foreach ($rb in 'rbSevAll', 'rbSevCrit', 'rbSevWarn', 'rbSevInfo') { $ui[$rb].Add_Checked({ Update-IssueFilter }) }
$ui.txtIssueFilter.Add_TextChanged({ Request-Filter 'issues' { Update-IssueFilter } })
$ui.txtGridFilter.Add_TextChanged({ Request-Filter 'detail' { Update-DetailFilter } })
$ui.txtServerFilter.Add_TextChanged({ Request-Filter 'servers' { Update-ServerFilter } })
foreach ($rb in 'sfAll', 'sfProblems', 'sfOffline', 'sfHosts', 'sfVms', 'sfNew') { $ui[$rb].Add_Checked({ Update-ServerFilter }) }
$ui.chkIgnored.Add_Click({ Invoke-UiAction 'Widok' { Update-Overview } })
foreach ($rb in 'vfAll', 'vfRunning', 'vfOff', 'vfProblems', 'vfNotListed') { $ui[$rb].Add_Checked({ Update-VmFilter }) }
$ui.txtVmFilter.Add_TextChanged({ Request-Filter 'vms' { Update-VmFilter } })
foreach ($rb in 'lfAll', 'lfWarn', 'lfErr') { $ui[$rb].Add_Checked({ Update-LogFilter }) }
$ui.txtLogFilter.Add_TextChanged({ Request-Filter 'log' { Update-LogFilter } })

# Kafelki = szybkie filtry
$ui.tileTotal.Add_MouseLeftButtonUp({ $ui.sfAll.IsChecked = $true; $ui.rbSevAll.IsChecked = $true })
$ui.tileOnline.Add_MouseLeftButtonUp({ $ui.sfAll.IsChecked = $true })
$ui.tileOffline.Add_MouseLeftButtonUp({ $ui.sfOffline.IsChecked = $true; $ui.txtIssueFilter.Text = 'łączność'; $ui.rbSevAll.IsChecked = $true })
$ui.tileCrit.Add_MouseLeftButtonUp({ $ui.rbSevCrit.IsChecked = $true; $ui.txtIssueFilter.Text = '' })
$ui.tileWarn.Add_MouseLeftButtonUp({ $ui.rbSevWarn.IsChecked = $true; $ui.txtIssueFilter.Text = '' })
$ui.tileHv.Add_MouseLeftButtonUp({ Show-View 'Vms' })

# Lista serwerów
$ui.lstServers.Add_SelectionChanged({
    if ($script:Refreshing) { return }
    $sel = @($ui.lstServers.SelectedItems)
    if ($sel.Count -ne 1) { return }   # kilka zaznaczonych – tylko do akcji z menu (skan, diagnoza, usunięcie)
    Invoke-UiAction 'Widok' {
        if ($ui.rbServer.IsChecked) { Show-ServerDetail $sel[0].Name }
        else { $script:CurrentServer = $sel[0].Name; $ui.rbServer.IsChecked = $true }
    }
})
$ui.lstSections.Add_SelectionChanged({ Invoke-UiAction 'Widok' { Show-Section } })

function Format-RowDetail($Row) {
    if (-not $Row) { return '' }
    $skip = 'Flag', 'Key', 'Rows', 'SevColor', 'SevBg', 'Rank', 'ServerKey', 'Section', 'IssueKey', 'Ignored'
    $lines = @($Row.PSObject.Properties | Where-Object { $skip -notcontains $_.Name -and $_.Name -notlike '_*' } | ForEach-Object { "{0}: {1}" -f (Get-Header $_.Name), $_.Value })
    $lines -join [Environment]::NewLine
}
$ui.gridDetail.Add_SelectionChanged({ $ui.dRowDetail.Text = Format-RowDetail $ui.gridDetail.SelectedItem })
$ui.gridIssues.Add_SelectionChanged({ $ui.dIssueDetail.Text = Format-RowDetail $ui.gridIssues.SelectedItem })

function Remove-SelectedServers {
    $sel = @($ui.lstServers.SelectedItems)
    if (-not $sel.Count -or (Get-Operation 'Scan')) { return }
    if ($sel.Count -gt 1 -and -not (Confirm-Action -Text "Usunąć z listy serwerów: $($sel.Count) ($(Join-Short ($sel | ForEach-Object { $_.Display }) 10))?`n`nMigawki na dysku zostaną (usuwa je limit przechowywania)." -Title 'Usuń z listy' -ConfirmText 'Usuń' -Danger)) { return }
    Remove-ServerEntries $sel
    Save-ServerList
    Write-Log "Usunięto z listy: $(Join-Short ($sel | ForEach-Object { $_.Display }) 15)" 'INFO' 'Lista'
    if (-not $script:CurrentServer -and $ui.rbServer.IsChecked) { Show-ServerDetail $null }
    Update-VmIndex
    Request-UiRefresh -All
}
$ui.lstServers.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Delete') { Invoke-UiAction 'Lista' { Remove-SelectedServers } } })

# Menu kontekstowe listy serwerów (budowane przy otwarciu – zależy od zaznaczenia)
$ui.lstServers.ContextMenu = New-Object System.Windows.Controls.ContextMenu
$ui.lstServers.Add_ContextMenuOpening({
    param($s, $e)
    $m = $ui.lstServers.ContextMenu
    $m.Items.Clear()
    $names = @(Get-SelectedServerNames)
    if (-not $names.Count) { $e.Handled = $true; return }
    $one = $names[0]
    $busy = [bool](Get-Operation 'Scan')
    [void]$m.Items.Add((New-MenuItem $(if ($names.Count -gt 1) { "Skanuj zaznaczone ($($names.Count))" } else { 'Skanuj ten serwer' }) 'E768' { Start-Scan @(Get-SelectedServerNames) } -Enabled (-not $busy)))
    [void]$m.Items.Add((New-MenuItem $(if ($names.Count -gt 1) { "Diagnozuj połączenie ($($names.Count))" } else { 'Diagnozuj połączenie' }) 'E9D9' { Start-Diagnostics @(Get-SelectedServerNames) }))
    [void]$m.Items.Add((New-MenuItem 'Kopiuj nazwy' 'E8C8' { $t = (@(Get-SelectedServerNames) -join [Environment]::NewLine); [System.Windows.Clipboard]::SetText($t); Show-Toast "Skopiowano nazw: $(@(Get-SelectedServerNames).Count)" 'ok' }))
    [void]$m.Items.Add((New-MenuSeparator))
    if ($names.Count -eq 1) {
        [void]$m.Items.Add((New-MenuItem 'Połącz przez RDP' 'E7F4' { Start-Process mstsc.exe -ArgumentList "/v:$(@(Get-SelectedServerNames)[0])" }))
        [void]$m.Items.Add((New-MenuItem 'PowerShell (Enter-PSSession)' 'E756' { $n = @(Get-SelectedServerNames)[0]; Start-Process powershell.exe -ArgumentList '-NoExit', '-Command', "Enter-PSSession -ComputerName '$n'" }))
        [void]$m.Items.Add((New-MenuItem 'Zarządzanie komputerem' 'E770' { Start-Process compmgmt.msc -ArgumentList "/computer:\\$(@(Get-SelectedServerNames)[0])" }))
        [void]$m.Items.Add((New-MenuItem 'Podgląd zdarzeń' 'E81C' { Start-Process eventvwr.exe -ArgumentList @(Get-SelectedServerNames)[0] }))
        [void]$m.Items.Add((New-MenuItem 'Usługi' 'E713' { Start-Process services.msc -ArgumentList "/computer:\\$(@(Get-SelectedServerNames)[0])" }))
        [void]$m.Items.Add((New-MenuItem 'Otwórz udział C$' 'E838' { Start-Process explorer.exe -ArgumentList "\\$(@(Get-SelectedServerNames)[0])\C$" }))
        $it = Get-ServerItem $one
        if ($it -and $it.Kind -eq 'HV') { [void]$m.Items.Add((New-MenuItem 'Pokaż maszyny tego hosta' 'E8FD' { $h = (Get-ServerItem @(Get-SelectedServerNames)[0]).Display; Show-View 'Vms'; $ui.vfAll.IsChecked = $true; $ui.txtVmFilter.Text = $h.ToLowerInvariant() })) }
        if ($it -and $it.HvHost) { [void]$m.Items.Add((New-MenuItem "Przejdź do hosta $($it.HvHost)" 'E8FD' { $h = (Get-ServerItem @(Get-SelectedServerNames)[0]).HvHost; $hk = @($script:Servers | Where-Object { $_.Display -eq $h })[0]; if ($hk) { Select-Server $hk.Name 'HyperV' } else { Show-Toast "Host $h nie jest na liście serwerów." 'info' } })) }
        [void]$m.Items.Add((New-MenuSeparator))
    }
    [void]$m.Items.Add((New-MenuItem $(if ($names.Count -gt 1) { "Usuń z listy ($($names.Count))" } else { 'Usuń z listy' }) 'E74D' { Remove-SelectedServers } -Danger -Enabled (-not $busy)))
})

# Menu problemów (przegląd i sekcja Problemy w szczegółach): wyciszanie
function Get-ContextIssue($Grid) {
    $r = $Grid.SelectedItem
    if (-not $r) { return $null }
    if ($r.PSObject.Properties['_Issue']) { return $r._Issue }
    if ($r.PSObject.Properties['IssueKey']) { return $r }
    $null
}
$script:IssueMenuOpening = {
    param($s, $e)
    $m = $s.ContextMenu
    $m.Items.Clear()
    $i = Get-ContextIssue $s
    if (-not $i) { $e.Handled = $true; return }
    $script:MenuIssue = $i
    if ($i.Ignored) {
        [void]$m.Items.Add((New-MenuItem 'Przywróć (usuń wyciszenie)' 'E767' { Remove-IgnoreRule $script:MenuIssue }))
    } else {
        [void]$m.Items.Add((New-MenuItem "Wycisz na serwerze $($i.Server)" 'E74F' { Add-IgnoreRule $script:MenuIssue }))
        [void]$m.Items.Add((New-MenuItem 'Wycisz na wszystkich serwerach' 'E74F' { Add-IgnoreRule $script:MenuIssue -AllServers }))
    }
    [void]$m.Items.Add((New-MenuSeparator))
    [void]$m.Items.Add((New-MenuItem 'Kopiuj treść' 'E8C8' { [System.Windows.Clipboard]::SetText("$($script:MenuIssue.Server): $($script:MenuIssue.Message)"); Show-Toast 'Skopiowano.' 'ok' 2 }))
    if ($s -eq $ui.gridIssues -and $i.ServerKey -and (Get-ServerItem $i.ServerKey)) { [void]$m.Items.Add((New-MenuItem 'Otwórz serwer' 'E9D9' { Select-Server $script:MenuIssue.ServerKey $script:MenuIssue.Section })) }
}
foreach ($g in 'gridIssues', 'gridDetail') { $ui[$g].ContextMenu = New-Object System.Windows.Controls.ContextMenu; $ui[$g].Add_ContextMenuOpening($script:IssueMenuOpening) }

$addHandler = {
    $names = @($ui.txtAdd.Text -split '[,;\s]+' | Where-Object { $_ })
    $n = 0
    foreach ($x in $names) { if (Add-ServerEntry $x) { $n++ } }
    if ($names.Count) {
        Save-ServerList; $ui.txtAdd.Text = ''
        Write-Log "Dodano do listy: $n ($(Join-Short $names 10))$(if ($n -lt $names.Count) { "; pominięto duplikaty: $($names.Count - $n)" })" 'INFO' 'Lista'
        Refresh-ServerList; Request-UiRefresh -All
    }
}
$ui.btnAdd.Add_Click({ Invoke-UiAction 'Lista' $addHandler })
$ui.txtAdd.Add_KeyDown({ param($s, $e); if ($e.Key -eq 'Return') { Invoke-UiAction 'Lista' $addHandler } })

$ui.btnAD.Add_Click({
    Invoke-UiAction 'Lista' {
        $old = $window.Cursor; $window.Cursor = [System.Windows.Input.Cursors]::Wait
        try { $found = @(Get-ServersFromAD) } catch { Show-Message "Nie udało się odpytać AD: $($_.Exception.Message)" 'Pobierz z AD' 'crit'; return } finally { $window.Cursor = $old }
        if (-not $found.Count) { Show-Message "Nie znaleziono aktywnych kont serwerów Windows w AD$(if ($Config.AdSearchBase) { " (OU: $($Config.AdSearchBase))" })." 'Pobierz z AD' 'info'; return }
        # $dn przed wewnętrznym Where-Object – tam $_ to już pozycja listy, nie wynik z AD
        $new = @($found | Where-Object { $dn = Get-DisplayName $_.Name; -not (Get-ServerItem $_.Name) -and -not @($script:Servers | Where-Object { $_.Display -eq $dn }).Count })
        if (-not $new.Count) { Show-Toast "W AD jest $($found.Count) aktywnych serwerów – wszystkie są już na liście." 'info'; return }
        if (Confirm-Action -Text "W AD jest $($found.Count) aktywnych serwerów Windows (logowanie w ostatnich $($Config.AdInactiveDays) dniach$(if ($Config.AdSearchBase) { ", OU: $($Config.AdSearchBase)" })), z czego $($new.Count) nie ma jeszcze na liście:`n$(Join-Short ($new | ForEach-Object { Get-DisplayName $_.Name }) 20)`n`nDodać brakujące?" -Title 'Pobierz z AD' -ConfirmText 'Dodaj' -Tone 'info') {
            foreach ($f in ($new | Sort-Object Name)) { [void](Add-ServerEntry $f.Name $f.OS) }
            Save-ServerList
            Write-Log "Dodano z AD: $($new.Count) serwerów" 'OK' 'Lista'
            Refresh-ServerList; Request-UiRefresh -All
            Show-Toast "Dodano z AD: $($new.Count)" 'ok'
        }
    }
})
$ui.btnFile.Add_Click({
    Invoke-UiAction 'Lista' {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Lista serwerów (*.txt;*.csv)|*.txt;*.csv|Wszystkie pliki|*.*'
        if ($dlg.ShowDialog($window) -eq $true) {
            $n = Import-ServerFile $dlg.FileName
            Save-ServerList
            Write-Log "Dodano z pliku $($dlg.FileName): $n serwerów" 'OK' 'Lista'
            Refresh-ServerList; Request-UiRefresh -All
            Show-Toast "Dodano z pliku: $n" 'ok'
        }
    }
})
$ui.btnCred.ContextMenu = New-Object System.Windows.Controls.ContextMenu
$ui.btnCred.Add_Click({
    $m = $ui.btnCred.ContextMenu
    $m.Items.Clear()
    [void]$m.Items.Add((New-MenuItem 'Użyj innego konta…' 'E77B' { Set-OtherCredential }))
    [void]$m.Items.Add((New-MenuItem "Wróć do bieżącego konta ($env:USERDOMAIN\$env:USERNAME)" 'E72C' { $script:Cred = $null; Update-CredLabel; Write-Log 'Konto do połączeń: bieżące' 'INFO' 'Konto' } -Enabled ([bool]$script:Cred)))
    $m.PlacementTarget = $ui.btnCred; $m.Placement = 'Bottom'; $m.IsOpen = $true
})
$ui.btnReport.ContextMenu = New-Object System.Windows.Controls.ContextMenu
$ui.btnReport.Add_Click({
    $m = $ui.btnReport.ContextMenu
    $m.Items.Clear()
    [void]$m.Items.Add((New-MenuItem 'Raport – podsumowanie (problemy, niedostępność, Hyper-V)' 'E8A5' { [void](Export-HtmlReport -Mode Summary) }))
    [void]$m.Items.Add((New-MenuItem 'Raport – pełny (wszystkie sekcje)' 'E8A5' {
        if ($script:Data.Count -gt 60 -and -not (Confirm-Action -Text "Pełny raport $($script:Data.Count) serwerów wczyta kolejno wszystkie migawki i może mieć kilkadziesiąt MB. Kontynuować?" -Title 'Raport pełny' -ConfirmText 'Utwórz' -Tone 'info')) { return }
        $old = $window.Cursor; $window.Cursor = [System.Windows.Input.Cursors]::Wait
        try { [void](Export-HtmlReport -Mode Full) } finally { $window.Cursor = $old }
    }))
    [void]$m.Items.Add((New-MenuSeparator))
    [void]$m.Items.Add((New-MenuItem 'Otwórz folder raportów' 'E838' { New-Item -ItemType Directory -Force -Path $Config.ReportDir | Out-Null; Start-Process explorer.exe -ArgumentList "`"$($Config.ReportDir)`"" }))
    $m.PlacementTarget = $ui.btnReport; $m.Placement = 'Bottom'; $m.IsOpen = $true
})
$ui.btnScan.Add_Click({
    $op = Get-Operation 'Scan'
    if ($op) { Stop-Operation $op 'Skan przerwany przez użytkownika'; return }
    Invoke-UiAction 'Skan' { Start-Scan @($script:Servers | ForEach-Object { $_.Name }) }
})
$ui.btnCancelOps.Add_Click({ Stop-AllOperations 'Przerwano przez użytkownika' })
$ui.btnRescan.Add_Click({ if ($script:CurrentServer) { Invoke-UiAction 'Skan' { Start-Scan @($script:CurrentServer) } } })
$ui.btnDiag.Add_Click({ if ($script:CurrentServer) { Invoke-UiAction 'Diagnoza' { Start-Diagnostics @($script:CurrentServer) } } })
$ui.btnSettings.Add_Click({ Invoke-UiAction 'Ustawienia' { Show-SettingsDialog } })
$ui.btnLock.Add_Click({ Invoke-UiAction 'Blokada' { Lock-Program } })
$ui.btnVmAdd.Add_Click({ Invoke-UiAction 'Lista' { Add-VmsToList } })
$ui.btnCsv.Add_Click({ Invoke-UiAction 'Eksport' { $sel = $ui.lstSections.SelectedItem; if ($sel) { Export-GridCsv $ui.gridDetail "$(Get-DisplayName $script:CurrentServer)_$($sel.Key)" } } })
$ui.btnIssuesCsv.Add_Click({ Invoke-UiAction 'Eksport' { Export-GridCsv $ui.gridIssues 'Problemy' } })
$ui.btnServersCsv.Add_Click({ Invoke-UiAction 'Eksport' { Export-GridCsv $ui.gridServers 'Stan_serwerow' } })
$ui.btnVmCsv.Add_Click({ Invoke-UiAction 'Eksport' { Export-GridCsv $ui.gridVms 'Maszyny_wirtualne' } })

$ui.gridIssues.Add_MouseDoubleClick({ param($s, $e) $i = Get-ClickedRowItem $e; if ($i -and $i.ServerKey -and (Get-ServerItem $i.ServerKey)) { Invoke-UiAction 'Widok' { Select-Server $i.ServerKey $i.Section } } })
$ui.gridServers.Add_MouseDoubleClick({ param($s, $e) $r = Get-ClickedRowItem $e; if ($r) { Invoke-UiAction 'Widok' { Select-Server $r.Key 'Issues' } } })
$ui.gridHosts.Add_MouseDoubleClick({ param($s, $e) $r = Get-ClickedRowItem $e; if ($r) { Invoke-UiAction 'Widok' { Select-Server $r.Key 'HvHost' } } })
$ui.gridVms.Add_MouseDoubleClick({
    param($s, $e)
    $r = Get-ClickedRowItem $e
    if (-not $r) { return }
    Invoke-UiAction 'Widok' { if ($r._ServerKey) { Select-Server $r._ServerKey 'Issues' } else { Select-Server $r._HostKey 'HyperV' } }
})

# Dziennik
$ui.btnLogToggle.Add_Click({ Set-LogVisible (-not $script:UiState.LogVisible) })
$ui.btnLogHide.Add_Click({ Set-LogVisible $false })
$ui.btnLogClear.Add_Click({ $script:LogItems.Clear() })
$ui.btnLogFile.Add_Click({ $f = Get-LogFile; if (Test-Path -LiteralPath $f) { Start-Process notepad.exe -ArgumentList "`"$f`"" } else { Start-Process explorer.exe -ArgumentList "`"$($Config.LogDir)`"" } })
$ui.btnLogFolder.Add_Click({ New-Item -ItemType Directory -Force -Path $Config.LogDir | Out-Null; Start-Process explorer.exe -ArgumentList "`"$($Config.LogDir)`"" })
$ui.btnLogCopy.Add_Click({
    $items = @($ui.logList.SelectedItems)
    if ($items.Count -eq 0) { $items = @([System.Windows.Data.CollectionViewSource]::GetDefaultView($script:LogItems)) }
    $text = (@($items | ForEach-Object { '{0} [{1}] [{2}] {3}' -f $_.Time, $_.Level, $_.Module, $_.Message }) -join [Environment]::NewLine)
    if ($text) { [System.Windows.Clipboard]::SetText($text); Show-Toast "Skopiowano wpisów: $($items.Count)" 'ok' }
})

# Skróty klawiszowe
$window.Add_PreviewKeyDown({
    param($s, $e)
    try {
        $mods = [System.Windows.Input.Keyboard]::Modifiers
        $none = [System.Windows.Input.ModifierKeys]::None
        $ctrl = [System.Windows.Input.ModifierKeys]::Control
        $shift = [System.Windows.Input.ModifierKeys]::Shift
        $key = $e.Key
        if ($key -eq [System.Windows.Input.Key]::F5 -and $mods -eq $none) { if (-not (Get-Operation 'Scan')) { Start-Scan @($script:Servers | ForEach-Object { $_.Name }) }; $e.Handled = $true }
        elseif ($key -eq [System.Windows.Input.Key]::F5 -and $mods -eq $shift) { $n = @(Get-SelectedServerNames); if ($n.Count -and -not (Get-Operation 'Scan')) { Start-Scan $n }; $e.Handled = $true }
        elseif ($key -eq [System.Windows.Input.Key]::F -and $mods -eq $ctrl) {
            $tb = if ($ui.viewServer.Visibility -eq 'Visible') { $ui.txtGridFilter } elseif ($ui.viewVms.Visibility -eq 'Visible') { $ui.txtVmFilter } else { $ui.txtIssueFilter }
            [void]$tb.Focus(); $tb.SelectAll(); $e.Handled = $true
        }
        elseif ($key -eq [System.Windows.Input.Key]::L -and $mods -eq ($ctrl -bor $shift)) { $e.Handled = $true; Lock-Program }
        elseif ($key -eq [System.Windows.Input.Key]::L -and $mods -eq $ctrl) { Set-LogVisible (-not $script:UiState.LogVisible); $e.Handled = $true }
        elseif ($mods -eq $ctrl -and $key -eq [System.Windows.Input.Key]::D1) { Show-View 'Overview'; $e.Handled = $true }
        elseif ($mods -eq $ctrl -and $key -eq [System.Windows.Input.Key]::D2) { Show-View 'Vms'; $e.Handled = $true }
        elseif ($mods -eq $ctrl -and $key -eq [System.Windows.Input.Key]::D3) { Show-View 'Server'; $e.Handled = $true }
        elseif ($key -eq [System.Windows.Input.Key]::Escape -and $e.OriginalSource -is [System.Windows.Controls.TextBox] -and -not $e.OriginalSource.IsReadOnly) { $e.OriginalSource.Text = ''; $e.Handled = $true }
    } catch { Write-Log "Błąd skrótu klawiszowego: $($_.Exception.Message)" 'ERROR' 'Program' }
})
$window.Add_SourceInitialized({ param($s, $e) Set-DarkTitleBar $s })
$window.Dispatcher.Add_UnhandledException({
    param($s, $e)
    $e.Handled = $true
    Write-Log "Nieobsłużony błąd interfejsu: $($e.Exception.Message)" 'ERROR' 'Program'
    Show-Toast "Błąd: $(Get-ShortText $e.Exception.Message 160)" 'crit' 6
})
$window.Add_Closing({
    param($s, $e)
    try {
        if ($script:Ops.Count -and -not $script:UnlockState.Emergency) {
            # zamknięcie awaryjne z ekranu blokady w trakcie tego pytania też zamyka program
            if (-not (Confirm-Action -Text 'Trwa skan lub wczytywanie wyników. Zamknięcie programu je przerwie. Zamknąć mimo to?' -Title 'Zamknięcie programu' -ConfirmText 'Zamknij' -Danger) -and -not $script:UnlockState.Emergency) { $e.Cancel = $true; return }
        }
        Stop-AllOperations 'Zamykanie programu'
        $script:UiState.WindowMaximized = ($s.WindowState -eq 'Maximized')
        if ($s.WindowState -eq 'Normal') { $script:UiState.WindowWidth = [int]$s.ActualWidth; $script:UiState.WindowHeight = [int]$s.ActualHeight }
        if ($script:UiState.LogVisible) { $script:UiState.LogHeight = [int]$ui.logRow.ActualHeight }
        try { Save-UserSettings } catch { }
        Write-Log 'Zamknięto program.' 'INFO' 'Program'
    } catch { }
})
$window.Add_Loaded({
    Invoke-UiAction 'Program' {
        Remove-OldLogs
        if (Test-Path -LiteralPath $Config.ServerListFile) {
            try { [void](Import-ServerFile $Config.ServerListFile) } catch { Write-Log "Nie wczytano listy serwerów $($Config.ServerListFile): $($_.Exception.Message)" 'ERROR' 'Lista' }
        }
        Initialize-AvailabilityStats
        Refresh-ServerList
        Update-SettingsButton
        Update-CredLabel
        Set-LogVisible ([bool]$script:UiState.LogVisible)
        Update-Overview
        if (-not $script:Servers.Count) { $ui.txtStatus.Text = 'Dodaj serwery: przycisk AD, Plik albo wpisz nazwę w polu po lewej' }
        else { $ui.txtStatus.Text = "Wczytano $($script:Servers.Count) serwerów z $($Config.ServerListFile)" }
        Write-Log ("Lista serwerów: {0} ({1})" -f $script:Servers.Count, $Config.ServerListFile) 'INFO' 'Lista'
        if ($script:BaseFallback) { Write-Log $script:BaseFallback 'WARN' 'Program' }
        if ($script:SettingsWarning) { Write-Log $script:SettingsWarning 'WARN' 'Ustawienia' }
        if (-not $script:NativeOk) { Write-Log "Bez kodu natywnego (ciemny pasek tytułu, szybkie sortowanie): $script:NativeError" 'INFO' 'Program' }
        if ($script:LogFailed) { Write-Log "Nie można zapisywać dziennika w $($Config.LogDir)" 'WARN' 'Program' }
        Start-SnapshotLoad
        Start-IdleLock
    }
})
Register-IdleActivity -Window $window
#endregion

#region ── Uruchomienie ─────────────────────────────────────────────────────────
Write-Log ("Przegląd serwerów {0} – start (PowerShell {1}, {2}\{3}, dane: {4})" -f $script:AppVersion, $PSVersionTable.PSVersion, $env:USERDOMAIN, $env:USERNAME, $Base) 'INFO' 'Program'
try {
    if (Unlock-AtStart) {
        if (Test-PinConfigured) { Write-Log 'Program odblokowany PIN-em.' 'INFO' 'Blokada' }
        [void]$window.ShowDialog()
    }
}
finally {
    if ($script:IdleLock.Timer) { $script:IdleLock.Timer.Stop() }
    if ($script:EngineTimer) { $script:EngineTimer.Stop() }
    # Zadania jeszcze działające: przerwanie i krótka chwila na zakończenie (wątki tła nie blokują zamknięcia procesu)
    $deadline = (Get-Date).AddSeconds(5)
    foreach ($op in @($script:Ops)) { foreach ($it in $op.Items) { if (-not $it.Finished) { try { [void]$it.PS.BeginStop($null, $null) } catch { } } } }
    foreach ($op in @($script:Ops)) { foreach ($it in $op.Items) { $left = [int][Math]::Max(0, ($deadline - (Get-Date)).TotalMilliseconds); try { [void]$it.Handle.AsyncWaitHandle.WaitOne($left) } catch { } } }
    foreach ($k in 'Remote', 'Local') { $p = $script:Pools[$k]; if ($p) { try { $p.BeginClose($null, $null) | Out-Null } catch { } } }
    if ($script:InstanceMutex) { try { $script:InstanceMutex.ReleaseMutex() } catch { }; $script:InstanceMutex.Dispose() }
}
#endregion
