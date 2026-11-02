<#
    Kontrole CI dla ServerReview.ps1 (uruchamiane przez .github/workflows/ci.yml na windows-latest, Windows PowerShell 5.1).
    Plik musi być zapisany jako UTF-8 z BOM – inaczej Windows PowerShell 5.1 źle odczyta polskie znaki.
    Użycie: powershell.exe -NoProfile -File tools\ci.ps1 -Step Encoding|Syntax|Analyzer|Collector
#>
param([Parameter(Mandatory)][ValidateSet('Encoding', 'Syntax', 'Analyzer', 'Collector')][string]$Step)
$ErrorActionPreference = 'Stop'
$file = Join-Path (Split-Path $PSScriptRoot -Parent) 'ServerReview.ps1'
function Fail([string]$Msg, [int]$Line = 0) { Write-Output "::error file=ServerReview.ps1$(if ($Line) { ",line=$Line" })::$Msg" }

switch ($Step) {
    'Encoding' {
        $b = [IO.File]::ReadAllBytes($file)
        if ($b.Length -lt 3 -or $b[0] -ne 0xEF -or $b[1] -ne 0xBB -or $b[2] -ne 0xBF) { Fail 'Plik musi być zapisany jako UTF-8 z BOM (polskie znaki w Windows PowerShell 5.1)'; exit 1 }
        $t = [Text.Encoding]::UTF8.GetString($b)
        $lf = ([regex]::Matches($t, '(?<!\r)\n')).Count
        if ($lf) { Fail "$lf linii kończy się samym LF zamiast CRLF"; exit 1 }
        'Kodowanie: UTF-8 z BOM, CRLF'
    }
    'Syntax' {
        $tokens = $null; $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errs)
        foreach ($e in $errs) { Fail $e.Message $e.Extent.StartLineNumber }
        if ($errs) { exit 1 }
        "PowerShell $($PSVersionTable.PSVersion): bez błędów składni"
    }
    'Analyzer' {
        Set-PSRepository PSGallery -InstallationPolicy Trusted
        Install-Module PSScriptAnalyzer -RequiredVersion 1.23.0 -Scope CurrentUser -Force
        # Błędy plus reguły wykrywające realne pomyłki (nie styl): przypisanie do zmiennej automatycznej ($input, $args, $_ …),
        # '=' zamiast '-eq' w warunku, '>' zamiast '-gt', zła składnia wywołania polecenia, wiszący znak ` na końcu linii
        $rules = 'PSAvoidAssignmentToAutomaticVariable', 'PSPossibleIncorrectUsageOfAssignmentOperator', 'PSPossibleIncorrectUsageOfRedirectionOperator',
                 'PSUseCmdletCorrectly', 'PSMisleadingBacktick'
        $res = @(Invoke-ScriptAnalyzer -Path $file -Severity Error) + @(Invoke-ScriptAnalyzer -Path $file -IncludeRule $rules)
        foreach ($r in $res) { Fail "[$($r.RuleName)] $($r.Message)" $r.Line }
        if ($res.Count) { "Znaleziono: $($res.Count)"; exit 1 }
        'PSScriptAnalyzer: bez uwag'
    }
    'Collector' {
        # Kolektor ($Collector) wyjęty z drzewa składni i uruchomiony na maszynie runnera (Windows Server, konto administratora)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)
        $as = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$Collector' }, $true)
        if (-not $as) { Fail 'Nie znaleziono $Collector'; exit 1 }
        $collector = & ([scriptblock]::Create($as.Right.Extent.Text))
        $ErrorActionPreference = 'Continue'
        $out = @(& $collector 7 @('C:\Windows\Temp') 1000 $false @() @(445, 3389, 5985) 2>&1)
        $json = $out | Where-Object { $_ -is [string] -and $_.StartsWith('{') } | Select-Object -Last 1
        if (-not $json) { Fail 'Kolektor nie zwrócił JSON'; $out | Select-Object -First 20 | ForEach-Object { "$_" }; exit 1 }
        $d = $json | ConvertFrom-Json
        if ($d.PSObject.Properties['Fatal']) { Fail "Kolektor przerwał pracę: $($d.Fatal)"; exit 1 }
        foreach ($o in @($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })) { Write-Output "::warning::Błąd poza sekcjami kolektora: $o" }
        "Czas: $($d.DurationSec) s, rozmiar JSON: $([math]::Round($json.Length / 1KB)) KB"
        $d.Timings | Select-Object -First 12 | Format-Table -AutoSize | Out-String
        foreach ($e in @($d.Errors)) { Write-Output "::warning::Sprawdzenie nie wykonane: $e" }
        $s = $d.System
        "System: $($s.OS) $($s.Build); aktywacja: $($s.LicenseStatus) ($($s.LicenseChannel)), pozostało dni: $($s.LicenseGraceDays)"
        foreach ($k in 'Disks', 'Backup', 'AppRoles') { "${k}: $(@($d.$k | Where-Object { $_ }).Count) wierszy" }
        # nowe sekcje nie mogą kończyć się błędem na czystym systemie
        $bad = @($d.Errors | Where-Object { "$_" -match '^(Kopie zapasowe|Role aplikacyjne|Aktywacja Windows):' })
        foreach ($e in $bad) { Fail "Nowa sekcja zakończona błędem: $e" }
        if ($bad.Count) { exit 1 }
    }
}
