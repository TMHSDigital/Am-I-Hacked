<#
.SYNOPSIS
    Test harness for Am I Hacked — creates safe mock IOCs and validates detection.
.DESCRIPTION
    Drops harmless artifacts that should trigger specific findings, runs AmIHacked.ps1
    with -ExportJson, then validates the JSON output contains expected findings.
    All artifacts are cleaned up after the test.
.NOTES
    Run from the repo root: .\tests\Invoke-MockScan.ps1
    Requires: PowerShell 5.1+. Some tests require Administrator.
#>

[CmdletBinding()]
param(
    [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:CleanupActions = [System.Collections.ArrayList]::new()

$repoRoot = Split-Path $PSScriptRoot -Parent

function Write-TestHeader { param([string]$Name)
    Write-Host "`n  ── TEST: $Name " -ForegroundColor Cyan -NoNewline
    Write-Host "─" * (50 - $Name.Length) -ForegroundColor DarkCyan
}

function Assert-FindingExists {
    param(
        [object[]]$Findings,
        [string]$TitlePattern,
        [string]$TestName
    )
    $match = $Findings | Where-Object { $_.Title -match $TitlePattern }
    if ($match) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] $TestName — no finding matching '$TitlePattern'" -ForegroundColor Red
        $script:TestsFailed++
    }
}

function Assert-FindingCount {
    param(
        [object[]]$Findings,
        [string]$Category,
        [int]$MinCount,
        [string]$TestName
    )
    $count = ($Findings | Where-Object { $_.Category -eq $Category }).Count
    if ($count -ge $MinCount) {
        Write-Host "  [PASS] $TestName ($count findings in '$Category')" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] $TestName — expected >= $MinCount in '$Category', got $count" -ForegroundColor Red
        $script:TestsFailed++
    }
}

# ── Setup: Create mock artifacts ─────────────────────────────────────────────

Write-Host "`n  ╔══════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║   Am I Hacked? — Test Harness            ║" -ForegroundColor Magenta
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Magenta

$testTempDir = Join-Path $env:TEMP "AmIHacked_Test_$(Get-Random)"
New-Item -ItemType Directory -Path $testTempDir -Force | Out-Null
$script:CleanupActions.Add({ Remove-Item $testTempDir -Recurse -Force -ErrorAction SilentlyContinue }) | Out-Null

# ── Unit tests (no scan needed) ──────────────────────────────────────────────

function Assert-True {
    param([bool]$Condition, [string]$TestName, [string]$FailDetail = "")
    if ($Condition) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] $TestName$(if ($FailDetail) { " — $FailDetail" })" -ForegroundColor Red
        $script:TestsFailed++
    }
}

. "$repoRoot\lib\Helpers.ps1"
. "$repoRoot\lib\ReportGenerator.ps1"

Write-TestHeader "Report Verdict With One Critical"
$unitFindings = [System.Collections.ArrayList]::new()
$unitFindings.Add([PSCustomObject]@{ Severity = "CRITICAL"; Category = "Unit"; Title = "Unit critical"; Description = "d"; Remediation = "r"; Details = $null; MITRE = @("T1059") }) | Out-Null
$unitFindings.Add([PSCustomObject]@{ Severity = "INFO"; Category = "Unit"; Title = "Unit info"; Description = "d"; Remediation = "r"; Details = $null; MITRE = @("T1059") }) | Out-Null
$unitReport = Join-Path $testTempDir "unit_report.html"
Generate-HtmlReport -Findings $unitFindings -SystemInfo @{ ComputerName = "UNIT"; UserName = "unit"; Domain = "unit"; OSVersion = "unit"; OSBuild = "0"; PSVersion = "5.1"; IsAdmin = $false; ScanTime = (Get-Date) } `
    -OutputFile $unitReport -Duration ([timespan]::FromSeconds(1)) -Version "test" | Out-Null
$unitHtml = Get-Content $unitReport -Raw
Assert-True ($unitHtml -match 'data-verdict="COMPROMISED" data-critical="1"') "Single CRITICAL finding yields COMPROMISED verdict and count 1" "report verdict banner: $([regex]::Match($unitHtml, 'data-verdict="[^"]*" data-critical="[^"]*"').Value)"

Write-TestHeader "Outbound Port Classification"
$script:Config = Get-DefaultConfig
Assert-True (-not (Test-IsUncommonRemotePort 443) -and -not (Test-IsUncommonRemotePort 80) -and -not (Test-IsUncommonRemotePort 53)) "Outbound 443/80/53 are not uncommon ports"
Assert-True (Test-IsUncommonRemotePort 23) "Outbound port 23 is an uncommon port"
$script:Config = @{}

Write-TestHeader "Event Log Clear Parsing"
$xml104 = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>104</EventID></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>alice</SubjectUserName><SubjectDomainName>CONTOSO</SubjectDomainName><Channel>System</Channel><BackupPath></BackupPath></LogFileCleared></UserData></Event>'
$info104 = ConvertFrom-LogClearedXml $xml104
Assert-True ($info104.Channel -eq "System" -and $info104.Account -eq "CONTOSO\alice") "Event 104 channel and account are read by name" "Channel=$($info104.Channel) Account=$($info104.Account)"
$clearSources = @(Get-ChildItem "$repoRoot\modules" -Filter "Check-*.ps1" | Select-String -Pattern "Id\s*=\s*1102" | Select-Object -ExpandProperty Path -Unique)
Assert-True ($clearSources.Count -eq 1) "Event log clears (1102) are detected by exactly one module" "$($clearSources.Count) modules"

Write-TestHeader "Root CA Trust List"
Assert-True ((Get-CertDisplayName 'CN="Electronic Arts, Inc.", OU=EA, O="Electronic Arts, Inc."') -eq 'Electronic Arts, Inc.') "Root CA display name has no surrounding quotes"
$trustedRoots = Get-TrustedRootThumbprints
$selfSigned = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=AmIHacked Test Root", [System.Security.Cryptography.RSA]::Create(2048), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1).CreateSelfSigned([DateTimeOffset]::Now, [DateTimeOffset]::Now.AddDays(1))
Assert-True (-not $trustedRoots.Thumbprints.ContainsKey($selfSigned.Thumbprint)) "A new self-signed root is not on the trusted root list"
if ($trustedRoots.FromCtl) {
    # Microsoft Root Certificate Authority 2011, present in every Windows 10/11 Root store
    Assert-True ($trustedRoots.Thumbprints.ContainsKey("8F43288AD272F3103B6FB1428485EA3014C0BCFE")) "Windows default root is on the trusted root list (authroot CTL)"
}

Write-TestHeader "Hosts File Security Entries"
$adBlock = @("0.0.0.0 googleads.g.doubleclick.net", "0.0.0.0 google-analytics.com", "0.0.0.0 avgthing.example.com", "0.0.0.0 example.com # virustotal", "0.0.0.0 vortex.data.microsoft.com")
Assert-True (@(Get-HostsSecurityEntry -Lines $adBlock).Count -eq 0) "Ad-block and telemetry hosts lines are not security entries"
$secHosts = @("0.0.0.0 www.virustotal.com", "1.2.3.4 update.microsoft.com", "127.0.0.1 example.com download.windowsupdate.com")
Assert-True (@(Get-HostsSecurityEntry -Lines ($secHosts + $adBlock)).Count -eq 3) "Security/update hosts lines are detected"

Write-TestHeader "Severity Escalation"
Assert-True ((Get-MaxSeverity "CRITICAL" "WARNING") -eq "CRITICAL" -and (Get-MaxSeverity "INFO" "WARNING") -eq "WARNING" -and (Get-MaxSeverity "WARNING" "CRITICAL") -eq "CRITICAL") "Get-MaxSeverity only ever raises severity"

Write-TestHeader "Defender Exclusion Placeholder"
$filtered = @(Select-MpExclusion @("N/A: Must be an administrator to view exclusions", "C:\Tools"))
Assert-True ($filtered.Count -eq 1 -and $filtered[0] -eq "C:\Tools") "Non-admin 'N/A:' placeholder is dropped, real exclusions kept"

Write-TestHeader "WMI Default Binding Allowlist"
Assert-True (Test-IsDefaultWmiBinding '__EventFilter.Name="SCM Event Log Filter"' 'NTEventLogEventConsumer.Name="SCM Event Log Consumer"') "Default SCM Event Log binding is allowlisted"
Assert-True (-not (Test-IsDefaultWmiBinding '__EventFilter.Name="Updater"' 'CommandLineEventConsumer.Name="Updater"')) "Non-default WMI binding is not allowlisted"
$cimRef = [PSCustomObject]@{ Name = "SCM Event Log Filter"; CimClass = [PSCustomObject]@{ CimClassName = "__EventFilter" } }
Assert-True ((ConvertTo-WmiRefString $cimRef) -eq '__EventFilter.Name="SCM Event Log Filter"') "CIM binding reference formats as Class.Name=""X"""
$liveBindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
$liveDefault = @($liveBindings | Where-Object { $_.Consumer.Name -eq "SCM Event Log Consumer" })
if ($liveDefault.Count -gt 0) {
    Assert-True (Test-IsDefaultWmiBinding (ConvertTo-WmiRefString $liveDefault[0].Filter) (ConvertTo-WmiRefString $liveDefault[0].Consumer)) "Live default SCM binding (via Get-CimInstance) is allowlisted"
}

Write-TestHeader "Degraded Signature Checks"
# Simulate Get-AuthenticodeSignature being unavailable: every signature comes back as CheckFailed.
. "$repoRoot\modules\Check-Processes.ps1"
$script:Config = Get-DefaultConfig
$script:Config.ProcessWhitelist = @()
$script:Findings = [System.Collections.ArrayList]::new()
$script:SuppressedCount = 0
function Get-FileSignature { param([string]$FilePath) [PSCustomObject]@{ Status = "CheckFailed"; StatusMessage = "mock" } }
Invoke-ProcessesChecks *> $null
$sigFindings = @($script:Findings | Where-Object { $_.Title -match '^(Unsigned/Invalid Process|UNSIGNED Process in Temp):' })
Assert-True ($sigFindings.Count -eq 0) "No process finding is raised only because the signature check failed" "$($sigFindings.Count) findings, e.g. $(($sigFindings | Select-Object -First 2 -ExpandProperty Title) -join '; ')"
Remove-Item Function:\Get-FileSignature
. "$repoRoot\lib\Helpers.ps1"

Write-TestHeader "Defender With Third-Party Antivirus"
Assert-True ((Test-AVProductEnabled 0x061000) -and -not (Test-AVProductEnabled 0x060000)) "Security Center productState decoding (0x061000 on, 0x060000 off)"
. "$repoRoot\modules\Check-DefenseEvasion.ps1"
function Get-MpComputerStatus { [PSCustomObject]@{ AMRunningMode = "Passive Mode"; RealTimeProtectionEnabled = $false; AntivirusEnabled = $false; AntispywareEnabled = $false; AntivirusSignatureAge = 0 } }
$script:Config = Get-DefaultConfig
foreach ($mockAV in @(@("Contoso AV"), @())) {
    $script:MockAV = $mockAV
    function Get-ActiveThirdPartyAV { $script:MockAV }
    $script:Findings = [System.Collections.ArrayList]::new()
    Invoke-DefenseEvasionChecks *> $null
    $defCrit = @($script:Findings | Where-Object { $_.Title -in @("Defender Real-Time Protection Disabled", "Antivirus Engine Disabled") })
    if ($mockAV.Count -gt 0) {
        $passive = @($script:Findings | Where-Object { $_.Title -like "*Contoso AV*" -and $_.Severity -eq "INFO" })
        Assert-True ($defCrit.Count -eq 0 -and $passive.Count -eq 1) "Third-party AV active: no Defender CRITICAL, one INFO naming the product" "$($defCrit.Count) critical, $($passive.Count) info"
    } else {
        Assert-True ($defCrit.Count -eq 2) "No other AV active: Defender-disabled CRITICALs still raised" "$($defCrit.Count) critical"
    }
}
Remove-Item Function:\Get-MpComputerStatus, Function:\Get-ActiveThirdPartyAV
. "$repoRoot\lib\Helpers.ps1"

Write-TestHeader "Accounts Without PasswordLastSet"
. "$repoRoot\modules\Check-Accounts.ps1"
function Get-LocalUser {
    [PSCustomObject]@{ Name = "aaa-test"; Enabled = $true; Description = ""; PasswordLastSet = $null; PasswordRequired = $false; PasswordExpires = $null; LastLogon = $null; UserMayChangePassword = $true }
    [PSCustomObject]@{ Name = "zzz-hidden$"; Enabled = $true; Description = ""; PasswordLastSet = (Get-Date).AddDays(-30); PasswordRequired = $true; PasswordExpires = (Get-Date).AddDays(30); LastLogon = $null; UserMayChangePassword = $true }
}
function Get-WinEvent { }
function Get-LocalGroupMember { }
$script:Findings = [System.Collections.ArrayList]::new()
Invoke-AccountsChecks *> $null
Assert-True (@($script:Findings | Where-Object { $_.Title -eq 'Hidden Account Detected: zzz-hidden$' }).Count -eq 1) "Account without PasswordLastSet does not stop enumeration (later hidden account reported)"
Assert-True (@($script:Findings | Where-Object { $_.Title -eq 'No Password Set Date: aaa-test' }).Count -eq 1) "Enabled account without PasswordLastSet gets its own finding"

Write-TestHeader "RDP Logon Query"
# Mock Get-WinEvent: return RDP events only when the query itself filters LogonType 10.
function Get-WinEvent {
    param([string]$LogName, [string]$FilterXPath, [hashtable]$FilterHashtable, [int]$MaxEvents)
    if ($LogName -ne 'Security' -or $FilterXPath -notmatch "LogonType'\]='10'") { return }
    foreach ($i in 1..3) {
        $evt = [PSCustomObject]@{ TimeCreated = (Get-Date).AddDays(-$i) }
        $evt | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event><EventData><Data Name="TargetUserName">bob</Data><Data Name="IpAddress">203.0.113.5</Data><Data Name="WorkstationName">X</Data><Data Name="LogonType">10</Data></EventData></Event>' }
        $evt
    }
}
$script:Findings = [System.Collections.ArrayList]::new()
Invoke-AccountsChecks *> $null
Assert-True (@($script:Findings | Where-Object { $_.Title -eq "RDP Logins Detected: 3 sessions" }).Count -eq 1) "RDP logons are filtered by LogonType in the event log query"
Remove-Item Function:\Get-LocalUser, Function:\Get-WinEvent, Function:\Get-LocalGroupMember

Write-TestHeader "Baseline Tasks and Exclusions"
$mockBaseline = Join-Path $testTempDir "mock_baseline.json"
@{
    Timestamp = (Get-Date).ToString("o"); ListeningPorts = @(); Services = @(); LocalAccounts = @(); RunKeys = @()
    ScheduledTasks = @(@{ Name = "MockTask"; Path = "\"; Actions = @(@{ Execute = "a.exe"; Arguments = "" }) })
    DefenderExclusions = @{ Paths = @("C:\Known"); Processes = @(); Extensions = @() }
} | ConvertTo-Json -Depth 5 | Set-Content $mockBaseline -Encoding UTF8
function Get-ScheduledTask {
    [PSCustomObject]@{ TaskName = "MockTask"; TaskPath = "\"; State = "Ready"; Actions = @([PSCustomObject]@{ Execute = "b.exe"; Arguments = "" }) }
    [PSCustomObject]@{ TaskName = "NewTask"; TaskPath = "\"; State = "Ready"; Actions = @([PSCustomObject]@{ Execute = "c.exe"; Arguments = "-x" }) }
}
function Get-MpPreference { [PSCustomObject]@{ ExclusionPath = @("C:\Known", "C:\Evil"); ExclusionProcess = $null; ExclusionExtension = $null } }
$script:Findings = [System.Collections.ArrayList]::new()
Compare-Baseline -BaselinePath $mockBaseline *> $null
Assert-True (@($script:Findings | Where-Object { $_.Title -eq "New Scheduled Task: \NewTask" }).Count -eq 1) "Task registered after the baseline is reported"
Assert-True (@($script:Findings | Where-Object { $_.Title -eq "Scheduled Task Action Changed: \MockTask" }).Count -eq 1) "Changed task action is reported"
Assert-True (@($script:Findings | Where-Object { $_.Title -eq "New Defender Exclusion (Path): C:\Evil" }).Count -eq 1 -and
             @($script:Findings | Where-Object { $_.Title -like "New Defender Exclusion*Known" }).Count -eq 0) "New Defender exclusion is reported, baseline one is not"
$legacyBaseline = Join-Path $testTempDir "legacy_baseline.json"
@{ Timestamp = (Get-Date).ToString("o"); ListeningPorts = @(); Services = @(); LocalAccounts = @(); RunKeys = @() } | ConvertTo-Json | Set-Content $legacyBaseline -Encoding UTF8
$script:Findings = [System.Collections.ArrayList]::new()
$legacyOut = Compare-Baseline -BaselinePath $legacyBaseline *>&1 | Out-String
Assert-True ($legacyOut -notmatch "Could not compare baseline" -and @($script:Findings | Where-Object { $_.Title -like "New Scheduled Task*" }).Count -eq 0) "Baseline without task/exclusion keys still loads"
Remove-Item Function:\Get-ScheduledTask, Function:\Get-MpPreference
$script:Config = @{}
$script:Findings = $null

# 1. Double-extension file in temp
Write-TestHeader "Double Extension File"
$doubleExtFile = Join-Path $testTempDir "invoice.pdf.exe"
"This is not a real executable" | Set-Content $doubleExtFile
Write-Host "  [SETUP] Created: $doubleExtFile"

# 2. Stealer-pattern filename
Write-TestHeader "Stealer Output Pattern"
$stealerFile = Join-Path $env:TEMP "passwords.txt"
"mock stealer output for testing" | Set-Content $stealerFile
$script:CleanupActions.Add({ Remove-Item $stealerFile -Force -ErrorAction SilentlyContinue }) | Out-Null
Write-Host "  [SETUP] Created: $stealerFile"

# 3. Suspicious autorun entry (in a safe test-only location)
Write-TestHeader "Suspicious Autorun Entry"
$testRunKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$testRunKeyName = "AmIHackedTestEntry_$(Get-Random)"
$testRunKeyValue = "powershell.exe -enc VGVzdA== -WindowStyle Hidden"
try {
    Set-ItemProperty -Path $testRunKeyPath -Name $testRunKeyName -Value $testRunKeyValue -ErrorAction Stop
    $script:CleanupActions.Add({ Remove-ItemProperty -Path $testRunKeyPath -Name $testRunKeyName -ErrorAction SilentlyContinue }) | Out-Null
    Write-Host "  [SETUP] Created Run key: $testRunKeyName"
} catch {
    Write-Host "  [SKIP] Could not create Run key: $_" -ForegroundColor Yellow
}

# 4. Autorun matching both a CRITICAL rule (Temp path) and a WARNING rule (wscript)
$testRunKeyName2 = "AmIHackedTestMixed_$(Get-Random)"
try {
    Set-ItemProperty -Path $testRunKeyPath -Name $testRunKeyName2 -Value 'wscript.exe C:\Users\Public\AppData\Local\Temp\a.vbs' -ErrorAction Stop
    $script:CleanupActions.Add({ Remove-ItemProperty -Path $testRunKeyPath -Name $testRunKeyName2 -ErrorAction SilentlyContinue }) | Out-Null
    Write-Host "  [SETUP] Created Run key: $testRunKeyName2"
} catch {
    Write-Host "  [SKIP] Could not create Run key: $_" -ForegroundColor Yellow
}

# ── Run the scan ─────────────────────────────────────────────────────────────

Write-Host "`n  Running AmIHacked.ps1 -ExportJson -Offline -CreateBaseline..." -ForegroundColor White

$outputDir = Join-Path $testTempDir "reports"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

try {
    & "$repoRoot\AmIHacked.ps1" -OutputPath $outputDir -ExportJson -Offline -CreateBaseline -SkipModules @() 2>&1 | Out-Null
} catch {
    Write-Host "  [ERROR] Scan failed: $_" -ForegroundColor Red
}

# ── Validate JSON output ────────────────────────────────────────────────────

$jsonFiles = Get-ChildItem $outputDir -Filter "*.json" -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "baseline_latest.json" }
if (-not $jsonFiles) {
    Write-Host "`n  [FATAL] No JSON output found. Cannot validate." -ForegroundColor Red
    $script:TestsFailed++
} else {
    $jsonFile = $jsonFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Host "`n  Validating: $($jsonFile.FullName)" -ForegroundColor White

    $results = Get-Content $jsonFile.FullName -Raw | ConvertFrom-Json
    $findings = $results.Findings

    Write-Host "  Total findings: $($findings.Count)" -ForegroundColor DarkGray

    # Validate expected detections
    Assert-FindingExists -Findings $findings -TitlePattern "Suspicious Autorun:.*$testRunKeyName" -TestName "Detected suspicious autorun with encoded PS"

    $mixedAutorun = @($findings | Where-Object { $_.Title -eq "Suspicious Autorun: $testRunKeyName2" })
    Assert-True ($mixedAutorun.Count -eq 1 -and $mixedAutorun[0].Severity -eq "CRITICAL") "Autorun matching CRITICAL and WARNING rules stays CRITICAL" "got: $(($mixedAutorun | Select-Object -ExpandProperty Severity) -join ',')"

    Assert-FindingExists -Findings $findings -TitlePattern "Stealer Output File.*passwords" -TestName "Detected stealer output file pattern"

    Assert-FindingExists -Findings $findings -TitlePattern "Double Extension.*\.exe" -TestName "Detected double-extension file (invoice.pdf.exe)"

    $placeholderFindings = @($findings | Where-Object { $_.Title -match '^Defender Exclusion \(\w+\): N/A:' })
    Assert-True ($placeholderFindings.Count -eq 0) "No Defender Exclusion finding from the non-admin placeholder" "$($placeholderFindings.Count) found"

    # Category coverage: each active module should produce at least one finding
    Write-TestHeader "Module Coverage"
    Assert-FindingCount -Findings $findings -Category "FileSystem"     -MinCount 1 -TestName "FileSystem module produced findings"
    Assert-FindingCount -Findings $findings -Category "General"        -MinCount 1 -TestName "General module produced findings"
    Assert-FindingCount -Findings $findings -Category "Network"        -MinCount 1 -TestName "Network module produced findings"
    Assert-FindingCount -Findings $findings -Category "DefenseEvasion" -MinCount 1 -TestName "DefenseEvasion module produced findings"

    # Severity field is always one of the three valid values
    Write-TestHeader "Severity Field Validity"
    $invalidSeverity = $findings | Where-Object { $_.Severity -notin @("CRITICAL","WARNING","INFO") }
    if ($invalidSeverity.Count -eq 0) {
        Write-Host "  [PASS] All $($findings.Count) findings have valid Severity" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] $($invalidSeverity.Count) findings have invalid Severity: $(($invalidSeverity | Select-Object -ExpandProperty Severity) -join ', ')" -ForegroundColor Red
        $script:TestsFailed++
    }

    # Every finding has non-empty Remediation
    Write-TestHeader "Remediation Field Coverage"
    $noRemediation = $findings | Where-Object { -not $_.Remediation }
    if ($noRemediation.Count -eq 0) {
        Write-Host "  [PASS] All findings have Remediation text" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] $($noRemediation.Count) findings missing Remediation: $(($noRemediation | Select-Object -First 3 -ExpandProperty Title) -join '; ')" -ForegroundColor Red
        $script:TestsFailed++
    }

    # Every finding has at least one MITRE tag
    Write-TestHeader "MITRE Tag Coverage"
    $noMitre = $findings | Where-Object { -not $_.MITRE -or $_.MITRE.Count -eq 0 }
    if ($noMitre.Count -eq 0) {
        Write-Host "  [PASS] All findings have MITRE ATT&CK tags" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] $($noMitre.Count) findings missing MITRE tags: $(($noMitre | Select-Object -First 3 -ExpandProperty Title) -join '; ')" -ForegroundColor Red
        $script:TestsFailed++
    }

    # Check that JSON structure is valid
    Write-TestHeader "JSON Structure Validation"
    if ($results.Version -and $results.SystemInfo -and $results.Findings -and $results.Duration) {
        Write-Host "  [PASS] JSON structure contains all required fields" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] JSON structure missing required fields" -ForegroundColor Red
        $script:TestsFailed++
    }

    # Check baseline was exported (only when -CreateBaseline used)
    Write-TestHeader "Baseline Export"
    $baselineFile = Join-Path $outputDir "baseline_latest.json"
    if (Test-Path $baselineFile) {
        $baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json
        $baselineExcl = @($baseline.DefenderExclusions.Paths) + @($baseline.DefenderExclusions.Processes) + @($baseline.DefenderExclusions.Extensions)
        Assert-True (@($baselineExcl | Where-Object { "$_" -match '^N/A:' }).Count -eq 0) "Baseline does not store the Defender 'N/A:' placeholder"
        if ($baseline.Timestamp -and $baseline.Services -and $baseline.ListeningPorts) {
            Write-Host "  [PASS] Baseline exported with valid structure" -ForegroundColor Green
            $script:TestsPassed++
        } else {
            Write-Host "  [FAIL] Baseline missing expected fields" -ForegroundColor Red
            $script:TestsFailed++
        }
    } else {
        Write-Host "  [FAIL] No baseline file found" -ForegroundColor Red
        $script:TestsFailed++
    }

    # Check HTML was generated
    Write-TestHeader "HTML Report Generation"
    $htmlFiles = Get-ChildItem $outputDir -Filter "*.html" -ErrorAction SilentlyContinue
    if ($htmlFiles) {
        $htmlContent = Get-Content $htmlFiles[0].FullName -Raw
        $hasTitle = $htmlContent -match "AM I HACKED"
        $hasVerdict = $htmlContent -match "verdict-banner"
        $hasTerminalMode = $htmlContent -match "terminal-mode"
        $hasCopyCmd = $htmlContent -match "copyCmd"
        $hasMitreBadge = $htmlContent -match "mitre-badge"
        if ($hasTitle -and $hasVerdict -and $hasTerminalMode -and $hasCopyCmd -and $hasMitreBadge) {
            Write-Host "  [PASS] HTML report has title, verdict, Terminal Mode toggle, copy-cmd, and MITRE badges" -ForegroundColor Green
            $script:TestsPassed++
        } else {
            Write-Host "  [FAIL] HTML report missing expected elements" -ForegroundColor Red
            $script:TestsFailed++
        }

        # Report counts must match the JSON findings
        Write-TestHeader "HTML Report Counts"
        $jsonCrit = @($findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $jsonWarn = @($findings | Where-Object { $_.Severity -eq "WARNING" }).Count
        $expectedVerdict = if ($jsonCrit -gt 0) { "COMPROMISED" } elseif ($jsonWarn -gt 3) { "SUSPICIOUS" } elseif ($jsonWarn -gt 0) { "CAUTION" } else { "CLEAN" }
        if ($htmlContent -match 'data-verdict="(\w+)" data-critical="(\d+)" data-warning="(\d+)"' -and
            $Matches[1] -eq $expectedVerdict -and [int]$Matches[2] -eq $jsonCrit -and [int]$Matches[3] -eq $jsonWarn) {
            Write-Host "  [PASS] HTML verdict $expectedVerdict and counts match JSON ($jsonCrit critical, $jsonWarn warning)" -ForegroundColor Green
            $script:TestsPassed++
        } else {
            Write-Host "  [FAIL] HTML verdict/counts do not match JSON (expected $expectedVerdict, $jsonCrit critical, $jsonWarn warning)" -ForegroundColor Red
            $script:TestsFailed++
        }
    } else {
        Write-Host "  [FAIL] No HTML report generated" -ForegroundColor Red
        $script:TestsFailed++
    }

    # Verify baseline is NOT auto-exported without -CreateBaseline
    Write-TestHeader "No Auto-Baseline"
    $secondOutputDir = Join-Path $testTempDir "reports2"
    New-Item -ItemType Directory -Path $secondOutputDir -Force | Out-Null
    try {
        & "$repoRoot\AmIHacked.ps1" -OutputPath $secondOutputDir -Offline -SkipModules @() 2>&1 | Out-Null
    } catch {}
    $autoBaseline = Join-Path $secondOutputDir "baseline_latest.json"
    if (-not (Test-Path $autoBaseline)) {
        Write-Host "  [PASS] Baseline NOT auto-exported without -CreateBaseline" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] Baseline was auto-exported without -CreateBaseline" -ForegroundColor Red
        $script:TestsFailed++
    }

    # Validate -CIMode output
    Write-TestHeader "CIMode JSON Summary"
    $ciOutputDir = Join-Path $testTempDir "reports_ci"
    New-Item -ItemType Directory -Path $ciOutputDir -Force | Out-Null
    $ciOutput = $null
    $ciExit = 0
    try {
        # *>&1 captures Write-Host (information stream) as well as errors
        $ciOutput = & "$repoRoot\AmIHacked.ps1" -OutputPath $ciOutputDir -Offline -CIMode -ExportJson *>&1
        $ciExit = $LASTEXITCODE
    } catch {
        $ciExit = $LASTEXITCODE
    }
    $ciOutputStr = $ciOutput -join "`n"

    Write-TestHeader "CIMode Redaction"
    $identityValues = @($env:USERNAME, $env:COMPUTERNAME, $env:USERDOMAIN) | Where-Object { $_ } | Select-Object -Unique
    $leaks = @($ciOutput | ForEach-Object { "$_" } | Where-Object { $line = $_; @($identityValues | Where-Object { $line -match [regex]::Escape($_) }).Count -gt 0 })
    Assert-True ($leaks.Count -eq 0) "CIMode output contains no username, computer name or domain" "$($leaks.Count) lines, e.g. $(($leaks | Select-Object -First 2) -join ' | ' -replace [regex]::Escape($env:USERNAME), '<user>')"
    if ($ciOutputStr -match "---AMIHACKED-SUMMARY-JSON---") {
        $jsonLine = ($ciOutputStr -split "---AMIHACKED-SUMMARY-JSON---")[-1].Trim()
        try {
            $ciSummary = $jsonLine | ConvertFrom-Json
            if ($ciSummary.verdict -and $null -ne $ciSummary.critical -and $null -ne $ciSummary.warning -and
                $null -ne $ciSummary.info -and $null -ne $ciSummary.suppressed -and
                $null -ne $ciSummary.total -and $ciSummary.reportPath) {
                Write-Host "  [PASS] CIMode JSON summary contains all required fields" -ForegroundColor Green
                $script:TestsPassed++
            } else {
                Write-Host "  [FAIL] CIMode JSON summary missing fields" -ForegroundColor Red
                $script:TestsFailed++
            }
        } catch {
            Write-Host "  [FAIL] CIMode JSON summary failed to parse: $_" -ForegroundColor Red
            $script:TestsFailed++
        }
    } else {
        Write-Host "  [FAIL] CIMode output missing ---AMIHACKED-SUMMARY-JSON--- delimiter" -ForegroundColor Red
        $script:TestsFailed++
    }

    Write-TestHeader "CIMode Exit Code"
    if ($ciExit -ge 0 -and $ciExit -le 2) {
        Write-Host "  [PASS] CIMode exit code is $ciExit (0=clean, 1=warning, 2=critical)" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] CIMode exit code is $ciExit (expected 0, 1, or 2)" -ForegroundColor Red
        $script:TestsFailed++
    }
}

# ── Cleanup ──────────────────────────────────────────────────────────────────

if (-not $KeepArtifacts) {
    Write-Host "`n  Cleaning up test artifacts..." -ForegroundColor DarkGray
    foreach ($action in $script:CleanupActions) {
        try { & $action } catch {}
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────

$total = $script:TestsPassed + $script:TestsFailed
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor $(if ($script:TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "  ║   TEST RESULTS: $($script:TestsPassed)/$total passed$(if ($script:TestsFailed -gt 0) { ", $($script:TestsFailed) FAILED" })              ║" -ForegroundColor $(if ($script:TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor $(if ($script:TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host ""

exit $script:TestsFailed
