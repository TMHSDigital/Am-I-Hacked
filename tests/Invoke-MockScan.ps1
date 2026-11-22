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
    $count = @($Findings | Where-Object { $_.Category -eq $Category }).Count
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

try {
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
    $externalLoads = [regex]::Matches($unitHtml, '(@import|src=|<link)[^>]*https?://') | ForEach-Object { $_.Value }
    Assert-True (@($externalLoads).Count -eq 0 -and $unitHtml -match "Content-Security-Policy") "Report loads no external resources and sets a CSP" (@($externalLoads) -join ", ")

    Write-TestHeader "IP Helpers"
    Assert-True ((Test-IPInCIDR "8.8.8.8" "0.0.0.0/0") -and (Test-IPInCIDR "20.1.2.3" "20.0.0.0/8") -and -not (Test-IPInCIDR "21.1.2.3" "20.0.0.0/8")) "Test-IPInCIDR handles /0 and /8"
    Assert-True ((Test-IPInCIDR "1.2.3.4" "1.2.3.4/32") -and -not (Test-IPInCIDR "1.2.3.5" "1.2.3.4/32")) "Test-IPInCIDR handles /32"
    Assert-True ((Test-IPInCIDR "172.20.1.1" "172.16.0.0/12") -and (Test-IPInCIDR "172.31.255.255" "172.16.0.0/12") -and -not (Test-IPInCIDR "172.32.0.1" "172.16.0.0/12") -and -not (Test-IPInCIDR "172.15.255.255" "172.16.0.0/12")) "Test-IPInCIDR handles /12"
    Assert-True ((Test-IPInCIDR "10.1.15.9" "10.1.0.0/20") -and -not (Test-IPInCIDR "10.1.16.0" "10.1.0.0/20")) "Test-IPInCIDR handles /20"
    Assert-True ((Test-IPInCIDR "10.0.0.3" "10.0.0.0/30") -and -not (Test-IPInCIDR "10.0.0.4" "10.0.0.0/30") -and (Test-IPInCIDR "10.0.0.1" "10.0.0.0/31") -and -not (Test-IPInCIDR "10.0.0.2" "10.0.0.0/31")) "Test-IPInCIDR handles /30 and /31"
    Assert-True ((Test-IPInCIDR "2001:db8:abcd::1" "2001:db8:a000::/36") -and -not (Test-IPInCIDR "2001:db8:b000::1" "2001:db8:a000::/36")) "Test-IPInCIDR handles a non-byte-aligned IPv6 prefix"
    Assert-True (-not (Test-IPInCIDR "::ffff:20.1.2.3" "20.0.0.0/8") -and -not (Test-IPInCIDR "20.1.2.3" "2001:db8::/32")) "Test-IPInCIDR does not match across IPv4/IPv6"
    Assert-True ((Test-IsPrivateIP "10.1.2.3") -and (Test-IsPrivateIP "172.16.0.1") -and (Test-IsPrivateIP "192.168.1.1") -and (Test-IsPrivateIP "127.0.0.1") -and (Test-IsPrivateIP "::1") -and (Test-IsPrivateIP "fe80::1")) "Test-IsPrivateIP recognises RFC 1918, loopback and link-local IPv6"
    Assert-True ((Test-IsPrivateIP "169.254.1.1") -and (Test-IsPrivateIP "100.64.0.1") -and (Test-IsPrivateIP "100.127.255.254") -and (Test-IsPrivateIP "fd00::1") -and (Test-IsPrivateIP "FC12:3456::1") -and (Test-IsPrivateIP "::ffff:192.168.1.1") -and (Test-IsPrivateIP "fe80::1%12")) "Test-IsPrivateIP recognises APIPA, CGNAT, IPv6 ULA, mapped and scoped addresses"
    Assert-True (-not (Test-IsPrivateIP "172.32.0.1") -and -not (Test-IsPrivateIP "8.8.8.8") -and -not (Test-IsPrivateIP "100.128.0.1") -and -not (Test-IsPrivateIP "100.63.255.255") -and -not (Test-IsPrivateIP "2001:4860::8888") -and -not (Test-IsPrivateIP "not-an-ip")) "Test-IsPrivateIP rejects public addresses"

    Write-TestHeader "Redaction"
    $script:RedactMode = $true
    $script:RedactMap = [ordered]@{ "C:\Users\Jane.Doe" = "C:\Users\REDACTED-USER"; "jdoe" = "REDACTED-USER"; "WS-01" = "REDACTED-PC" }
    Assert-True ((Invoke-Redact "Path C:\Users\Jane.Doe\x on ws-01 by JDOE") -eq "Path C:\Users\REDACTED-USER\x on REDACTED-PC by REDACTED-USER") "Invoke-Redact replaces profile path, host and user case-insensitively"
    $redObj = Invoke-RedactObject @{ A = "jdoe"; B = @("WS-01", "x"); C = [PSCustomObject]@{ D = "C:\Users\Jane.Doe" } }
    Assert-True ($redObj.A -eq "REDACTED-USER" -and $redObj.B[0] -eq "REDACTED-PC" -and $redObj.B[1] -eq "x" -and $redObj.C.D -eq "C:\Users\REDACTED-USER") "Invoke-RedactObject redacts nested hashtables, arrays and objects"
    $when = Get-Date "2026-01-02 03:04:05"
    $redVals = Invoke-RedactObject @{ Ports = @(80, 443); Mixed = @(7, $true, $when, "jdoe"); Pid = 1234; Obj = [PSCustomObject]@{ N = 5; Users = @("jdoe", 3) } }
    $typesOk = ($redVals.Ports[0] -is [int] -and $redVals.Ports[0] -eq 80 -and $redVals.Ports[1] -eq 443 -and
                $redVals.Mixed[0] -eq 7 -and $redVals.Mixed[1] -is [bool] -and $redVals.Mixed[1] -and
                $redVals.Mixed[2] -is [datetime] -and $redVals.Mixed[2] -eq $when -and $redVals.Mixed[3] -eq "REDACTED-USER" -and
                $redVals.Pid -eq 1234 -and $redVals.Obj.N -eq 5 -and $redVals.Obj.Users[0] -eq "REDACTED-USER" -and $redVals.Obj.Users[1] -eq 3)
    Assert-True $typesOk "Invoke-RedactObject keeps numbers, booleans and dates (in arrays and objects) unchanged" ($redVals | ConvertTo-Json -Depth 4 -Compress)
    $redShape = Invoke-RedactObject @{ One = @("jdoe"); Port = @(445); Empty = @(); Nested = @(@(1, 2), 3); Obj = [PSCustomObject]@{ L = @("x") } }
    $shapeOk = ($redShape.One -is [array] -and $redShape.One.Count -eq 1 -and $redShape.One[0] -eq "REDACTED-USER" -and
                $redShape.Port -is [array] -and $redShape.Port[0] -eq 445 -and $redShape.Empty -is [array] -and $redShape.Empty.Count -eq 0 -and
                $redShape.Nested.Count -eq 2 -and $redShape.Nested[0] -is [array] -and $redShape.Nested[0].Count -eq 2 -and
                $redShape.Obj.L -is [array] -and $redShape.Obj.L.Count -eq 1)
    Assert-True $shapeOk "Invoke-RedactObject keeps one-element, empty and nested arrays as arrays" ($redShape | ConvertTo-Json -Depth 4 -Compress)
    $script:RedactMode = $false
    $script:RedactMap = @{}

    Write-TestHeader "Config Defaults"
    function ConvertTo-NormalizedValue {
        param($Value)
        if ($null -eq $Value) { return "" }
        if ($Value -is [string] -or $Value -is [ValueType]) { return "$Value" }
        if ($Value -is [System.Collections.IDictionary]) {
            return "{" + (($Value.Keys | Sort-Object | ForEach-Object { "$_=$(ConvertTo-NormalizedValue $Value[$_])" }) -join ";") + "}"
        }
        if ($Value -is [System.Collections.IEnumerable]) {
            return "[" + ((@($Value) | ForEach-Object { ConvertTo-NormalizedValue $_ }) -join "|") + "]"
        }
        return "{" + (($Value.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$(ConvertTo-NormalizedValue $_.Value)" }) -join ";") + "}"
    }
    $defaultCfg = Get-DefaultConfig
    $exampleCfg = Get-Content "$repoRoot\config\config.example.json" -Raw | ConvertFrom-Json
    $defaultKeys = @($defaultCfg.PSObject.Properties.Name | Sort-Object)
    $exampleKeys = @($exampleCfg.PSObject.Properties.Name | Sort-Object)
    $keyDiff = @(Compare-Object $defaultKeys $exampleKeys | ForEach-Object { "$($_.InputObject)$($_.SideIndicator)" })
    Assert-True ($keyDiff.Count -eq 0) "config.example.json has the same keys as Get-DefaultConfig" ($keyDiff -join ", ")
    # Intentional differences: the example suggests common app folders (TrustedAppDirs) and shows sample
    # Suppressions; the built-in defaults skip no app folders and suppress nothing.
    $valueDiff = @($defaultKeys | Where-Object { $_ -notin @("TrustedAppDirs", "Suppressions") -and $_ -in $exampleKeys -and
        (ConvertTo-NormalizedValue $defaultCfg.$_) -ne (ConvertTo-NormalizedValue $exampleCfg.$_) })
    Assert-True ($valueDiff.Count -eq 0) "config.example.json values match Get-DefaultConfig" ($valueDiff -join ", ")
    $oldUserCfg = [PSCustomObject]@{ TrustedIPs = @("10.9.9.9"); AccountMaxAgeDays = 14 }
    $mergedCfg = Merge-Config -Defaults $defaultCfg -UserConfig $oldUserCfg
    Assert-True ($mergedCfg.AccountMaxAgeDays -eq 14 -and @($mergedCfg.TrustedIPs).Count -eq 1 -and @($mergedCfg.BackdoorPorts).Count -gt 0 -and $mergedCfg.MaxVTLookups -eq $defaultCfg.MaxVTLookups) "Older config files get defaults for keys they lack"
    $fallbackLines = @(Get-ChildItem "$repoRoot\modules" -Filter "Check-*.ps1" | Select-String -Pattern 'if \(\$script:Config\.\w+\) \{[^}]*\} else \{')
    Assert-True ($fallbackLines.Count -eq 0) "No module contains literal fallback values for config keys" (($fallbackLines | ForEach-Object { "$($_.Filename):$($_.LineNumber)" }) -join ", ")

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

    Write-TestHeader "Proxy Configuration"
    Assert-True ((Get-PacUrlSeverity "http://wpad.corp.example.com/proxy.pac") -eq "WARNING" -and (Get-PacUrlSeverity "http://wpad.corp.example.com/proxy.pac" $true) -eq "INFO") "PAC URL on a host name is WARNING (INFO when set by policy)"
    Assert-True ((Get-PacUrlSeverity "file:///C:/Users/a/AppData/x.pac") -eq "CRITICAL" -and (Get-PacUrlSeverity "http://203.0.113.9/p.pac" $true) -eq "CRITICAL") "PAC URL from a local file or raw IP is CRITICAL"
    $directBlob = [byte[]](0x18,0,0,0, 0,0,0,0, 1,0,0,0, 0,0,0,0, 0,0,0,0)
    $proxyText = [System.Text.Encoding]::ASCII.GetBytes("10.0.0.5:8080"); $bypassText = [System.Text.Encoding]::ASCII.GetBytes("<local>")
    $proxyBlob = [byte[]](@(0x18,0,0,0, 0,0,0,0, 3,0,0,0) + [BitConverter]::GetBytes([int]$proxyText.Length) + $proxyText + [BitConverter]::GetBytes([int]$bypassText.Length) + $bypassText)
    $decodedProxy = ConvertFrom-WinHttpSettings $proxyBlob
    Assert-True (-not (ConvertFrom-WinHttpSettings $directBlob).UsesProxy -and $decodedProxy.UsesProxy -and $decodedProxy.Proxy -eq "10.0.0.5:8080" -and $decodedProxy.Bypass -eq "<local>") "WinHTTP proxy settings decode (direct vs named proxy)"

    Write-TestHeader "PowerShell Profile Candidates"
    $fakeUsers = Join-Path $testTempDir "Users"
    New-Item -ItemType Directory -Path (Join-Path $fakeUsers "bob\Documents\PowerShell") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $fakeUsers "Public") -Force | Out-Null
    $candidates = @(Get-PowerShellProfileCandidates -AllUsers -UsersRoot $fakeUsers -CurrentUserDocuments (Join-Path $testTempDir "MyDocs") -CurrentUserName "me")
    $candidatePaths = @($candidates | ForEach-Object { $_.Path })
    Assert-True ($candidatePaths -contains (Join-Path $testTempDir "MyDocs\PowerShell\Microsoft.PowerShell_profile.ps1") -and
                 $candidatePaths -contains (Join-Path $testTempDir "MyDocs\WindowsPowerShell\Microsoft.PowerShell_profile.ps1") -and
                 $candidatePaths -contains (Join-Path $env:ProgramFiles "PowerShell\7\profile.ps1")) "Profile scan covers both PowerShell editions regardless of host"
    # Suffix match: TEMP can be an 8.3 short path (C:\Users\RUNNER~1\...) while Get-ChildItem returns long names
    Assert-True (@($candidatePaths | Where-Object { $_ -like "*\bob\Documents\PowerShell\profile.ps1" }).Count -gt 0 -and
                 @($candidates | Where-Object { $_.Owner -eq "bob" }).Count -gt 0 -and
                 @($candidates | Where-Object { $_.Owner -eq "Public" }).Count -eq 0) "Profile scan covers other users (as admin) and records the owner"
    $selfOnly = @(Get-PowerShellProfileCandidates -UsersRoot $fakeUsers -CurrentUserDocuments (Join-Path $testTempDir "MyDocs") -CurrentUserName "me")
    Assert-True (@($selfOnly | Where-Object { $_.Owner -eq "bob" }).Count -eq 0) "Without admin, other users' profiles are not scanned"

    Write-TestHeader "VirusTotal Lookup Limits"
    $vtFiles = foreach ($i in 1..6) { $vf = Join-Path $testTempDir "vt$i.bin"; "vt sample $i" | Set-Content $vf; Get-Item $vf }
    function Invoke-RestMethod { $script:VTCalls++; throw "mock HTTP error" }
    function Get-HttpStatusCode { param($ErrorRecord) $script:MockHttpStatus }
    $script:Findings = [System.Collections.ArrayList]::new()
    $script:VTCalls = 0; $script:MockHttpStatus = 404
    Invoke-VirusTotalLookups -Files $vtFiles -ApiKey "x" -MaxLookups 4 *> $null
    Assert-True ($script:VTCalls -eq 4 -and @($script:Findings | Where-Object { $_.Title -like "Unknown to VirusTotal*" }).Count -eq 4) "404 responses count toward MaxVTLookups" "$($script:VTCalls) requests"
    foreach ($code in @(401, 429)) {
        $script:VTCalls = 0; $script:MockHttpStatus = $code
        $vtOut = Invoke-VirusTotalLookups -Files $vtFiles -ApiKey "x" -MaxLookups 4 *>&1 | Out-String
        Assert-True ($script:VTCalls -eq 1 -and $vtOut -match "HTTP $code") "HTTP $code stops VirusTotal lookups with a visible status line" "$($script:VTCalls) requests"
    }
    Remove-Item Function:\Invoke-RestMethod, Function:\Get-HttpStatusCode
    . "$repoRoot\lib\Helpers.ps1"

    Write-TestHeader "Unquoted Service Paths"
    Assert-True ((Test-UnquotedServicePath 'C:\Program Files\Vendor\svc.exe') -and
                 -not (Test-UnquotedServicePath 'C:\Tools\svc.exe --run now') -and
                 -not (Test-UnquotedServicePath '"C:\Program Files\Vendor\svc.exe" -x') -and
                 -not (Test-UnquotedServicePath 'C:\Windows\System32\svchost.exe -k Local Service')) "Unquoted service path check only looks at the executable part"

    Write-TestHeader "Module Selection"
    $avail = @(Get-ScanModules -ModulesDir "$repoRoot\modules" | ForEach-Object { $_.Name })
    Assert-True ($avail -contains "Network" -and $avail -contains "FileSystem") "Modules are discovered from modules\Check-*.ps1"
    $sel = Resolve-ModuleSelection -Available $avail -Modules @("network") -SkipModules @()
    Assert-True ($sel.Skip -notcontains "Network" -and $sel.Skip -contains "Processes" -and $sel.Skip -notcontains "Baseline" -and $sel.Unknown.Count -eq 0) "-Modules runs only the named modules (case-insensitive), Baseline kept"
    $sel = Resolve-ModuleSelection -Available $avail -SkipModules @("Netwrok", "Baseline")
    Assert-True ($sel.Unknown -contains "Netwrok" -and $sel.Skip -contains "Baseline" -and $sel.Skip -notcontains "Network") "Unknown -SkipModules names are reported"
    $sel = Resolve-ModuleSelection -Available $avail -SkipModules @("Network, Accounts")
    Assert-True ($sel.Skip -contains "Network" -and $sel.Skip -contains "Accounts" -and $sel.Unknown.Count -eq 0) "A comma-separated single string (powershell.exe -File) is split into names"
    $listOut = & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File "$repoRoot\AmIHacked.ps1" -ListModules 2>&1 | Out-String
    Assert-True ($listOut -match "(?m)^Network\s+Network Indicators" -and $listOut -notmatch "AM I HACKED") "-ListModules prints module names and descriptions without scanning"

    Write-TestHeader "Hosts File Security Entries"
    $adBlock = @("0.0.0.0 googleads.g.doubleclick.net", "0.0.0.0 google-analytics.com", "0.0.0.0 avgthing.example.com", "0.0.0.0 example.com # virustotal", "0.0.0.0 vortex.data.microsoft.com")
    Assert-True (@(Get-HostsSecurityEntry -Lines $adBlock).Count -eq 0) "Ad-block and telemetry hosts lines are not security entries"
    $secHosts = @("0.0.0.0 www.virustotal.com", "1.2.3.4 update.microsoft.com", "127.0.0.1 example.com download.windowsupdate.com")
    Assert-True (@(Get-HostsSecurityEntry -Lines ($secHosts + $adBlock)).Count -eq 3) "Security/update hosts lines are detected"

    Write-TestHeader "Finding Rule IDs"
    # Every Add-Finding call outside the tests passes a constant -RuleId; IDs are unique and match docs/RULES.md
    $ruleCalls = [System.Collections.ArrayList]::new()
    $missingRule = [System.Collections.ArrayList]::new()
    $codeFiles = @(Get-Item "$repoRoot\AmIHacked.ps1") + @(Get-ChildItem "$repoRoot\lib", "$repoRoot\modules" -Filter "*.ps1")
    foreach ($codeFile in $codeFiles) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($codeFile.FullName, [ref]$null, [ref]$null)
        $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Add-Finding" }, $true)
        foreach ($call in $calls) {
            $els = $call.CommandElements
            $idx = -1
            for ($i = 0; $i -lt $els.Count; $i++) { if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$i].ParameterName -eq "RuleId") { $idx = $i } }
            if ($idx -ge 0 -and $idx + 1 -lt $els.Count -and $els[$idx + 1] -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $ruleCalls.Add($els[$idx + 1].Value) | Out-Null
            } else {
                $missingRule.Add("$($codeFile.Name):$($call.Extent.StartLineNumber)") | Out-Null
            }
        }
    }
    $dupRules = @($ruleCalls | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object Name)
    $badFormat = @($ruleCalls | Where-Object { $_ -cnotmatch '^AIH-[A-Z]+-[A-Z0-9-]+$' })
    Assert-True ($ruleCalls.Count -ge 90 -and $missingRule.Count -eq 0) "Every Add-Finding call has a constant -RuleId" "$($ruleCalls.Count) with IDs; missing: $($missingRule -join ', ')"
    Assert-True ($dupRules.Count -eq 0 -and $badFormat.Count -eq 0) "Rule IDs are unique and follow AIH-<AREA>-<NAME>" "duplicates: $($dupRules -join ', '); bad: $($badFormat -join ', ')"
    $docRules = @([regex]::Matches((Get-Content "$repoRoot\docs\RULES.md" -Raw), '(?m)^\| `(AIH-[A-Z0-9-]+)`') | ForEach-Object { $_.Groups[1].Value })
    $undocumented = @($ruleCalls | Where-Object { $_ -notin $docRules })
    $staleDocs = @($docRules | Where-Object { $_ -notin $ruleCalls })
    Assert-True ($undocumented.Count -eq 0 -and $staleDocs.Count -eq 0) "docs/RULES.md lists exactly the rule IDs used in the code" "undocumented: $($undocumented -join ', '); not in code: $($staleDocs -join ', ')"

    Assert-True ((Get-FallbackRuleId -Category "My Module" -Title "Odd Thing: x (3)") -eq "CUSTOM-MYMODULE-ODD-THING" -and (Get-FallbackRuleId -Category "X" -Title "!!!") -eq "CUSTOM-X-FINDING") "Findings without -RuleId get a CUSTOM-<CATEGORY>-<TITLE> ID"

    $sups = @(
        [PSCustomObject]@{ rule = "AIH-NET-UNUSUAL-LISTENER"; key = "6463|*"; reason = "a" },
        [PSCustomObject]@{ rule = "AIH-PROC-UNQUOTED-*"; reason = "b" },
        [PSCustomObject]@{ key = "anything"; reason = "key alone does nothing" },
        @{ pattern = "Autorun Entry: OneDrive*"; rule = "AIH-FS-AUTORUN" },
        [PSCustomObject]@{ rule = "AIH-FS-TEMP-FILE"; key = "C:\x\[1].exe" }
    )
    $supCases = @(
        @("Unusual Listening Port: 6463 (Discord)", "AIH-NET-UNUSUAL-LISTENER", "6463|Discord", $true),
        @("Unusual Listening Port: 6464 (Discord)", "AIH-NET-UNUSUAL-LISTENER", "6464|Discord", $false),
        @("Unquoted Service Path: Foo", "AIH-PROC-UNQUOTED-SERVICE-PATH", "Foo", $true),
        @("Something", "AIH-NET-SYSTEM-PROXY", "anything", $false),
        @("Autorun Entry: OneDriveSetup", "AIH-FS-AUTORUN", "HKCU:\Run\OneDriveSetup", $true),
        @("Autorun Entry: OneDriveSetup", "AIH-FS-AUTORUN-SUSPICIOUS", "HKCU:\Run\OneDriveSetup", $false),
        @("Suspicious File in Temp: [1].exe", "AIH-FS-TEMP-FILE", "C:\x\[1].exe", $true)
    )
    $supWrong = @($supCases | Where-Object { (Test-FindingSuppressed -Title $_[0] -RuleId $_[1] -Key $_[2] -Suppressions $sups) -ne $_[3] } | ForEach-Object { "$($_[1]) $($_[2])" })
    Assert-True ($supWrong.Count -eq 0) "Suppressions match by rule, rule + key, and title pattern + rule; key alone suppresses nothing" ($supWrong -join "; ")

    $script:Config = @{ Suppressions = @() }
    $script:Findings = [System.Collections.ArrayList]::new()
    $script:RedactMode = $true
    $script:RedactMap = [ordered]@{ "C:\Users\Jane.Doe" = "C:\Users\REDACTED-USER" }
    Add-Finding -Severity "WARNING" -Category "FileSystem" -RuleId "AIH-FS-TEMP-FILE" -Key "C:\Users\Jane.Doe\AppData\Local\Temp\a.exe" -Title "Suspicious File in Temp: a.exe" -Description "d" -Details @{ Path = "C:\Users\Jane.Doe\AppData\Local\Temp\a.exe" } -MITRE @("T1204.002") *> $null
    Add-Finding -Severity "INFO" -Category "Custom" -Title "Odd Thing: 1" -Description "d" *> $null
    $script:RedactMode = $false
    $script:RedactMap = @{}
    $f0 = $script:Findings[0]
    Assert-True ($f0.RuleId -eq "AIH-FS-TEMP-FILE" -and $f0.Key -eq "C:\Users\REDACTED-USER\AppData\Local\Temp\a.exe" -and $script:Findings[1].RuleId -eq "CUSTOM-CUSTOM-ODD-THING") "Add-Finding stores RuleId and a redacted Key"

    $sarif = ConvertTo-SarifLog -Findings @($script:Findings) -Version "9.9.9"
    $sarifRun = $sarif.runs[0]
    $sarifOk = ($sarif.version -eq "2.1.0" -and $sarifRun.tool.driver.version -eq "9.9.9" -and @($sarifRun.tool.driver.rules).Count -eq 2 -and
                @($sarifRun.results).Count -eq 2 -and $sarifRun.results[0].ruleId -eq "AIH-FS-TEMP-FILE" -and $sarifRun.results[0].level -eq "warning" -and
                $sarifRun.results[1].level -eq "note" -and
                $sarifRun.results[0].partialFingerprints["amIHacked/v1"] -eq "AIH-FS-TEMP-FILE|C:\Users\REDACTED-USER\AppData\Local\Temp\a.exe" -and
                $sarifRun.results[0].locations[0].physicalLocation.artifactLocation.uri -eq "file:///C:/Users/REDACTED-USER/AppData/Local/Temp/a.exe" -and
                -not $sarifRun.results[1].Contains("locations"))
    Assert-True $sarifOk "SARIF log has rules, levels, fingerprints and file locations" ($sarif | ConvertTo-Json -Depth 12 -Compress)
    $script:Findings = $null
    $script:Config = Get-DefaultConfig

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

    Write-TestHeader "Signature Lookup Caching"
    $script:AuthenticodeCalls = 0
    function Get-AuthenticodeSignature { param($FilePath, $ErrorAction) $script:AuthenticodeCalls++; [PSCustomObject]@{ Status = "Valid" } }
    $script:SignatureCache = @{}
    $script:SignatureCheckAvailable = $true
    $null = Get-FileSignature -FilePath "C:\Windows\explorer.exe"
    $null = Get-FileSignature -FilePath "C:\WINDOWS\explorer.exe"
    Assert-True ($script:AuthenticodeCalls -eq 1) "Each file path is verified at most once per scan" "$($script:AuthenticodeCalls) calls"
    $script:SignatureCheckAvailable = $false
    $degradedSig = Get-FileSignature -FilePath "C:\Windows\notepad.exe"
    Assert-True ($degradedSig.Status -eq "CheckFailed" -and $script:AuthenticodeCalls -eq 1) "Unavailable signature checks return CheckFailed without calling the cmdlet"
    $helpersText = Get-Content "$repoRoot\lib\Helpers.ps1" -Raw
    Assert-True ($helpersText -notmatch '(?m)^\s*Import-Module\s+Microsoft\.PowerShell\.Security') "Get-FileSignature does not re-import the Security module"
    Remove-Item Function:\Get-AuthenticodeSignature
    $script:SignatureCheckAvailable = $null
    $script:SignatureCache = @{}

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

    Write-TestHeader "FileSystem Check Isolation"
    . "$repoRoot\modules\Check-FileSystem.ps1"
    $fsChecks = @(Get-Command -CommandType Function -Name "Test-*" | Where-Object { $_.ScriptBlock.File -like "*\modules\Check-FileSystem.ps1" } | ForEach-Object Name)
    $script:FsCalls = [System.Collections.ArrayList]::new()
    foreach ($fsCheck in $fsChecks) {
        Set-Item -Path "Function:\$fsCheck" -Value ([scriptblock]::Create("`$script:FsCalls.Add('$fsCheck') | Out-Null"))
    }
    Set-Item -Path "Function:\Test-RecentSystemBinary" -Value { $script:FsCalls.Add("Test-RecentSystemBinary") | Out-Null; throw "simulated failure" }
    $script:Findings = [System.Collections.ArrayList]::new()
    Invoke-FileSystemChecks *> $null
    $fsErr = @($script:Findings | Where-Object { $_.Title -eq "FileSystem Check Error: Test-RecentSystemBinary" })
    Assert-True ($fsChecks.Count -ge 13 -and $script:FsCalls.Count -eq $fsChecks.Count -and $fsErr.Count -eq 1) "An error in one FileSystem check is reported and the remaining checks still run" "$($script:FsCalls.Count) of $($fsChecks.Count) checks ran, $($fsErr.Count) error finding(s)"
    foreach ($fsCheck in $fsChecks) { Remove-Item "Function:\$fsCheck" -ErrorAction SilentlyContinue }
    . "$repoRoot\modules\Check-FileSystem.ps1"

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

    Write-TestHeader "Admin Group By SID"
    $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    function Get-LocalGroupMember {
        [PSCustomObject]@{ Name = "MicrosoftAccount\someone@outlook.com"; SID = $mySid; ObjectClass = "User"; PrincipalSource = "MicrosoftAccount" }
        [PSCustomObject]@{ Name = "PC\Administrator"; SID = "S-1-5-21-1-2-3-500"; ObjectClass = "User"; PrincipalSource = "Local" }
        [PSCustomObject]@{ Name = "PC\intruder"; SID = "S-1-5-21-1-2-3-1009"; ObjectClass = "User"; PrincipalSource = "Local" }
    }
    $script:Findings = [System.Collections.ArrayList]::new()
    Invoke-AccountsChecks *> $null
    $unexpectedAdmins = @($script:Findings | Where-Object { $_.Title -like "Unexpected Admin:*" })
    Assert-True ($unexpectedAdmins.Count -eq 1 -and $unexpectedAdmins[0].Title -eq "Unexpected Admin: PC\intruder") "Admin check matches the current user and built-in Administrator by SID" (($unexpectedAdmins | ForEach-Object { $_.Title }) -join "; ")

    Write-TestHeader "Failed Logon Grouping"
    function Get-WinEvent {
        param([string]$LogName, [string]$FilterXPath, [hashtable]$FilterHashtable, [int]$MaxEvents)
        if ($FilterXPath -notmatch 'EventID=4625\]') { return }
        foreach ($i in 1..12) {
            $evt = [PSCustomObject]@{ TimeCreated = (Get-Date).AddMinutes(-$i) }
            $evt | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event><EventData><Data Name="TargetUserName">bob</Data><Data Name="IpAddress">-</Data><Data Name="LogonType">2</Data><Data Name="SubStatus">0xc000006a</Data></EventData></Event>' }
            $evt
        }
    }
    $script:Findings = [System.Collections.ArrayList]::new()
    Invoke-AccountsChecks *> $null
    Assert-True (@($script:Findings | Where-Object { $_.Title -like "Brute Force:*" }).Count -eq 0 -and
                 @($script:Findings | Where-Object { $_.Title -eq "Failed Logins (24h): 12 attempts" }).Count -eq 1) "Failed logons without a source IP are not reported as brute force"

    Write-TestHeader "Security Log Access Denied"
    function Get-WinEvent { throw [System.UnauthorizedAccessException]::new("Attempted to perform an unauthorized operation.") }
    $script:Findings = [System.Collections.ArrayList]::new()
    Invoke-AccountsChecks *> $null
    Assert-True (@($script:Findings | Where-Object { $_.Title -eq "Event Log Access Denied" }).Count -eq 1) "Unreadable Security log is reported instead of silently skipped"
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

    Write-TestHeader "Baseline Integrity"
    $goodHash = (Get-FileHash $legacyBaseline -Algorithm SHA256).Hash
    $script:Findings = [System.Collections.ArrayList]::new()
    Compare-Baseline -BaselinePath $legacyBaseline -ExpectedHash $goodHash.ToLower() *> $null
    Assert-True (@($script:Findings | Where-Object { $_.Title -like "Baseline Hash Mismatch*" }).Count -eq 0) "Matching -BaselineHash (any case) is accepted"
    $script:Findings = [System.Collections.ArrayList]::new()
    Compare-Baseline -BaselinePath $legacyBaseline -ExpectedHash ("0" * 64) *> $null
    Assert-True (@($script:Findings | Where-Object { $_.Title -eq "Baseline Hash Mismatch" }).Count -eq 1 -and $script:Findings.Count -eq 1) "Mismatched -BaselineHash raises a WARNING and skips the comparison"
    $staleBaseline = Join-Path $testTempDir "stale_baseline.json"
    @{ Timestamp = (Get-Date).AddDays(-3).ToString("o"); ListeningPorts = @(); Services = @(); LocalAccounts = @(); RunKeys = @() } | ConvertTo-Json | Set-Content $staleBaseline -Encoding UTF8
    $script:Findings = [System.Collections.ArrayList]::new()
    Compare-Baseline -BaselinePath $staleBaseline *> $null
    Assert-True (@($script:Findings | Where-Object { $_.Title -eq "Baseline Modified After Creation" }).Count -eq 1) "Baseline written after its embedded timestamp is reported"
    $script:Findings = [System.Collections.ArrayList]::new()
    Compare-Baseline -BaselinePath $legacyBaseline *> $null
    Assert-True (@($script:Findings | Where-Object { $_.Title -eq "Baseline Modified After Creation" }).Count -eq 0) "Fresh baseline is not reported as modified"
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
    if (-not (Test-Path $testRunKeyPath)) {
        # Fresh profiles (e.g. CI runners) may not have the Run key yet; remove it again only if we created it
        New-Item -Path $testRunKeyPath -Force | Out-Null
        $script:CleanupActions.Add({ Remove-Item -Path $testRunKeyPath -ErrorAction SilentlyContinue }) | Out-Null
    }
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
        & "$repoRoot\AmIHacked.ps1" -OutputPath $outputDir -ExportJson -ExportSarif -Offline -CreateBaseline -CIMode -SkipModules @() *>&1 | Out-Null
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

        $doubleExtFinding = @($findings | Where-Object { $_.Title -eq "Suspicious File in Temp: invoice.pdf.exe" -and $_.Description -match "Double extension" })
        Assert-True ($doubleExtFinding.Count -ge 1 -and @($doubleExtFinding | Where-Object { $_.Severity -ne "CRITICAL" }).Count -eq 0) "Detected double-extension file (invoice.pdf.exe) as CRITICAL" "$($doubleExtFinding.Count) matching findings"

        $placeholderFindings = @($findings | Where-Object { $_.Title -match '^Defender Exclusion \(\w+\): N/A:' })
        Assert-True ($placeholderFindings.Count -eq 0) "No Defender Exclusion finding from the non-admin placeholder" "$($placeholderFindings.Count) found"

        # Category coverage: each active module should produce at least one finding
        Write-TestHeader "Module Coverage"
        Assert-FindingCount -Findings $findings -Category "FileSystem"     -MinCount 1 -TestName "FileSystem module produced findings"
        Assert-FindingCount -Findings $findings -Category "Account"        -MinCount 1 -TestName "Accounts module produced findings"
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

        # Every actionable (CRITICAL/WARNING) finding has Remediation text; INFO findings are informational
        Write-TestHeader "Remediation Field Coverage"
        $actionable = @($findings | Where-Object { $_.Severity -in @("CRITICAL", "WARNING") })
        $noRemediation = @($actionable | Where-Object { -not $_.Remediation })
        if ($noRemediation.Count -eq 0) {
            Write-Host "  [PASS] All $($actionable.Count) CRITICAL/WARNING findings have Remediation text" -ForegroundColor Green
            $script:TestsPassed++
        } else {
            Write-Host "  [FAIL] $($noRemediation.Count) findings missing Remediation: $(($noRemediation | Select-Object -First 3 -ExpandProperty Title) -join '; ')" -ForegroundColor Red
            $script:TestsFailed++
        }

        # Every actionable (CRITICAL/WARNING) finding has at least one MITRE tag
        Write-TestHeader "MITRE Tag Coverage"
        $noMitre = @($actionable | Where-Object { -not $_.MITRE -or @($_.MITRE).Count -eq 0 })
        if ($noMitre.Count -eq 0) {
            Write-Host "  [PASS] All $($actionable.Count) CRITICAL/WARNING findings have MITRE ATT&CK tags" -ForegroundColor Green
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

        $noRule = @($results.Findings | Where-Object { $_.RuleId -notmatch '^AIH-' })
        Assert-True (@($results.Findings).Count -gt 0 -and $noRule.Count -eq 0) "Every finding in the JSON export has an AIH- rule ID" "$($noRule.Count) without: $(@($noRule | Select-Object -First 3 | ForEach-Object Title) -join ', ')"
        $sarifFile = Get-ChildItem $outputDir -Filter "*.sarif" | Select-Object -First 1
        $sarifBytes = if ($sarifFile) { [System.IO.File]::ReadAllBytes($sarifFile.FullName) } else { @() }
        $sarifDoc = if ($sarifFile) { Get-Content $sarifFile.FullName -Raw | ConvertFrom-Json } else { $null }
        Assert-True ($sarifDoc -and $sarifDoc.version -eq "2.1.0" -and @($sarifDoc.runs[0].results).Count -eq @($results.Findings).Count -and $sarifBytes[0] -ne 0xEF) "-ExportSarif writes a SARIF 2.1.0 file (no BOM) with one result per finding"

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
            & "$repoRoot\AmIHacked.ps1" -OutputPath $secondOutputDir -Offline -CIMode -SkipModules @() *>&1 | Out-Null
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

        Write-TestHeader "NonInteractive Host"
        $hostExe = (Get-Process -Id $PID).Path
        $niOutputDir = Join-Path $testTempDir "reports_noni"
        New-Item -ItemType Directory -Path $niOutputDir -Force | Out-Null
        $niOutput = & $hostExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$repoRoot\AmIHacked.ps1" -OutputPath $niOutputDir -Offline `
            -SkipModules Processes,Network,Accounts,FileSystem,DefenseEvasion,Baseline 2>&1 | Out-String
        Assert-True ($niOutput -match "---AMIHACKED-SUMMARY-JSON---") "Host started with -NonInteractive auto-enables CI mode"

        Write-TestHeader "Missing -BaselinePath"
        $bpOutputDir = Join-Path $testTempDir "reports_bp"
        New-Item -ItemType Directory -Path $bpOutputDir -Force | Out-Null
        & "$repoRoot\AmIHacked.ps1" -OutputPath $bpOutputDir -Offline -CIMode -ExportJson -BaselinePath (Join-Path $testTempDir "missing.json") `
            -SkipModules Processes,Network,Accounts,FileSystem,DefenseEvasion *>&1 | Out-Null
        $bpJson = Get-ChildItem $bpOutputDir -Filter "AmIHacked_*.json" | Select-Object -First 1
        $bpFindings = if ($bpJson) { (Get-Content $bpJson.FullName -Raw | ConvertFrom-Json).Findings } else { @() }
        Assert-True (@($bpFindings | Where-Object { $_.Title -eq "Baseline File Not Found" }).Count -eq 1) "A -BaselinePath that does not exist is reported"

        Write-TestHeader "CIMode Exit Code"
        if ($ciExit -ge 0 -and $ciExit -le 2) {
            Write-Host "  [PASS] CIMode exit code is $ciExit (0=clean, 1=warning, 2=critical)" -ForegroundColor Green
            $script:TestsPassed++
        } else {
            Write-Host "  [FAIL] CIMode exit code is $ciExit (expected 0, 1, or 2)" -ForegroundColor Red
            $script:TestsFailed++
        }
    }
} finally {
    # ── Cleanup (always runs, so a crash cannot leave the test Run keys behind) ──
    if (-not $KeepArtifacts) {
        Write-Host "`n  Cleaning up test artifacts..." -ForegroundColor DarkGray
        foreach ($action in $script:CleanupActions) {
            try { & $action } catch {}
        }
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
