<#
.SYNOPSIS
    Shared helper functions for Am I Hacked modules.
#>

# ── Console Output Helpers ───────────────────────────────────────────────────

$script:ModuleIndex = 0
$script:ModuleTotal = 0
$script:SectionStart = $null
$script:IsAdmin = $false

# Shared constants (single source for every module and the baseline code)
$script:RunKeyPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$script:CategoryDisplayNames = @{
    "Process"        = "Process &amp; Service Analysis"
    "Network"        = "Network Indicators"
    "Account"        = "Account &amp; Authentication"
    "FileSystem"     = "File System Red Flags"
    "DefenseEvasion" = "Defense Evasion &amp; Anti-Forensics"
    "Baseline"       = "Baseline Comparison"
}

function Get-SeverityCounts {
    <# CRITICAL/WARNING/INFO counts for a list of findings (always arrays, so a single match counts as 1 in PS 5.1). #>
    param([object[]]$Findings)
    $list = @($Findings | Where-Object { $_ })
    return [PSCustomObject]@{
        Critical = @($list | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        Warning  = @($list | Where-Object { $_.Severity -eq "WARNING" }).Count
        Info     = @($list | Where-Object { $_.Severity -eq "INFO" }).Count
        Total    = $list.Count
    }
}

function Write-Banner {
    Write-Host ""
    $lines = @(
        "       _   __  __   ___   _  _   _    ___ _  _____ ___  ___ "
        "      /_\ |  \/  | |_ _| | || | /_\  / __| |/ / __|   \|__ \"
        "     / _ \| |\/| |  | |  | __ |/ _ \| (__| ' <| _|| |) | /_/"
        "    /_/ \_\_|  |_| |___| |_||_/_/ \_\\___|_|\_\___|___/ (_) "
    )
    $colors = @("DarkRed", "Red", "Red", "DarkRed")
    for ($i = 0; $i -lt $lines.Count; $i++) {
        Write-Host $lines[$i] -ForegroundColor $colors[$i]
    }
    Write-Host ""
    Write-Host "    Windows Security Assessment Tool" -NoNewline -ForegroundColor White
    Write-Host "  v$($script:Version)" -NoNewline -ForegroundColor DarkGray
    if ($script:IsAdmin) {
        Write-Host "  [" -NoNewline -ForegroundColor DarkGray
        Write-Host "ADMIN" -NoNewline -ForegroundColor Green
        Write-Host "]" -ForegroundColor DarkGray
    } else {
        Write-Host "  [" -NoNewline -ForegroundColor DarkGray
        Write-Host "LIMITED" -NoNewline -ForegroundColor Yellow
        Write-Host "]" -ForegroundColor DarkGray
    }
    Write-Host "    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Status {
    param(
        [string]$Message,
        [ConsoleColor]$Color = "Gray"
    )
    Write-Host "  [" -NoNewline -ForegroundColor DarkGray
    Write-Host "*" -NoNewline -ForegroundColor Cyan
    Write-Host "] " -NoNewline -ForegroundColor DarkGray
    Write-Host (Invoke-Redact $Message) -ForegroundColor $Color
}

function Write-Section {
    param([string]$Title)

    if ($script:SectionStart) {
        $elapsed = ((Get-Date) - $script:SectionStart).TotalSeconds
        Write-Host "  [" -NoNewline -ForegroundColor DarkGray
        Write-Host "+" -NoNewline -ForegroundColor Green
        Write-Host "] " -NoNewline -ForegroundColor DarkGray
        Write-Host "Done " -NoNewline -ForegroundColor DarkGray
        Write-Host "$([math]::Round($elapsed, 1))s" -ForegroundColor DarkGray
    }
    $script:SectionStart = Get-Date

    $script:ModuleIndex++
    $progress = ""
    $barColor = "DarkGray"
    if ($script:ModuleTotal -gt 0) {
        $pct = [math]::Round(($script:ModuleIndex / $script:ModuleTotal) * 100)
        $barLen = 20
        $filled = [math]::Round($barLen * $script:ModuleIndex / $script:ModuleTotal)
        $empty = $barLen - $filled
        $bar = ("█" * $filled) + ("░" * $empty)

        $fc = $script:Findings.Count
        $tally = ""
        if ($fc -gt 0) {
            $sevCounts = Get-SeverityCounts $script:Findings
            $cc = $sevCounts.Critical
            $wc = $sevCounts.Warning
            $ic = $sevCounts.Info
            $parts = @()
            if ($cc -gt 0) { $parts += "${cc}C" }
            if ($wc -gt 0) { $parts += "${wc}W" }
            if ($ic -gt 0) { $parts += "${ic}I" }
            $tally = " | $($parts -join ' ')"
        }
        $progress = " [$bar] ${pct}%$tally"

        if ($cc -gt 0) { $barColor = "Red" }
        elseif ($wc -gt 0) { $barColor = "Yellow" }
        else { $barColor = "Green" }
    }
    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │ " -NoNewline -ForegroundColor DarkCyan
    $padded = $Title.PadRight(53)
    Write-Host $padded -NoNewline -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor DarkCyan
    if ($progress) {
        Write-Host "  │ " -NoNewline -ForegroundColor DarkCyan
        $progPadded = $progress.PadRight(53)
        Write-Host $progPadded -NoNewline -ForegroundColor $barColor
        Write-Host "│" -ForegroundColor DarkCyan
    }
    Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
}

function Write-SectionEnd {
    if ($script:SectionStart) {
        $elapsed = ((Get-Date) - $script:SectionStart).TotalSeconds
        Write-Host "  [" -NoNewline -ForegroundColor DarkGray
        Write-Host "+" -NoNewline -ForegroundColor Green
        Write-Host "] " -NoNewline -ForegroundColor DarkGray
        Write-Host "Done " -NoNewline -ForegroundColor DarkGray
        Write-Host "$([math]::Round($elapsed, 1))s" -ForegroundColor DarkGray
        $script:SectionStart = $null
    }
}

# ── Redaction ────────────────────────────────────────────────────────────────

function Invoke-Redact {
    param([string]$Text)
    if (-not $script:RedactMode -or -not $Text) { return $Text }
    foreach ($key in $script:RedactMap.Keys) {
        $Text = $Text -replace [regex]::Escape($key), $script:RedactMap[$key]
    }
    return $Text
}

function Invoke-RedactObject {
    param([object]$Obj)
    if (-not $script:RedactMode -or $null -eq $Obj) { return $Obj }

    if ($Obj -is [string]) {
        return Invoke-Redact $Obj
    }
    if ($Obj -is [hashtable]) {
        $result = @{}
        foreach ($k in $Obj.Keys) {
            $result[$k] = Invoke-RedactObject $Obj[$k]
        }
        return $result
    }
    # Numbers, booleans, dates, enums: nothing to redact. Checked on the base object because
    # PowerShell wraps values in a PSObject, and [PSCustomObject] -is matches any wrapped value.
    if ($Obj.PSObject.BaseObject -is [ValueType]) {
        return $Obj
    }
    if ($Obj -is [System.Collections.IList]) {
        return @(foreach ($item in $Obj) { Invoke-RedactObject $item })
    }
    if ($Obj.PSObject.BaseObject -is [System.Management.Automation.PSCustomObject]) {
        $result = [PSCustomObject]@{}
        foreach ($prop in $Obj.PSObject.Properties) {
            $result | Add-Member -NotePropertyName $prop.Name -NotePropertyValue (Invoke-RedactObject $prop.Value)
        }
        return $result
    }
    return $Obj
}

# ── Finding Management ───────────────────────────────────────────────────────

function Add-Finding {
    param(
        [ValidateSet("CRITICAL","WARNING","INFO")]
        [string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Description,
        [string]$Remediation = "",
        [object]$Details = $null,
        [string[]]$MITRE = @()
    )

    $Title       = Invoke-Redact $Title
    $Description = Invoke-Redact $Description
    $Remediation = Invoke-Redact $Remediation
    $Details     = Invoke-RedactObject $Details

    if ($script:Config.Suppressions) {
        foreach ($sup in $script:Config.Suppressions) {
            if ($Title -like $sup.pattern) {
                $script:SuppressedCount++
                return
            }
        }
    }

    $finding = [PSCustomObject]@{
        Severity    = $Severity
        Category    = $Category
        Title       = $Title
        Description = $Description
        Remediation = $Remediation
        Details     = $Details
        MITRE       = $MITRE
        Timestamp   = Get-Date
    }

    $script:Findings.Add($finding) | Out-Null

    switch ($Severity) {
        "CRITICAL" {
            Write-Host "  [" -NoNewline -ForegroundColor DarkGray
            Write-Host "!!!" -NoNewline -ForegroundColor Red
            Write-Host "] " -NoNewline -ForegroundColor DarkGray
            Write-Host "CRITICAL" -NoNewline -ForegroundColor Red
            Write-Host " │ " -NoNewline -ForegroundColor DarkGray
            Write-Host $Title -ForegroundColor White
        }
        "WARNING" {
            Write-Host "  [" -NoNewline -ForegroundColor DarkGray
            Write-Host " ! " -NoNewline -ForegroundColor Yellow
            Write-Host "] " -NoNewline -ForegroundColor DarkGray
            Write-Host "WARNING " -NoNewline -ForegroundColor Yellow
            Write-Host " │ " -NoNewline -ForegroundColor DarkGray
            Write-Host $Title -ForegroundColor Gray
        }
        "INFO" {
            Write-Host "  [" -NoNewline -ForegroundColor DarkGray
            Write-Host " i " -NoNewline -ForegroundColor DarkCyan
            Write-Host "] " -NoNewline -ForegroundColor DarkGray
            Write-Host "INFO    " -NoNewline -ForegroundColor DarkCyan
            Write-Host " │ " -NoNewline -ForegroundColor DarkGray
            Write-Host $Title -ForegroundColor DarkGray
        }
    }
}

# ── Config Helpers ───────────────────────────────────────────────────────────

function Get-DefaultConfig {
    return [PSCustomObject]@{
        ProcessWhitelist = @(
            "svchost", "csrss", "wininit", "services", "lsass", "smss",
            "winlogon", "dwm", "taskhostw", "explorer", "runtimebroker",
            "searchhost", "startmenuexperiencehost", "textinputhost",
            "sihost", "ctfmon", "conhost", "dllhost", "fontdrvhost",
            "msdtc", "spoolsv", "wuauclt", "audiodg", "searchindexer",
            "securityhealthservice", "securityhealthsystray", "sgrmbroker",
            "systemsettings", "applicationframehost", "shellexperiencehost",
            "lockapp", "msedge", "msedgewebview2", "widgetservice"
        )

        ServiceWhitelist = @()

        TrustedIPs = @(
            "13.107.0.0/16",
            "20.0.0.0/8",
            "23.0.0.0/8",
            "104.0.0.0/8"
        )

        TrustedPorts = @(135, 139, 445, 5040, 7680, 5432, 5357, 2179, 8811, 3306, 6379, 27017, 8080, 8443, 3000, 5000, 5500, 8000)

        CommonRemotePorts = @(80, 443, 53, 22, 993, 995, 587, 465, 853)

        VirusTotalAPIKey = ""
        AbuseIPDBKey     = ""

        AccountMaxAgeDays      = 7
        FileSystemMaxAgeDays   = 3
        MaxEventLogEntries     = 1000

        SuspiciousParentChild = @(
            @{ Parent = "winword.exe";   Child = "powershell.exe" }
            @{ Parent = "winword.exe";   Child = "cmd.exe" }
            @{ Parent = "winword.exe";   Child = "wscript.exe" }
            @{ Parent = "winword.exe";   Child = "cscript.exe" }
            @{ Parent = "excel.exe";     Child = "powershell.exe" }
            @{ Parent = "excel.exe";     Child = "cmd.exe" }
            @{ Parent = "outlook.exe";   Child = "powershell.exe" }
            @{ Parent = "outlook.exe";   Child = "cmd.exe" }
            @{ Parent = "mshta.exe";     Child = "powershell.exe" }
            @{ Parent = "svchost.exe";   Child = "cmd.exe" }
            @{ Parent = "explorer.exe";  Child = "mshta.exe" }
            @{ Parent = "wmiprvse.exe";  Child = "powershell.exe" }
        )

        SuspiciousTempExtensions = @(
            ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".psd1",
            ".hta", ".cpl", ".msi", ".msp", ".com", ".pif"
        )

        TrustedCompanies = @(
            "Microsoft Corporation", "Google LLC", "Slack Technologies",
            "Spotify AB", "Discord Inc.", "Mozilla Corporation",
            "Apple Inc.", "Adobe Inc.", "Valve Corporation",
            "GitHub, Inc.", "GitHub", "Node.js Foundation", "OpenJS Foundation",
            "Rockstar Games", "Cfx.re", "Python Software Foundation",
            "NVIDIA Corporation", "Intel Corporation", "Samsung Electronics",
            "Amazon.com Services LLC", "Amazon Web Services",
            "Proton AG", "Notion Labs, Inc.", "LM Studio", "Anthropic",
            "JetBrains s.r.o.", "Docker Inc", "Canonical Ltd.",
            "Postman Inc.", "Activision Publishing", "Blizzard Entertainment",
            "Electronic Arts", "Epic Games", "Ubisoft",
            "Dropbox, Inc.", "Zoom Video Communications, Inc.",
            "1Password", "AgileBits Inc.", "Bitwarden Inc.",
            "The Chromium Authors", "The Electron Authors"
        )

        TrustedAppDirs = @()

        TrustedDomainSuffixes = @(
            ".microsoft.com", ".windowsupdate.com", ".akamaized.net",
            ".cloudfront.net", ".slack-msgs.com", ".googleapis.com",
            ".gstatic.com", ".steamcontent.com"
        )

        BackdoorPorts = @(4444, 5555, 6666, 1234, 31337, 12345, 54321, 9999, 1337)

        KnownDNSServers = @(
            "8.8.8.8", "8.8.4.4",
            "1.1.1.1", "1.0.0.1",
            "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220",
            "76.76.2.0", "76.76.10.0"
        )

        AbuseIPDBMaxChecks = 30

        MaxVTLookups = 4

        Suppressions = @()
    }
}

function Get-ScanModules {
    <# Discovers modules\Check-*.ps1; the module name comes from the filename, the description from the MODULE metadata block. #>
    param([string]$ModulesDir)
    if (-not (Test-Path $ModulesDir)) { return @() }
    return @(Get-ChildItem $ModulesDir -Filter "Check-*.ps1" | ForEach-Object {
        $name = $_.BaseName -replace '^Check-', ''
        $description = "$name Analysis"
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match '(?s)<#\s*MODULE\s*\r?\n(.*?)#>') {
            $metaBlock = $Matches[1]
            if ($metaBlock -match 'Description:\s*(.+)') {
                $description = $Matches[1].Trim()
            }
        }
        @{ Name = $name; File = $_.Name; Description = $description; FullPath = $_.FullName }
    })
}

function Resolve-ModuleSelection {
    <#
        Turns -Modules / -SkipModules into the final skip list. Names are matched case-insensitively
        against the discovered modules ("Baseline" is also accepted). Unknown names are returned in
        Unknown so the caller can warn; -Modules keeps Baseline unless it is skipped explicitly.
    #>
    param([string[]]$Available, [string[]]$Modules = @(), [string[]]$SkipModules = @())
    # powershell.exe -File passes "-SkipModules A,B" as the single string "A,B"
    $Modules = @($Modules | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $SkipModules = @($SkipModules | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $valid = @($Available) + @("Baseline")
    $unknown = @(@($Modules) + @($SkipModules) | Where-Object { $_ -and $_ -notin $valid } | Select-Object -Unique)
    $skip = [System.Collections.ArrayList]::new()
    foreach ($n in @($SkipModules)) {
        $match = $valid | Where-Object { $_ -eq $n } | Select-Object -First 1
        if ($match -and $match -notin $skip) { $skip.Add($match) | Out-Null }
    }
    if (@($Modules | Where-Object { $_ }).Count -gt 0) {
        foreach ($a in $Available) {
            if ($a -notin $Modules -and $a -notin $skip) { $skip.Add($a) | Out-Null }
        }
    }
    return [PSCustomObject]@{ Skip = @($skip); Unknown = $unknown; Valid = $valid }
}

function Merge-Config {
    <#
        Overlays the properties of a user config (from config.json) onto the built-in defaults, so a
        config file written for an older version still gets defaults for keys added later.
        A key present in the user file replaces the default value entirely (including empty arrays).
    #>
    param($Defaults, $UserConfig)
    $merged = [PSCustomObject]@{}
    foreach ($prop in $Defaults.PSObject.Properties) {
        $merged | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
    }
    if ($UserConfig) {
        foreach ($prop in $UserConfig.PSObject.Properties) {
            $merged | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
        }
    }
    return $merged
}

function New-DefaultConfig {
    param([string]$Path = "")
    if (-not $Path) {
        $repoRoot = Split-Path $PSScriptRoot -Parent
        $Path = Join-Path $repoRoot "config\config.json"
    }

    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $config = Get-DefaultConfig
    $config | ConvertTo-Json -Depth 5 | Set-Content $Path -Encoding UTF8
    Write-Status "Default config written to $Path" -Color Green
}

# ── Utility Functions ────────────────────────────────────────────────────────

function Test-IsUncommonRemotePort {
    # Outbound connections to a well-known port below 1024 that is not in CommonRemotePorts.
    # TrustedPorts is for listeners only and is deliberately not consulted here.
    param([int]$Port)
    return ($Port -lt 1024 -and $Port -notin @($script:Config.CommonRemotePorts))
}

function Test-IsTrustedIP {
    param([string]$IP)

    if (-not $script:Config.TrustedIPs) { return $false }

    foreach ($trusted in $script:Config.TrustedIPs) {
        if ($trusted -match "/") {
            if (Test-IPInCIDR -IP $IP -CIDR $trusted) { return $true }
        } else {
            if ($IP -eq $trusted) { return $true }
        }
    }
    return $false
}

function Test-IPInCIDR {
    param([string]$IP, [string]$CIDR)
    try {
        $parts = $CIDR -split "/"
        $network = [System.Net.IPAddress]::Parse($parts[0])
        $maskBits = [int]$parts[1]
        $target = [System.Net.IPAddress]::Parse($IP)

        $netBytes = $network.GetAddressBytes()
        $targetBytes = $target.GetAddressBytes()

        if ($netBytes.Length -ne $targetBytes.Length) { return $false }

        $fullBytes = [math]::Floor($maskBits / 8)
        $remainBits = $maskBits % 8

        for ($i = 0; $i -lt $fullBytes; $i++) {
            if ($netBytes[$i] -ne $targetBytes[$i]) { return $false }
        }

        if ($remainBits -gt 0) {
            # -shl yields an [int] (e.g. 0xFF -shl 4 = 4080); keep only the low byte before comparing
            $mask = (0xFF -shl (8 - $remainBits)) -band 0xFF
            if (($netBytes[$fullBytes] -band $mask) -ne ($targetBytes[$fullBytes] -band $mask)) {
                return $false
            }
        }

        return $true
    } catch {
        Write-Verbose "Test-IPInCIDR: cannot compare '$IP' with '$CIDR': $($_.Exception.Message)"
        return $false
    }
}

function Test-IsPrivateIP {
    <# Private, loopback, link-local, CGNAT and IPv6 unique-local addresses (not routed on the public internet). #>
    param([string]$IP)
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse(($IP -replace '%.*$', ''), [ref]$addr)) { return $false }
    if ($addr.IsIPv4MappedToIPv6) { $addr = $addr.MapToIPv4() }
    $ranges = @(
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
        "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",   # loopback, link-local (APIPA), carrier-grade NAT
        "::1/128", "fe80::/10", "fc00::/7"                  # IPv6 loopback, link-local, unique-local
    )
    foreach ($range in $ranges) {
        if (Test-IPInCIDR $addr.ToString() $range) { return $true }
    }
    return $false
}

function Get-FileSignature {
    <#
        Authenticode signature of a file, cached per path for the rest of the scan.
        The Security module is imported once in the orchestrator's preflight; when that preflight found
        Get-AuthenticodeSignature unavailable ($script:SignatureCheckAvailable -eq $false), return the
        CheckFailed sentinel straight away so callers don't treat the file as unsigned.
    #>
    param([string]$FilePath)
    $sentinel = [PSCustomObject]@{ Status = "CheckFailed"; StatusMessage = "Signature check unavailable (PS.Security module could not be loaded)." }
    if ($script:SignatureCheckAvailable -eq $false) { return $sentinel }
    if (-not $script:SignatureCache) { $script:SignatureCache = @{} }
    $cacheKey = "$FilePath".ToLowerInvariant()
    if ($script:SignatureCache.ContainsKey($cacheKey)) { return $script:SignatureCache[$cacheKey] }
    $result = $sentinel
    try {
        $sig = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue
        if ($sig) { $result = $sig }
    } catch {
        Write-Verbose "Get-AuthenticodeSignature failed for '$FilePath': $_"
    }
    $script:SignatureCache[$cacheKey] = $result
    return $result
}

function ConvertFrom-LogClearedXml {
    <#
        Reads the LogFileCleared user data of Security 1102 / System 104 events by field name.
        Event 104's data is SubjectUserName, SubjectDomainName, Channel, BackupPath, so index-based
        access to Properties[0] returns the account, not the channel.
    #>
    param([string]$Xml)
    $data = $null
    try { $data = ([xml]$Xml).Event.UserData.LogFileCleared } catch { }
    if (-not $data) { return [PSCustomObject]@{ Channel = $null; Account = $null } }
    $account = if ($data.SubjectDomainName -and $data.SubjectUserName) { "$($data.SubjectDomainName)\$($data.SubjectUserName)" } else { $data.SubjectUserName }
    return [PSCustomObject]@{ Channel = $data.Channel; Account = $account }
}

function Test-UnquotedServicePath {
    <#
        True when a service's executable path is unquoted and contains a space, outside \Windows\.
        Only the executable part (up to ".exe") is considered, so spaces in arguments don't count.
    #>
    param([string]$PathName)
    if (-not $PathName -or $PathName.TrimStart() -match '^"') { return $false }
    $exePart = if ($PathName -match '^(.*?\.exe)(\s|$)') { $Matches[1] } else { $PathName }
    return ($exePart -match ' ' -and $exePart -notmatch '^[A-Za-z]:\\Windows\\')
}

function Get-WinEventOrEmpty {
    <#
        Get-WinEvent that returns @() when no events match, but rethrows real errors (e.g. access
        denied on the Security log without admin), which -ErrorAction SilentlyContinue would hide.
    #>
    param([hashtable]$FilterHashtable, [string]$LogName, [string]$FilterXPath, [int]$MaxEvents)
    $params = @{ ErrorAction = "Stop" }
    if ($FilterHashtable) { $params.FilterHashtable = $FilterHashtable }
    if ($LogName) { $params.LogName = $LogName }
    if ($FilterXPath) { $params.FilterXPath = $FilterXPath }
    if ($MaxEvents -gt 0) { $params.MaxEvents = $MaxEvents }
    try {
        return @(Get-WinEvent @params)
    } catch {
        if ("$($_.FullyQualifiedErrorId)" -like "NoMatchingEventsFound*") { return @() }
        throw
    }
}

function Get-HttpStatusCode {
    <# HTTP status code (int) from an Invoke-RestMethod/Invoke-WebRequest error record, or $null. #>
    param($ErrorRecord)
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($resp -and $null -ne $resp.StatusCode) { return [int]$resp.StatusCode }
    } catch {
        Write-Verbose "No HTTP status in error: $_"
    }
    return $null
}

function Invoke-VirusTotalLookups {
    <#
        Looks up file hashes on VirusTotal. At most -MaxLookups requests are sent, whatever the
        responses (404 "unknown" counts too). A rejected key (401/403) or rate limit (429) stops the
        loop with a visible status line; other errors are reported per file.
    #>
    param([object[]]$Files, [string]$ApiKey, [int]$MaxLookups)
    $checked = 0

    foreach ($file in $Files) {
        if ($checked -ge $MaxLookups) {
            Write-Status "VirusTotal rate limit reached. Remaining files skipped." -Color Yellow
            break
        }

        try {
            $hash = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if (-not $hash) { continue }

            # Count the attempt before sending it, so 404s and errors also use up the budget
            $checked++
            $vtResponse = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" `
                -Headers @{ "x-apikey" = $ApiKey } `
                -Method GET -ErrorAction Stop

            $stats = $vtResponse.data.attributes.last_analysis_stats
            $detections = $stats.malicious + $stats.suspicious

            if ($detections -gt 0) {
                $severity = if ($detections -ge 5) { "CRITICAL" } else { "WARNING" }

                Add-Finding -Severity $severity -Category "FileSystem" `
                    -Title "VirusTotal Detection: $($file.Name) ($detections engines)" `
                    -Description "File '$($file.Name)' (SHA256: $hash) is flagged by $detections VirusTotal engines ($($stats.malicious) malicious, $($stats.suspicious) suspicious out of $($stats.undetected + $detections) total)." `
                    -Remediation "Delete this file immediately. Run a full system scan. Consider this system potentially compromised." `
                    -Details @{
                        Path = $file.FullName
                        SHA256 = $hash
                        Detections = $detections
                        Malicious = $stats.malicious
                        Suspicious = $stats.suspicious
                        Harmless = $stats.harmless
                        Undetected = $stats.undetected
                        VTLink = "https://www.virustotal.com/gui/file/$hash"
                    } `
                    -MITRE @("T1204.002")
            }
        } catch {
            $status = Get-HttpStatusCode $_
            if ($status -eq 404) {
                Add-Finding -Severity "INFO" -Category "FileSystem" `
                    -Title "Unknown to VirusTotal: $($file.Name)" `
                    -Description "File '$($file.Name)' hash is not in the VirusTotal database. This means it's either very new, custom-built, or rarely seen — which can be suspicious for executables." `
                    -Details @{ Path = $file.FullName }
            } elseif ($status -in @(401, 403)) {
                Write-Status "VirusTotal rejected the API key (HTTP $status). Check 'VirusTotalAPIKey' in config.json. Remaining files skipped." -Color Yellow
                break
            } elseif ($status -eq 429) {
                Write-Status "VirusTotal quota or rate limit exceeded (HTTP 429). Remaining files skipped." -Color Yellow
                break
            } else {
                Write-Status "VirusTotal lookup failed for $($file.Name): $(if ($status) { "HTTP $status" } else { $_.Exception.Message })" -Color Yellow
            }
        }
    }
}

function Get-PowerShellProfileCandidates {
    <#
        Every PowerShell profile file that can run at startup, independent of the host running the scan:
        all-users profiles of Windows PowerShell 5.1 and PowerShell 7, and per-user profiles
        (WindowsPowerShell and PowerShell folders x console/ISE/VS Code/all-hosts) for the current
        user, plus every other user under the Users folder when -AllUsers is set (needs admin).
        Returns objects with Name, Path and Owner; paths are not checked for existence.
    #>
    param(
        [switch]$AllUsers,
        [string]$UsersRoot = (Split-Path $env:USERPROFILE -Parent),
        [string]$CurrentUserDocuments = [Environment]::GetFolderPath('MyDocuments'),
        [string]$CurrentUserName = $env:USERNAME
    )
    $list = [System.Collections.ArrayList]::new()
    $seen = @{}
    $add = {
        param($Name, $Path, $Owner)
        if (-not $Path) { return }
        $k = $Path.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { return }
        $seen[$k] = $true
        $list.Add([PSCustomObject]@{ Name = $Name; Path = $Path; Owner = $Owner }) | Out-Null
    }

    $allUserHomes = @(
        @{ Edition = "Windows PowerShell"; Dir = (Join-Path $env:windir "System32\WindowsPowerShell\v1.0") }
        @{ Edition = "PowerShell 7"; Dir = (Join-Path $env:ProgramFiles "PowerShell\7") }
    )
    foreach ($h in $allUserHomes) {
        foreach ($f in @("profile.ps1", "Microsoft.PowerShell_profile.ps1", "Microsoft.PowerShellISE_profile.ps1", "Microsoft.VSCode_profile.ps1")) {
            & $add "All users ($($h.Edition), $f)" (Join-Path $h.Dir $f) "All users"
        }
    }

    $userDocs = [System.Collections.ArrayList]::new()
    if ($CurrentUserDocuments) { $userDocs.Add(@{ Owner = $CurrentUserName; Docs = $CurrentUserDocuments }) | Out-Null }
    if ($AllUsers -and $UsersRoot -and (Test-Path $UsersRoot)) {
        foreach ($u in Get-ChildItem $UsersRoot -Directory -ErrorAction SilentlyContinue) {
            if ($u.Name -in @("Public", "Default", "Default User", "All Users")) { continue }
            $userDocs.Add(@{ Owner = $u.Name; Docs = (Join-Path $u.FullName "Documents") }) | Out-Null
            $userDocs.Add(@{ Owner = $u.Name; Docs = (Join-Path $u.FullName "OneDrive\Documents") }) | Out-Null
        }
    }
    foreach ($ud in $userDocs) {
        foreach ($edition in @(@{ Label = "Windows PowerShell"; Folder = "WindowsPowerShell" }, @{ Label = "PowerShell 7"; Folder = "PowerShell" })) {
            foreach ($f in @("profile.ps1", "Microsoft.PowerShell_profile.ps1", "Microsoft.PowerShellISE_profile.ps1", "Microsoft.VSCode_profile.ps1")) {
                & $add "$($ud.Owner) ($($edition.Label), $f)" (Join-Path $ud.Docs (Join-Path $edition.Folder $f)) $ud.Owner
            }
        }
    }
    return $list.ToArray()
}

function Get-PacUrlSeverity {
    <#
        Severity for a proxy auto-config (PAC) URL: CRITICAL for local files, raw-IP hosts or
        user-writable paths (typical of adware and banking trojans), INFO when delivered by
        Group Policy, otherwise WARNING.
    #>
    param([string]$Url, [bool]$FromPolicy = $false)
    $u = "$Url".Trim()
    $isFile = $u -match '^file:' -or $u -match '^[a-zA-Z]:\\' -or $u -match '^\\\\'
    $isRawIp = $u -match '^[a-z]+://(\d{1,3}\.){3}\d{1,3}([:/]|$)' -or $u -match '^[a-z]+://\[[0-9a-fA-F:]+\]'
    $isUserWritable = $u -match '(?i)\\Users\\|/Users/|AppData|\\Temp\\|/Temp/'
    if ($isFile -or $isRawIp -or $isUserWritable) { return "CRITICAL" }
    if ($FromPolicy) { return "INFO" }
    return "WARNING"
}

function ConvertFrom-WinHttpSettings {
    <#
        Decodes the WinHttpSettings blob (HKLM\...\Internet Settings\Connections):
        DWORD version, DWORD counter, DWORD flags (bit 0x2 = named proxy), DWORD proxy length,
        proxy (ASCII), DWORD bypass length, bypass list (ASCII).
    #>
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 16) { return $null }
    $flags = [BitConverter]::ToInt32($Bytes, 8)
    $proxyLen = [BitConverter]::ToInt32($Bytes, 12)
    $proxy = ""
    $bypass = ""
    if ($proxyLen -gt 0 -and $Bytes.Length -ge 16 + $proxyLen) {
        $proxy = [System.Text.Encoding]::ASCII.GetString($Bytes, 16, $proxyLen)
        $bypassOffset = 16 + $proxyLen
        if ($Bytes.Length -ge $bypassOffset + 4) {
            $bypassLen = [BitConverter]::ToInt32($Bytes, $bypassOffset)
            if ($bypassLen -gt 0 -and $Bytes.Length -ge $bypassOffset + 4 + $bypassLen) {
                $bypass = [System.Text.Encoding]::ASCII.GetString($Bytes, $bypassOffset + 4, $bypassLen)
            }
        }
    }
    return [PSCustomObject]@{ UsesProxy = (($flags -band 0x2) -ne 0 -and $proxy); Proxy = $proxy; Bypass = $bypass }
}

function Get-HostsSecurityEntry {
    <#
        Returns hosts-file lines that map a security or update host (exact name or subdomain).
        Lines are parsed into IP + host tokens with comments stripped, so ad/telemetry blocklists
        (doubleclick.net, google-analytics.com, ...) and words inside comments do not match.
    #>
    param([string[]]$Lines)
    $securityHosts = @(
        "windowsupdate.com", "windowsupdate.microsoft.com", "update.microsoft.com", "delivery.mp.microsoft.com",
        "definitionupdates.microsoft.com", "wdcp.microsoft.com", "wdcpalt.microsoft.com",
        "smartscreen.microsoft.com", "smartscreen-prod.microsoft.com", "security.microsoft.com",
        "virustotal.com", "malwarebytes.com", "norton.com", "symantec.com", "kaspersky.com", "kaspersky-labs.com",
        "avast.com", "avg.com", "bitdefender.com", "bitdefender.net", "eset.com", "sophos.com",
        "mcafee.com", "trendmicro.com", "f-secure.com", "avira.com"
    )
    $result = [System.Collections.ArrayList]::new()
    foreach ($line in $Lines) {
        if (-not $line) { continue }
        $content = ($line -replace '#.*$', '').Trim()
        if (-not $content) { continue }
        $tokens = @($content -split '\s+')
        if ($tokens.Count -lt 2) { continue }
        foreach ($hostName in $tokens[1..($tokens.Count - 1)]) {
            $h = $hostName.ToLower().TrimEnd('.')
            $isSecurity = $false
            foreach ($d in $securityHosts) {
                if ($h -eq $d -or $h.EndsWith(".$d")) { $isSecurity = $true; break }
            }
            if ($isSecurity) { $result.Add($line) | Out-Null; break }
        }
    }
    return $result.ToArray()
}

function Test-AVProductEnabled {
    <# Decodes Security Center productState: 0x10 in the middle byte (0x00FF00) means the real-time scanner is on. #>
    param([int]$ProductState)
    return ((($ProductState -shr 8) -band 0x10) -ne 0)
}

function Get-ActiveThirdPartyAV {
    <# Names of enabled antivirus products registered with Security Center, other than Microsoft Defender. #>
    try {
        $products = @(Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop)
    } catch {
        Write-Verbose "Could not query SecurityCenter2 AntiVirusProduct: $_"
        return @()
    }
    return @($products | Where-Object {
        $_.displayName -notmatch 'Windows Defender|Microsoft Defender' -and (Test-AVProductEnabled ([int]$_.productState))
    } | ForEach-Object { $_.displayName })
}

function Get-MaxSeverity {
    <# Returns the more severe of two severities (INFO < WARNING < CRITICAL), so later rules can only raise severity. #>
    param([string]$Current, [string]$New)
    $rank = @{ "INFO" = 0; "WARNING" = 1; "CRITICAL" = 2 }
    if ($rank[$New] -gt $rank[$Current]) { return $New }
    return $Current
}

function Select-MpExclusion {
    <# Drops the "N/A: Must be an administrator to view exclusions" placeholder Defender returns to non-admin callers. #>
    param([object[]]$Values)
    return @($Values | Where-Object { $_ -and "$_" -notmatch '^N/A:' })
}

function Get-TrustedRootThumbprints {
    <#
        Thumbprints of roots that Windows itself distributes or that an enterprise deployed:
        - the Microsoft Trusted Root Program list cached in the authroot CTL (AuthRoot\AutoUpdate\EncodedCtl);
          SHA-1 subject identifiers appear in it as 20-byte OCTET STRINGs (04 14 ...)
        - the LocalMachine\AuthRoot store
        - Group Policy / enterprise roots
        - legacy Windows roots that are not in the CTL
        FromCtl is false when the CTL is not cached, so callers can fall back to a coarser check.
    #>
    $set = @{}
    foreach ($t in @(
        "7F88CD7223F3C813818C994614A89C99FA3B5247",  # Microsoft Authenticode(tm) Root Authority
        "245C97DF7514E7CF2DF8BE72AE957B9E04741E85",  # Microsoft Time Stamping Service Root
        "EBE112F56D5FE0BA23289319C89D7784A10CEB61",  # XBL Client IPsec Issuing CA (installed by Windows Xbox components)
        "645984515AB9FB7AE8065B9DDB0E908F8E870ED5"   # XBL Server IPsec Issuing CA
    )) { $set[$t] = "Windows" }

    $fromCtl = $false
    try {
        $ctl = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate' -ErrorAction Stop).EncodedCtl
        if ($ctl -and $ctl.Length -gt 22) {
            $hex = [System.BitConverter]::ToString([byte[]]$ctl).Replace('-', '')
            foreach ($m in [regex]::Matches($hex, '0414([0-9A-F]{40})')) {
                if ($m.Index % 2 -eq 0) { $set[$m.Groups[1].Value] = "CTL" }
            }
            $fromCtl = $true
        }
    } catch {
        Write-Verbose "authroot CTL not available: $_"
    }

    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("AuthRoot", "LocalMachine")
        $store.Open("ReadOnly")
        foreach ($c in $store.Certificates) { $set[$c.Thumbprint] = "AuthRoot" }
        $store.Close()
    } catch {
        Write-Verbose "Could not read AuthRoot store: $_"
    }

    foreach ($gpoPath in @('HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates',
                           'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates')) {
        Get-ChildItem $gpoPath -ErrorAction SilentlyContinue | ForEach-Object { $set[$_.PSChildName.ToUpper()] = "Enterprise" }
    }

    return [PSCustomObject]@{ Thumbprints = $set; FromCtl = $fromCtl }
}

function Get-CertDisplayName {
    <# CN of a subject without surrounding quotes, else the first 60 characters of the subject. #>
    param([string]$Subject)
    if ($Subject -match 'CN=("[^"]*"|[^,]+)') { return $Matches[1].Trim('"').Trim() }
    if (-not $Subject) { return "" }
    return $Subject.Substring(0, [math]::Min(60, $Subject.Length))
}

function ConvertTo-WmiRefString {
    <# Formats a binding's Filter/Consumer reference as 'Class.Name="X"' (CIM returns an instance, WMI a path string). #>
    param($Ref)
    if ($null -eq $Ref) { return "" }
    if ($Ref -is [string]) { return $Ref }
    $class = if ($Ref.CimClass) { $Ref.CimClass.CimClassName } else { $Ref.GetType().Name }
    return "$class.Name=`"$($Ref.Name)`""
}

function Get-WmiErrorReason {
    <# Short reason for a failed CIM query, separating access denied from other errors. #>
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    if ("$($ex.NativeErrorCode)" -eq "AccessDenied" -or $ex -is [System.UnauthorizedAccessException]) { return "access denied (run as Administrator)" }
    return $ex.Message.Trim()
}

function Test-IsDefaultWmiBinding {
    <# True for the binding Windows ships by default (SCM Event Log Filter -> NTEventLogEventConsumer "SCM Event Log Consumer"). #>
    param([string]$Filter, [string]$Consumer)
    return ($Filter -match '(^|:)__EventFilter\.Name="SCM Event Log Filter"$' -and
            $Consumer -match '(^|:)NTEventLogEventConsumer\.Name="SCM Event Log Consumer"$')
}

function Test-SignatureUnknown {
    <# True when the signature could not be checked (CheckFailed sentinel). Callers must treat this as unknown, never as unsigned. #>
    param($Signature)
    return [bool]($Signature -and $Signature.Status -eq "CheckFailed")
}

function Get-FileVersionInfo {
    param([string]$FilePath)
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
        return @{
            CompanyName      = $vi.CompanyName
            OriginalFilename = $vi.OriginalFileName
            ProductName      = $vi.ProductName
            FileDescription  = $vi.FileDescription
            FileVersion      = $vi.FileVersion
        }
    } catch {
        return $null
    }
}

function Test-IsTrustedCompany {
    param([string]$CompanyName)
    if (-not $CompanyName) { return $false }
    if (-not $script:Config.TrustedCompanies) { return $false }
    foreach ($trusted in $script:Config.TrustedCompanies) {
        if ($CompanyName -like "*$trusted*") { return $true }
    }
    return $false
}

function Test-IsTrustedSigner {
    <# Only safe downgrade path: valid digital signature from a trusted company #>
    param($Signature, $VersionInfo)
    if (-not $Signature -or $Signature.Status -ne "Valid") { return $false }
    $signerSubject = $Signature.SignerCertificate.Subject
    if (-not $signerSubject) { return $false }
    if (-not $script:Config.TrustedCompanies) { return $false }
    foreach ($trusted in $script:Config.TrustedCompanies) {
        if ($signerSubject -like "*$trusted*") { return $true }
    }
    return $false
}

function Test-IsTrustedDomain {
    param([string]$Hostname)
    if (-not $Hostname) { return $false }
    if (-not $script:Config.TrustedDomainSuffixes) { return $false }
    foreach ($suffix in $script:Config.TrustedDomainSuffixes) {
        if ($Hostname.EndsWith($suffix)) { return $true }
    }
    return $false
}

function Format-ByteSize {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

# ── Baseline Functions ───────────────────────────────────────────────────────

function Export-Baseline {
    param(
        [string]$OutputPath,
        [string]$FilePath
    )

    try {
        if (-not $FilePath) {
            $FilePath = Join-Path $OutputPath "baseline_latest.json"
        }

        $dir = Split-Path $FilePath -Parent
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $baseline = @{
            Timestamp = (Get-Date).ToString("o")
            Version   = $script:Version

            ListeningPorts = @(
                Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
                    @{ Port = $_.LocalPort; Address = $_.LocalAddress; PID = $_.OwningProcess }
                }
            )

            Services = @(
                Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
                    @{ Name = $_.Name; Path = $_.PathName; Account = $_.StartName; StartMode = $_.StartMode }
                }
            )

            RunKeys = @(
                $script:RunKeyPaths | ForEach-Object {
                    $key = $_
                    try {
                        $entries = Get-ItemProperty $key -ErrorAction SilentlyContinue
                        if ($entries) {
                            $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -ne "(default)" } | ForEach-Object {
                                @{ Key = $key; Name = $_.Name; Value = $_.Value }
                            }
                        }
                    } catch {
                        Write-Verbose "Could not read Run key '${key}': $_"
                    }
                }
            )

            LocalAccounts = @(
                Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
                    @{ Name = $_.Name; Enabled = $_.Enabled; SID = $_.SID.Value }
                }
            )

            ScheduledTasks = @(
                Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
                    $actions = $_.Actions | ForEach-Object { @{ Execute = $_.Execute; Arguments = $_.Arguments } }
                    @{ Name = $_.TaskName; Path = $_.TaskPath; Actions = $actions }
                }
            )

            DefenderExclusions = @{
                Paths      = @(Select-MpExclusion @(try { (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath } catch { @() }))
                Processes  = @(Select-MpExclusion @(try { (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionProcess } catch { @() }))
                Extensions = @(Select-MpExclusion @(try { (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionExtension } catch { @() }))
            }
        }

        $baseline | ConvertTo-Json -Depth 5 | Set-Content $FilePath -Encoding UTF8
        Write-Status "Baseline snapshot saved to: $FilePath"
        $baselineSha = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        Write-Status "Baseline SHA-256: $baselineSha" -Color Green
        Write-Status "Store this hash (or a copy of the baseline) off this machine, then pass -BaselineHash $baselineSha on later scans." -Color DarkGray
    } catch {
        Write-Status "Could not export baseline: $_" -Color Yellow
    }
}

function Get-TaskActionSignature {
    <# One comparable string for a task's actions (Execute + Arguments of each action). #>
    param($Actions)
    return ((@($Actions) | Where-Object { $_ } | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join " ; ")
}

function Compare-Baseline {
    param(
        [string]$BaselinePath,
        [string]$ExpectedHash = ""
    )

    try {
        # Integrity: anything with write access to the baseline could add its own items to the "known good" list
        $actualHash = (Get-FileHash -Path $BaselinePath -Algorithm SHA256).Hash
        if ($ExpectedHash -and $actualHash -ne $ExpectedHash.Trim().ToUpperInvariant()) {
            Add-Finding -Severity "WARNING" -Category "Baseline" `
                -Title "Baseline Hash Mismatch" `
                -Description "The baseline file '$BaselinePath' has SHA-256 $actualHash, but -BaselineHash expected $($ExpectedHash.Trim().ToUpperInvariant()). The baseline was changed or replaced after it was created, so it was not used for comparison." `
                -Remediation "Restore the baseline from an off-machine copy, or create a new one on a known-clean system with -CreateBaseline." `
                -Details @{ Path = $BaselinePath; ExpectedHash = $ExpectedHash; ActualHash = $actualHash } `
                -MITRE @("T1565.001")
            return
        }

        $old = Get-Content $BaselinePath -Raw | ConvertFrom-Json

        try {
            $created = if ($old.Timestamp -is [datetime]) { $old.Timestamp } else { [datetime]::Parse($old.Timestamp, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
            $lastWrite = (Get-Item $BaselinePath).LastWriteTime
            if ($lastWrite -gt $created.ToLocalTime().AddMinutes(5)) {
                Add-Finding -Severity "INFO" -Category "Baseline" `
                    -Title "Baseline Modified After Creation" `
                    -Description "The baseline file '$BaselinePath' was last written on $lastWrite, after the snapshot it contains was taken ($($created.ToLocalTime())). If you did not edit or copy it, it may have been tampered with." `
                    -Remediation "Verify the baseline with -BaselineHash, or recreate it on a known-clean system with -CreateBaseline." `
                    -Details @{ Path = $BaselinePath; Created = $created; LastWriteTime = $lastWrite; Sha256 = $actualHash } `
                    -MITRE @("T1565.001")
            }
        } catch {
            Write-Verbose "Could not check baseline modification time: $_"
        }

        $baselineAge = ""
        try {
            $bts = [datetime]::Parse($old.Timestamp)
            $age = (Get-Date) - $bts
            if ($age.TotalDays -ge 1) {
                $baselineAge = " ($([math]::Floor($age.TotalDays)) days ago)"
            } else {
                $baselineAge = " ($([math]::Floor($age.TotalHours))h ago)"
            }
        } catch {
            Write-Verbose "Could not parse baseline timestamp: $_"
        }

        Write-Status "Baseline: $($old.Timestamp)$baselineAge" -Color Gray

        $currentPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            ForEach-Object { $_.LocalPort } | Sort-Object -Unique
        $oldPorts = $old.ListeningPorts | ForEach-Object { $_.Port } | Sort-Object -Unique
        $newPorts = $currentPorts | Where-Object { $_ -notin $oldPorts -and $_ -lt 49152 }  # skip ephemeral range
        foreach ($port in $newPorts) {
            Add-Finding -Severity "WARNING" -Category "Baseline" `
                -Title "New Listening Port: $port" `
                -Description "Port $port was not listening in the baseline scan from $($old.Timestamp). This may indicate a newly installed service or backdoor." `
                -Remediation "Investigate what process is listening on this port: Get-NetTCPConnection -LocalPort $port -State Listen" `
                -Details @{ Port = $port; BaselineDate = $old.Timestamp } `
                -MITRE @("T1571")
        }

        $oldSvcNames = $old.Services | ForEach-Object { $_.Name }
        $currentSvcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($svc in $currentSvcs) {
            if ($svc.Name -match '_[0-9a-f]{5,}$') { continue }  # skip per-user session service instances (e.g. AarSvc_ddff8)
            if ($svc.Name -notin $oldSvcNames) {
                Add-Finding -Severity "WARNING" -Category "Baseline" `
                    -Title "New Service: $($svc.Name)" `
                    -Description "Service '$($svc.DisplayName)' ($($svc.Name)) was not present in the baseline. Path: '$($svc.PathName)'." `
                    -Remediation "Verify this service is legitimate: Get-Service '$($svc.Name)' | Format-List *" `
                    -Details @{ Name = $svc.Name; Path = $svc.PathName; Account = $svc.StartName; BaselineDate = $old.Timestamp } `
                    -MITRE @("T1543.003")
            }
        }

        $oldAccounts = $old.LocalAccounts | ForEach-Object { $_.Name }
        $currentAccounts = Get-LocalUser -ErrorAction SilentlyContinue
        foreach ($acct in $currentAccounts) {
            if ($acct.Name -notin $oldAccounts) {
                Add-Finding -Severity "CRITICAL" -Category "Baseline" `
                    -Title "New Local Account: $($acct.Name)" `
                    -Description "Account '$($acct.Name)' did not exist in the baseline from $($old.Timestamp). Unauthorized account creation is a strong compromise indicator." `
                    -Remediation "If unexpected, disable immediately: Disable-LocalUser -Name '$($acct.Name)'" `
                    -Details @{ Name = $acct.Name; Enabled = $acct.Enabled; BaselineDate = $old.Timestamp } `
                    -MITRE @("T1136.001")
            }
        }

        $oldRunEntries = $old.RunKeys | ForEach-Object { "$($_.Key)\$($_.Name)" }
        foreach ($keyPath in $script:RunKeyPaths) {
            try {
                $entries = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue
                if (-not $entries) { continue }
                $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -ne "(default)" } | ForEach-Object {
                    $fullKey = "$keyPath\$($_.Name)"
                    if ($fullKey -notin $oldRunEntries) {
                        Add-Finding -Severity "WARNING" -Category "Baseline" `
                            -Title "New Autorun Entry: $($_.Name)" `
                            -Description "Autorun entry '$($_.Name)' at '$keyPath' was not present in the baseline. Value: '$($_.Value)'." `
                            -Remediation "If unexpected, remove: Remove-ItemProperty -Path '$keyPath' -Name '$($_.Name)'" `
                            -Details @{ Key = $keyPath; Name = $_.Name; Value = $_.Value; BaselineDate = $old.Timestamp } `
                            -MITRE @("T1547.001")
                    }
                }
            } catch {
                Write-Verbose "Could not read Run key '$keyPath' for baseline comparison: $_"
            }
        }

        # Scheduled tasks (baselines from before this check have no ScheduledTasks key)
        if ($old.PSObject.Properties['ScheduledTasks']) {
            $oldTasks = @{}
            foreach ($t in @($old.ScheduledTasks)) {
                if ($t) { $oldTasks["$($t.Path)$($t.Name)"] = Get-TaskActionSignature $t.Actions }
            }
            $currentTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" })
            foreach ($task in $currentTasks) {
                $taskKey = "$($task.TaskPath)$($task.TaskName)"
                $signature = Get-TaskActionSignature $task.Actions
                if (-not $oldTasks.ContainsKey($taskKey)) {
                    Add-Finding -Severity "WARNING" -Category "Baseline" `
                        -Title "New Scheduled Task: $taskKey" `
                        -Description "Scheduled task '$taskKey' was not present in the baseline from $($old.Timestamp). Actions: '$signature'." `
                        -Remediation "If unexpected, disable it: Disable-ScheduledTask -TaskName '$($task.TaskName)' -TaskPath '$($task.TaskPath)'" `
                        -Details @{ TaskName = $task.TaskName; TaskPath = $task.TaskPath; Actions = $signature; BaselineDate = $old.Timestamp } `
                        -MITRE @("T1053.005")
                } elseif ($oldTasks[$taskKey] -ne $signature) {
                    Add-Finding -Severity "WARNING" -Category "Baseline" `
                        -Title "Scheduled Task Action Changed: $taskKey" `
                        -Description "The actions of scheduled task '$taskKey' changed since the baseline from $($old.Timestamp). Before: '$($oldTasks[$taskKey])'. Now: '$signature'." `
                        -Remediation "Verify the new action is legitimate. If not, disable the task: Disable-ScheduledTask -TaskName '$($task.TaskName)' -TaskPath '$($task.TaskPath)'" `
                        -Details @{ TaskName = $task.TaskName; TaskPath = $task.TaskPath; OldActions = $oldTasks[$taskKey]; NewActions = $signature; BaselineDate = $old.Timestamp } `
                        -MITRE @("T1053.005")
                }
            }
        }

        # Defender exclusions (skipped for older baselines without the key)
        if ($old.PSObject.Properties['DefenderExclusions'] -and $old.DefenderExclusions) {
            $prefs = $null
            try { $prefs = Get-MpPreference -ErrorAction SilentlyContinue } catch { Write-Verbose "Get-MpPreference failed: $_" }
            if ($prefs) {
                $exclusionTypes = @(
                    @{ Type = "Path";      Old = $old.DefenderExclusions.Paths;      Current = $prefs.ExclusionPath;      Param = "ExclusionPath" }
                    @{ Type = "Process";   Old = $old.DefenderExclusions.Processes;  Current = $prefs.ExclusionProcess;   Param = "ExclusionProcess" }
                    @{ Type = "Extension"; Old = $old.DefenderExclusions.Extensions; Current = $prefs.ExclusionExtension; Param = "ExclusionExtension" }
                )
                foreach ($et in $exclusionTypes) {
                    $oldValues = @(Select-MpExclusion $et.Old)
                    foreach ($value in @(Select-MpExclusion $et.Current)) {
                        if ($value -notin $oldValues) {
                            Add-Finding -Severity "WARNING" -Category "Baseline" `
                                -Title "New Defender Exclusion ($($et.Type)): $value" `
                                -Description "Defender exclusion '$value' ($($et.Type)) was not present in the baseline from $($old.Timestamp). Attackers add exclusions to hide malware from scanning." `
                                -Remediation "If you didn't add it, remove it: Remove-MpPreference -$($et.Param) '$value'" `
                                -Details @{ ExclusionType = $et.Type; Value = $value; BaselineDate = $old.Timestamp } `
                                -MITRE @("T1562.001")
                        }
                    }
                }
            }
        }

        Write-Status "Baseline comparison complete."
    } catch {
        Write-Status "Could not compare baseline: $_" -Color Yellow
    }
}
