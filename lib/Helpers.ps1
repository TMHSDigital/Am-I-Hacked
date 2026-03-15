<#
.SYNOPSIS
    Shared helper functions for Am I Hacked modules.
#>

# ── Console Output Helpers ───────────────────────────────────────────────────

$script:ModuleIndex = 0
$script:ModuleTotal = 0
$script:SectionStart = $null
$script:IsAdmin = $false

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
    Write-Host $Message -ForegroundColor $Color
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
            $cc = @($script:Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
            $wc = @($script:Findings | Where-Object { $_.Severity -eq "WARNING" }).Count
            $ic = $fc - $cc - $wc
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
    if ($Obj -is [System.Collections.IList]) {
        return @($Obj | ForEach-Object { Invoke-RedactObject $_ })
    }
    if ($Obj -is [PSCustomObject]) {
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
            $mask = [byte](0xFF -shl (8 - $remainBits))
            if (($netBytes[$fullBytes] -band $mask) -ne ($targetBytes[$fullBytes] -band $mask)) {
                return $false
            }
        }

        return $true
    } catch {
        return $false
    }
}

function Test-IsPrivateIP {
    param([string]$IP)
    return ($IP -match "^10\." -or
            $IP -match "^172\.(1[6-9]|2[0-9]|3[01])\." -or
            $IP -match "^192\.168\." -or
            $IP -match "^127\." -or
            $IP -eq "::1" -or
            $IP -match "^fe80:")
}

function Get-FileSignature {
    param([string]$FilePath)
    # Force-load the module; suppress TypeData-conflict errors that occur in some PS 5.1 sessions
    Import-Module Microsoft.PowerShell.Security -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
    try {
        $sig = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue
        if ($sig) { return $sig }
    } catch { }
    # If the module still couldn't load, return a sentinel so callers don't treat it as "unsigned"
    return [PSCustomObject]@{ Status = "CheckFailed"; StatusMessage = "Signature check unavailable (PS.Security module could not be loaded)." }
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
                @(
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                ) | ForEach-Object {
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
                Paths      = @(try { (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath } catch { @() })
                Processes  = @(try { (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionProcess } catch { @() })
                Extensions = @(try { (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionExtension } catch { @() })
            }
        }

        $baseline | ConvertTo-Json -Depth 5 | Set-Content $FilePath -Encoding UTF8
        Write-Status "Baseline snapshot saved to: $FilePath"
    } catch {
        Write-Status "Could not export baseline: $_" -Color Yellow
    }
}

function Compare-Baseline {
    param([string]$BaselinePath)

    try {
        $old = Get-Content $BaselinePath -Raw | ConvertFrom-Json

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
        $runKeyPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($keyPath in $runKeyPaths) {
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

        Write-Status "Baseline comparison complete."
    } catch {
        Write-Status "Could not compare baseline: $_" -Color Yellow
    }
}
