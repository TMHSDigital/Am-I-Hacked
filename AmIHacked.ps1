<#
.SYNOPSIS
    Am I Hacked? - Comprehensive Windows Security Assessment Tool
.DESCRIPTION
    Runs a battery of security checks across multiple domains including:
      - Process & Service Analysis
      - Network Indicators
      - Account & Authentication
      - File System Red Flags
      - Defense Evasion Detection
    Generates an HTML report with findings categorized as CRITICAL, WARNING, or INFO.
.PARAMETER OutputPath
    Directory for the HTML report. Defaults to .\reports
.PARAMETER SkipModules
    Array of module names to skip (e.g., 'Network','FileSystem')
.PARAMETER ConfigPath
    Path to config.json for whitelists and API keys. Defaults to .\config\config.json
    Copy config\config.example.json to config\config.json to customize.
.PARAMETER Offline
    Disable all API calls (VirusTotal, AbuseIPDB). Rely purely on local heuristics.
.PARAMETER BaselinePath
    Path to a previous baseline JSON for diff comparison.
.PARAMETER CreateBaseline
    Export a baseline snapshot of the current system state. Run this on a known-clean system first.
.PARAMETER ExportJson
    Emit findings as a JSON file alongside the HTML report.
.PARAMETER VerboseOutput
    Enable verbose console output during scan
.NOTES
    Author: TM Hospitality Strategies / Am I Hacked Project
    License: MIT
    Requires: Windows 10/11, PowerShell 5.1+
    Run as Administrator for full results.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot "reports"),
    [string[]]$SkipModules = @(),
    [string]$ConfigPath = (Join-Path $PSScriptRoot "config\config.json"),
    [switch]$Offline,
    [string]$BaselinePath,
    [switch]$CreateBaseline,
    [switch]$ExportJson,
    [switch]$VerboseOutput
)

# ── Bootstrap ────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Continue"
$script:StartTime = Get-Date
$script:Findings = [System.Collections.ArrayList]::new()
$script:SystemInfo = @{}
$script:Config = @{}
$script:OfflineMode = $Offline.IsPresent

$script:Version = "0.3.3"

# ── Helpers (loaded first) ───────────────────────────────────────────────────

. (Join-Path $PSScriptRoot "lib\Helpers.ps1")

# ── Load Config (silent — summary printed after banner) ──────────────────────

if (Test-Path $ConfigPath) {
    try {
        $script:Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    } catch {
        $script:Config = Get-DefaultConfig
    }
} else {
    $script:Config = Get-DefaultConfig
}

# ── Admin Check ──────────────────────────────────────────────────────────────

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
$script:IsAdmin = $isAdmin

Write-Banner

# ── Post-Banner Status Lines ─────────────────────────────────────────────────

$companyCount = if ($script:Config.TrustedCompanies) { $script:Config.TrustedCompanies.Count } else { 0 }
$vtKey = if ($script:Config.VirusTotalAPIKey) { "VT" } else { $null }
$abKey = if ($script:Config.AbuseIPDBKey) { "AbuseIPDB" } else { $null }
$apis = @($vtKey, $abKey) | Where-Object { $_ }
$apiStr = if ($apis.Count -gt 0) { ", APIs: $($apis -join '+')" } else { ", no API keys" }
Write-Status "Config loaded ($companyCount trusted companies$apiStr)"

if ($script:OfflineMode) {
    Write-Status "OFFLINE MODE: API integrations disabled." -Color Yellow
}

if (-not $isAdmin) {
    Write-Status "Running without admin — some checks will be limited." -Color Yellow
    Add-Finding -Severity "INFO" -Category "General" -Title "Not Running as Administrator" `
        -Description "Some checks require elevated privileges for full results. Re-run as Administrator for comprehensive analysis." `
        -Remediation "Right-click PowerShell > Run as Administrator, then re-run this script."
}

# ── Collect System Info ──────────────────────────────────────────────────────

Write-Status "Collecting system information..."

$os = Get-CimInstance Win32_OperatingSystem
$script:SystemInfo = @{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    Domain       = $env:USERDOMAIN
    OSVersion    = $os.Caption
    OSBuild      = $os.BuildNumber
    LastBoot     = $os.LastBootUpTime
    IsAdmin      = $isAdmin
    ScanTime     = $script:StartTime
    PSVersion    = $PSVersionTable.PSVersion.ToString()
}

# ── Baseline Comparison ──────────────────────────────────────────────────────

$defaultBaselinePath = Join-Path (Join-Path $PSScriptRoot "reports") "baseline_latest.json"

if ($BaselinePath -and (Test-Path $BaselinePath)) {
    Write-Section "Baseline Comparison"
    Compare-Baseline -BaselinePath $BaselinePath
} elseif (-not $BaselinePath -and (Test-Path $defaultBaselinePath)) {
    Write-Section "Baseline Comparison"
    Compare-Baseline -BaselinePath $defaultBaselinePath
} elseif (-not $CreateBaseline) {
    Add-Finding -Severity "INFO" -Category "General" -Title "No Baseline Found" `
        -Description "No baseline snapshot exists for comparison. Run with -CreateBaseline on a known-clean system to enable change detection on future scans." `
        -Remediation ".\AmIHacked.ps1 -CreateBaseline"
}

# ── Dynamic Module Discovery ─────────────────────────────────────────────────

$modulesDir = Join-Path $PSScriptRoot "modules"
$modules = @()

if (Test-Path $modulesDir) {
    $modules = Get-ChildItem $modulesDir -Filter "Check-*.ps1" | ForEach-Object {
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
    }
}

# ── Run Modules ──────────────────────────────────────────────────────────────

$runnableModules = @($modules | Where-Object { $SkipModules -notcontains $_.Name })
$script:ModuleTotal = $runnableModules.Count + 1
$script:ModuleIndex = 0

$moduleNames = ($runnableModules | ForEach-Object { $_.Name }) -join ", "
Write-Status "Scanning $($runnableModules.Count) modules: $moduleNames"

foreach ($mod in $modules) {
    if ($SkipModules -contains $mod.Name) {
        Write-Status "SKIPPING: $($mod.Description)" -Color DarkGray
        continue
    }

    $modulePath = $mod.FullPath
    if (-not (Test-Path $modulePath)) {
        Write-Status "MODULE NOT FOUND: $modulePath" -Color Red
        continue
    }

    Write-Section $mod.Description
    try {
        . $modulePath
        $functionName = "Invoke-$($mod.Name)Checks"
        & $functionName
    } catch {
        Write-Host "  [" -NoNewline -ForegroundColor DarkGray
        Write-Host "X" -NoNewline -ForegroundColor Red
        Write-Host "] " -NoNewline -ForegroundColor DarkGray
        Write-Host "ERROR in $($mod.Name): $_" -ForegroundColor Red
        Add-Finding -Severity "INFO" -Category $mod.Name -Title "Module Error" `
            -Description "The $($mod.Description) module encountered an error: $_" `
            -Remediation "Check that all dependencies are available and you have appropriate permissions."
    }
}

# ── Generate Report ──────────────────────────────────────────────────────────

Write-SectionEnd
Write-Section "Generating Report"

. (Join-Path $PSScriptRoot "lib\ReportGenerator.ps1")

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = $script:StartTime.ToString("yyyy-MM-dd_HHmmss")
$reportFile = Join-Path $OutputPath "AmIHacked_$timestamp.html"

$duration = (Get-Date) - $script:StartTime

Generate-HtmlReport -Findings $script:Findings `
                    -SystemInfo $script:SystemInfo `
                    -OutputFile $reportFile `
                    -Duration $duration `
                    -Version $script:Version

Write-SectionEnd

# ── JSON Export ──────────────────────────────────────────────────────────────

if ($ExportJson) {
    $jsonFile = Join-Path $OutputPath "AmIHacked_$timestamp.json"
    @{
        Version    = $script:Version
        SystemInfo = $script:SystemInfo
        Findings   = $script:Findings
        Duration   = $duration.TotalSeconds
    } | ConvertTo-Json -Depth 5 | Set-Content $jsonFile -Encoding UTF8
    Write-Status "JSON export saved to: $jsonFile" -Color Green
}

# ── Baseline Snapshot (only when explicitly requested) ───────────────────────

if ($CreateBaseline) {
    Export-Baseline -OutputPath $OutputPath
    Write-Status "Baseline created. Future scans will auto-compare against it." -Color Green
}

# ── Summary ──────────────────────────────────────────────────────────────────

$critCount = @($script:Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$warnCount = @($script:Findings | Where-Object { $_.Severity -eq "WARNING" }).Count
$infoCount = @($script:Findings | Where-Object { $_.Severity -eq "INFO" }).Count
$totalCount = $script:Findings.Count

$verdict = "CLEAN"
$verdictColor = "Green"
if ($critCount -gt 0) {
    $verdict = "THREATS DETECTED"
    $verdictColor = "Red"
} elseif ($warnCount -gt 3) {
    $verdict = "SUSPICIOUS"
    $verdictColor = "Yellow"
} elseif ($warnCount -gt 0) {
    $verdict = "CAUTION"
    $verdictColor = "Yellow"
}

$durationStr = "$([math]::Round($duration.TotalSeconds, 1))s"
$w = 44

Write-Host ""
Write-Host ""
Write-Host "  ╔$('═' * $w)╗" -ForegroundColor DarkCyan
Write-Host "  ║" -NoNewline -ForegroundColor DarkCyan
$verdictPad = $verdict.PadLeft([math]::Floor(($w + $verdict.Length) / 2)).PadRight($w)
Write-Host $verdictPad -NoNewline -ForegroundColor $verdictColor
Write-Host "║" -ForegroundColor DarkCyan
Write-Host "  ╠$('═' * $w)╣" -ForegroundColor DarkCyan

function Write-SummaryLine { param($Label, $Value, $Color, $Width)
    $content = "$Label$Value"
    $innerWidth = $Width - 4
    $padded = $content.PadRight($innerWidth)
    Write-Host "  ║  " -NoNewline -ForegroundColor DarkCyan
    Write-Host $Label -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -NoNewline -ForegroundColor $Color
    $remaining = $innerWidth - $content.Length
    if ($remaining -gt 0) { Write-Host (' ' * $remaining) -NoNewline }
    Write-Host "  ║" -ForegroundColor DarkCyan
}

Write-SummaryLine "CRITICAL  " "$critCount" $(if ($critCount -gt 0) { "Red" } else { "Green" }) $w
Write-SummaryLine "WARNING   " "$warnCount" $(if ($warnCount -gt 0) { "Yellow" } else { "Green" }) $w
Write-SummaryLine "INFO      " "$infoCount" "DarkCyan" $w
Write-Host "  ║$(' ' * $w)║" -ForegroundColor DarkCyan

Write-SummaryLine "Total     " "$totalCount findings" "White" $w
Write-SummaryLine "Duration  " "$durationStr" "DarkGray" $w
Write-Host "  ║$(' ' * $w)║" -ForegroundColor DarkCyan
Write-SummaryLine "Report    " "See path below" "DarkGray" $w

Write-Host "  ╚$('═' * $w)╝" -ForegroundColor DarkCyan
Write-Host ""

if ($critCount -gt 0) {
    Write-Host "  ██ CRITICAL findings detected. Review the report immediately." -ForegroundColor Red
} elseif ($warnCount -eq 0 -and $critCount -eq 0) {
    Write-Host "  ✓ No threats detected. System appears clean." -ForegroundColor Green
}

Write-Host ""
Write-Host "  $reportFile" -ForegroundColor White
Write-Host ""

try {
    Start-Process $reportFile
} catch {
    Write-Status "Could not auto-open report. Open the path above manually." -Color Yellow
}
