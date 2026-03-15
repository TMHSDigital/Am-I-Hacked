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

# ── Setup: Create mock artifacts ─────────────────────────────────────────────

Write-Host "`n  ╔══════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║   Am I Hacked? — Test Harness            ║" -ForegroundColor Magenta
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Magenta

$testTempDir = Join-Path $env:TEMP "AmIHacked_Test_$(Get-Random)"
New-Item -ItemType Directory -Path $testTempDir -Force | Out-Null
$script:CleanupActions.Add({ Remove-Item $testTempDir -Recurse -Force -ErrorAction SilentlyContinue }) | Out-Null

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

    Assert-FindingExists -Findings $findings -TitlePattern "Stealer Output File.*passwords" -TestName "Detected stealer output file pattern"

    # Check that JSON structure is valid
    Write-TestHeader "JSON Structure Validation"
    if ($results.Version -and $results.SystemInfo -and $results.Findings -and $results.Duration) {
        Write-Host "  [PASS] JSON structure contains all required fields" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] JSON structure missing required fields" -ForegroundColor Red
        $script:TestsFailed++
    }

    # Check MITRE tags are present on findings
    Write-TestHeader "MITRE ATT&CK Tags"
    $mitreTagged = $findings | Where-Object { $_.MITRE -and $_.MITRE.Count -gt 0 }
    if ($mitreTagged -and $mitreTagged.Count -gt 0) {
        Write-Host "  [PASS] $($mitreTagged.Count) findings have MITRE ATT&CK tags" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] No findings have MITRE ATT&CK tags" -ForegroundColor Red
        $script:TestsFailed++
    }

    # Check baseline was exported (only when -CreateBaseline used)
    Write-TestHeader "Baseline Export"
    $baselineFile = Join-Path $outputDir "baseline_latest.json"
    if (Test-Path $baselineFile) {
        $baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json
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
