<#
.SYNOPSIS
    Static checks for every .ps1 in the repo: UTF-8 BOM, parse errors, and (optionally) PSScriptAnalyzer.
.DESCRIPTION
    Used by CI under both Windows PowerShell 5.1 and PowerShell 7, and runnable locally:
        .\tests\Invoke-StaticChecks.ps1                 # BOM + parse
        .\tests\Invoke-StaticChecks.ps1 -Analyzer       # + PSScriptAnalyzer (errors fail, warnings are listed)
    Exits with the number of failures.
#>
[CmdletBinding()]
param([switch]$Analyzer)

$repoRoot = Split-Path $PSScriptRoot -Parent
$failures = 0
$files = Get-ChildItem $repoRoot -Recurse -Filter "*.ps1" | Where-Object { $_.FullName -notmatch '\\\.(git|claude[^\\]*)\\' }

foreach ($f in $files) {
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    if (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) {
        Write-Host "MISSING BOM: $($f.FullName)" -ForegroundColor Red
        $failures++
    }
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) {
        Write-Host "PARSE ERROR: $($f.FullName):$($e.Extent.StartLineNumber): $($e.Message)" -ForegroundColor Red
        $failures++
    }
}
Write-Host "PowerShell $($PSVersionTable.PSVersion): checked $($files.Count) files for BOM and parse errors."

if ($Analyzer) {
    if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
        Write-Host "PSScriptAnalyzer is not installed." -ForegroundColor Red
        $failures++
    } else {
        $results = @(Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -Severity Error, Warning |
            Where-Object { $_.ScriptPath -notmatch '\\\.(git|claude[^\\]*)\\' })
        foreach ($r in ($results | Where-Object Severity -eq 'Warning' | Group-Object RuleName | Sort-Object Count -Descending)) {
            Write-Host ("  warning {0,4}  {1}" -f $r.Count, $r.Name)
        }
        foreach ($r in ($results | Where-Object Severity -eq 'Error')) {
            Write-Host "ANALYZER ERROR: $($r.ScriptPath):$($r.Line): [$($r.RuleName)] $($r.Message)" -ForegroundColor Red
            $failures++
        }
        Write-Host "PSScriptAnalyzer: $(@($results | Where-Object Severity -eq 'Error').Count) errors, $(@($results | Where-Object Severity -eq 'Warning').Count) warnings."
    }
}

if ($failures -gt 0) { Write-Host "$failures static check failure(s)." -ForegroundColor Red } else { Write-Host "Static checks passed." -ForegroundColor Green }
exit $failures
