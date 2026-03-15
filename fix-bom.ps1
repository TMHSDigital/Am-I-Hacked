$enc = New-Object System.Text.UTF8Encoding $true
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
foreach ($f in (Get-ChildItem $root -Recurse -Filter '*.ps1')) {
    [System.IO.File]::WriteAllText($f.FullName, [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8), $enc)
}
Write-Host "BOM applied to all .ps1 files under $root"
