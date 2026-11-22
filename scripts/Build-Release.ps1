<#
.SYNOPSIS
    Prepares a release: checks the version, extracts the changelog notes, and builds the zip.

.DESCRIPTION
    Used by .github/workflows/release.yml, and runnable locally to preview a release.
    Fails when the tag does not match $script:Version in AmIHacked.ps1 or when
    CHANGELOG.md has no section for the version. Writes to -OutputPath:
      Am-I-Hacked-<version>.zip         the tool (scripts, modules, config example, docs)
      Am-I-Hacked-<version>.zip.sha256  its SHA-256
      release-notes.md                  the CHANGELOG.md section for the version

.EXAMPLE
    .\scripts\Build-Release.ps1 -Tag v0.6.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Tag,
    [string]$OutputPath = "dist"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent

if ($Tag -notmatch '^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$') {
    Write-Error "Tag '$Tag' is not of the form v1.2.3 or v1.2.3-rc.1"
    exit 1
}
$version = $Matches[1]

$codeVersion = [regex]::Match((Get-Content (Join-Path $repoRoot "AmIHacked.ps1") -Raw), '\$script:Version\s*=\s*"([^"]+)"').Groups[1].Value
if ($codeVersion -ne $version) {
    Write-Error "Tag $Tag does not match `$script:Version '$codeVersion' in AmIHacked.ps1"
    exit 1
}

$changelog = (Get-Content (Join-Path $repoRoot "CHANGELOG.md") -Raw) -replace "`r`n", "`n"
$section = [regex]::Match($changelog, "(?ms)^## \[$([regex]::Escape($version))\][^\n]*\n(.*?)(?=^## \[|\z)")
if (-not $section.Success -or -not $section.Groups[1].Value.Trim()) {
    Write-Error "CHANGELOG.md has no '## [$version]' section with content"
    exit 1
}

if (-not [IO.Path]::IsPathRooted($OutputPath)) { $OutputPath = Join-Path $repoRoot $OutputPath }
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

$notes = $section.Groups[1].Value.Trim() + "`n`n**Full changelog**: [CHANGELOG.md](https://github.com/TMHSDigital/Am-I-Hacked/blob/$Tag/CHANGELOG.md)`n"
[IO.File]::WriteAllText((Join-Path $OutputPath "release-notes.md"), $notes, [Text.UTF8Encoding]::new($false))

# Stage the files a user needs to run the tool, under a versioned top-level folder
$name = "Am-I-Hacked-$version"
$stage = Join-Path ([IO.Path]::GetTempPath()) ("aih-release-" + [guid]::NewGuid())
$root = Join-Path $stage $name
New-Item -ItemType Directory -Force -Path $root | Out-Null
try {
    foreach ($item in @("AmIHacked.ps1", "lib", "modules", "config\config.example.json", "docs", "assets",
                        "README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md")) {
        $src = Join-Path $repoRoot $item
        if (-not (Test-Path $src)) { Write-Error "Missing release file: $item"; exit 1 }
        $dest = Join-Path $root $item
        New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
        Copy-Item $src $dest -Recurse
    }

    $zip = Join-Path $OutputPath "$name.zip"
    if (Test-Path $zip) { Remove-Item $zip }
    Compress-Archive -Path $root -DestinationPath $zip
    $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$zip.sha256", "$hash  $name.zip`n", [Text.UTF8Encoding]::new($false))
} finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Release $Tag ready in ${OutputPath}: $name.zip ($hash)"
