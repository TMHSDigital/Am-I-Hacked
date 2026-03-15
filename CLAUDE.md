# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**Am I Hacked?** is a zero-dependency PowerShell security assessment tool for Windows 10/11. It runs a suite of security checks, maps findings to MITRE ATT&CK techniques, and produces a self-contained interactive HTML report.

## Common Commands

```powershell
# Run a full scan (requires admin)
.\AmIHacked.ps1

# Run with specific modules skipped
.\AmIHacked.ps1 -SkipModules Network,Accounts

# Create a clean baseline snapshot
.\AmIHacked.ps1 -CreateBaseline

# Compare current state against a baseline
.\AmIHacked.ps1 -BaselinePath .\baseline_2024.json

# Run in offline mode (no threat intel API calls)
.\AmIHacked.ps1 -Offline

# Export findings as JSON
.\AmIHacked.ps1 -ExportJson

# Mask operator identity in all output
.\AmIHacked.ps1 -Redact

# CI / AI agent mode (structured output, no browser, auto-redact)
.\AmIHacked.ps1 -CIMode -ExportJson -Offline

# Run the test harness (creates mock IOCs, validates detections)
.\tests\Invoke-MockScan.ps1

# Set up custom config
Copy-Item config/config.example.json config/config.json
```

There is no formal CI system — testing is done manually via the mock scan harness.

## Architecture

### Entry Point & Orchestration

`AmIHacked.ps1` is the orchestrator. It:
1. Loads `lib/Helpers.ps1` and `lib/ReportGenerator.ps1`
2. Reads config from `config/config.json` (falls back to built-in defaults if absent)
3. Auto-discovers and dot-sources every `modules/Check-*.ps1`
4. Calls each module's `Invoke-{ModuleName}Checks` function in sequence
5. Passes collected findings to `ReportGenerator.ps1` → opens HTML report in browser (suppressed in `-CIMode`)

### Finding System

All modules feed into a global `$script:Findings` ArrayList via the `Add-Finding` helper in `lib/Helpers.ps1`. Each finding carries: `Severity` (CRITICAL/WARNING/INFO), `Category`, `Title`, `Description`, `Remediation`, `Details`, and `MITRE` (string array of technique IDs).

### Module System

Modules in `modules/` are self-contained. Each must have:
- A metadata comment block (Name, Description, Category, Author)
- A single exported function named `Invoke-{ModuleName}Checks`

Adding a new `modules/Check-Foo.ps1` with `Invoke-FooChecks` is all that's needed — no registration required.

### Key Libraries

- **`lib/Helpers.ps1`** — Console output formatting, `Add-Finding`, baseline export/compare/diff, file signature verification, IP validation, trust-list lookups.
- **`lib/ReportGenerator.ps1`** — Generates the self-contained HTML report. Embeds all CSS/JS inline. Includes severity filtering, MITRE ATT&CK badge links, copy-paste remediation commands, and a "Terminal Mode" theme.

### Configuration (`config/config.json`)

Copied from `config/config.example.json`. Controls:
- Trusted company/publisher whitelists
- Trusted IP/domain whitelists
- Optional API keys: VirusTotal (`VirusTotalAPIKey`), AbuseIPDB (`AbuseIPDBKey`)
- Suspicious parent→child process rules
- Per-module tuning parameters

`config/config.json` is gitignored to keep API keys local.

### Baseline System

`-CreateBaseline` snapshots ports, services, accounts, Run keys, scheduled tasks, and Defender exclusions to JSON. Baselines are **never auto-overwritten** — this is intentional to prevent a compromised system from poisoning its own baseline.

### Redaction System

`-Redact` masks operator identity (computer name, username, domain, profile paths) in all output. Implemented via two functions in `lib/Helpers.ps1`:

- `Invoke-Redact` — string replacement using `$script:RedactMap` (populated in `AmIHacked.ps1` bootstrap)
- `Invoke-RedactObject` — recursively redacts strings in hashtables, arrays, and PSCustomObjects

Redaction is applied at two choke points:
1. `Add-Finding` — redacts Title, Description, Remediation, and Details before storing/printing
2. `$script:SystemInfo` — redacts ComputerName, UserName, Domain after collection

Individual modules do not need to handle redaction.

### CI / AI Agent Mode

`-CIMode` makes the tool usable by AI terminal agents and CI pipelines:

- Suppresses ASCII banner (plain-text header instead) and browser auto-open
- Auto-enables `-Redact` so operator identity is never leaked
- Prints a JSON summary to stdout after all output, delimited by `---AMIHACKED-SUMMARY-JSON---`
- Exits with structured code: 0 = clean, 1 = warnings, 2 = critical

Non-interactive environments auto-enable these behaviors via `[Environment]::UserInteractive`.

Recommended invocation from an AI agent:

```powershell
.\AmIHacked.ps1 -CIMode -ExportJson -Offline
```

To parse the summary programmatically:

```powershell
$output = .\AmIHacked.ps1 -CIMode -ExportJson 2>&1
$jsonLine = ($output -join "`n" -split "---AMIHACKED-SUMMARY-JSON---")[-1].Trim()
$summary = $jsonLine | ConvertFrom-Json
```

`$PSScriptRoot` is empty during `param()` evaluation when invoked via `powershell.exe -File`. Path parameter defaults (`OutputPath`, `ConfigPath`) use empty strings and are resolved in the script body after the `$PSScriptRoot` fallback runs.

## Module Overview

| Module | Primary Checks |
|---|---|
| `Check-Processes.ps1` | Unsigned processes, suspicious parent→child chains, known malicious tool names |
| `Check-Network.ps1` | External connections, reverse-DNS, AbuseIPDB lookups, firewall rules |
| `Check-Accounts.ps1` | Hidden/new accounts, brute-force indicators, RDP history, LSA protection |
| `Check-FileSystem.ps1` | Modified system binaries, temp-dir executables, VirusTotal lookups, ADS, 8 persistence mechanisms |
| `Check-DefenseEvasion.ps1` | Cleared event logs, AMSI tampering, Defender status, ETW tampering |

## Code Conventions

- All `.ps1` files **must** be saved with UTF-8 BOM encoding. PowerShell 5.1 defaults to Windows-1252, which corrupts non-ASCII characters (checkmarks, box-drawing) and causes parse errors.
- See `CONTRIBUTING.md` for the full module authoring guide and test harness documentation.
