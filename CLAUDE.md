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
5. Passes collected findings to `ReportGenerator.ps1` → opens HTML report in browser

### Finding System

All modules feed into a global `$script:Findings` ArrayList via the `Add-Finding` helper in `lib/Helpers.ps1`. Each finding carries: `Severity` (CRITICAL/WARNING/INFO), `Category`, `Title`, `Description`, `Remediation`, `Details`, and `MitreAttack` technique IDs.

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
- Optional API keys: VirusTotal (`vtApiKey`), AbuseIPDB (`abuseIpDbApiKey`)
- Suspicious parent→child process rules
- Per-module tuning parameters

`config/config.json` is gitignored to keep API keys local.

### Baseline System

`-CreateBaseline` snapshots ports, services, accounts, Run keys, scheduled tasks, and Defender exclusions to JSON. Baselines are **never auto-overwritten** — this is intentional to prevent a compromised system from poisoning its own baseline.

## Module Overview

| Module | Primary Checks |
|---|---|
| `Check-Processes.ps1` | Unsigned processes, suspicious parent→child chains, known malicious tool names |
| `Check-Network.ps1` | External connections, reverse-DNS, AbuseIPDB lookups, firewall rules |
| `Check-Accounts.ps1` | Hidden/new accounts, brute-force indicators, RDP history, LSA protection |
| `Check-FileSystem.ps1` | Modified system binaries, temp-dir executables, VirusTotal lookups, ADS, 8 persistence mechanisms |
| `Check-DefenseEvasion.ps1` | Cleared event logs, AMSI tampering, Defender status, ETW tampering |

## Contributing New Modules

See `CONTRIBUTING.md` for the full module authoring guide and test harness documentation.
