# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.3] - 2026-03-15

### Added
- **AMSI registry checks** -- detects `AmsiEnable=0` (CRITICAL, T1562.001) and missing PowerShell Script Block Logging (INFO, T1562.002)
- **PS.Security preflight** -- detects when `Get-AuthenticodeSignature` is unavailable and emits a WARNING at scan startup listing affected checks
- **`-SkipModules Baseline`** -- baseline comparison is now skippable, enabling faster targeted scans without baseline drift noise
- **ASCII verdict box in CI mode** -- non-interactive output uses `+==+|` instead of Unicode box-drawing, preventing encoding issues in piped/agent output
- **Pre-commit hook** -- `.githooks/pre-commit` rejects commits with `.ps1` files missing UTF-8 BOM

### Fixed
- **Unsigned process false positives** -- `Check-Processes.ps1` now uses `TrustedAppDirs` from config to skip processes in trusted directories (e.g. Git for Windows)
- **Ephemeral port baseline noise** -- ports in the Windows dynamic range (49152-65535) are excluded from baseline diffs
- Added `Git\usr\bin` to `TrustedAppDirs` in `config.example.json`

## [0.4.2] - 2026-03-15

### Fixed
- **AMSI false CRITICAL** -- `Get-AuthenticodeSignature` fails silently in some PS 5.1 `-File` sessions; `Get-FileSignature` now returns a `CheckFailed` sentinel so callers distinguish module failures from unsigned files
- **Scanner self-contamination** -- `remoteIpMoProxy_*` temp files created by the scanner's own CIM/WMI calls are no longer flagged as suspicious
- **Stale COM registrations** -- HKCU COM overrides where the DLL no longer exists on disk are now skipped (inert registrations can't be exploited)
- **Known-legitimate scheduled tasks** -- OneDrive, Opera, Zoom, Discord, and Teams updater tasks are no longer flagged as persistence
- **Per-user session services** -- baseline diffs now skip Windows per-user service instances (e.g. `AarSvc_ddff8`) that change every login session
- **`$args` shadowing** -- renamed to `$taskArgs` in scheduled task checks to avoid shadowing PowerShell's automatic variable
- Restored Unicode box-drawing on verdict summary top border

## [0.4.1] - 2026-03-15

### Fixed
- **UTF-8 BOM** -- all `.ps1` files now use UTF-8 BOM encoding, fixing parse errors on PowerShell 5.1 where non-ASCII characters (checkmarks, box-drawing) were misinterpreted as string delimiters
- **`$PSScriptRoot` in `param()`** -- path parameter defaults no longer reference `$PSScriptRoot` (unavailable during `param()` evaluation with `powershell.exe -File`); resolved in the script body instead

## [0.4.0] - 2026-03-15

### Added
- **`-CIMode` switch** -- agent/CI-friendly output: suppresses ASCII banner and browser auto-open, auto-enables `-Redact`, prints a JSON summary to stdout (delimited by `---AMIHACKED-SUMMARY-JSON---`), and exits with structured code (0=clean, 1=warnings, 2=critical)
- **`$PSScriptRoot` fallback** -- fixes "Cannot bind argument" error when invoked via `powershell.exe -File`
- **Non-interactive auto-detection** -- `[Environment]::UserInteractive` check auto-enables CI behaviors in piped/headless environments
- CIMode test block in `tests/Invoke-MockScan.ps1` validating JSON summary and exit codes
- "CI / AI Agent Usage" section in README and "Using with AI Agents" section in CLAUDE.md

### Fixed
- Console verdict label `THREATS DETECTED` now reads `COMPROMISED` to match the HTML report

## [0.3.4] - 2026-03-15

### Added
- **`-Redact` switch** -- masks operator identity (computer name, username, domain, profile paths) in console output, HTML reports, and JSON exports; useful for screenshots and sharing reports publicly
- `Invoke-Redact` and `Invoke-RedactObject` helper functions in `lib/Helpers.ps1`

### Changed
- **Documentation overhaul** -- fixed incorrect API key names in CLAUDE.md (`vtApiKey` -> `VirusTotalAPIKey`, `abuseIpDbApiKey` -> `AbuseIPDBKey`), fixed `MitreAttack` -> `MITRE` field name, added missing config keys (`TrustedAppDirs`, `SuspiciousTempExtensions`) to README, fixed verdict label (`THREATS DETECTED` -> `COMPROMISED`), added `-MITRE` to CONTRIBUTING.md example
- Removed emoji from README heading
- Version bumped to 0.3.4

## [0.3.3] - 2026-03-15 -- Public Release

### Added
- `SECURITY.md` with vulnerability disclosure policy and scope
- `CLAUDE.md` for project documentation and AI-assisted development context

### Changed
- **Open-source release** -- fresh public repository with clean commit history and noreply author email
- **Config safety** -- renamed `config/config.json` to `config/config.example.json`; user config is now gitignored to prevent accidental API key commits
- **Console banner** -- replaced Unicode block-character ASCII art with standard-character ASCII banner for reliable terminal rendering
- **HTML report polish** -- removed all emoji, refined typography (Inter + JetBrains Mono), improved verdict banner with CSS-only icons, tightened spacing, more professional default appearance
- **README overhaul** -- reorganized sections, collapsed verbose blocks (Console Output, Project Structure) into details elements, replaced broken SVG banner with clean heading
- Removed personal utility scripts (`_run_scan.ps1`, `_fix_bom.ps1`)
- Added 10 GitHub repository topics for discoverability

## [0.3.0] - 2026-03-05

### Added
- **MITRE ATT&CK tagging** on all findings — technique IDs render as clickable badges linked to attack.mitre.org
- **Ghost scheduled tasks detection** — enumerates TaskCache registry for tasks with missing SD values or not visible to `Get-ScheduledTask`
- **BITS job abuse detection** — flags non-Microsoft URLs, raw IP targets, and suspended/error-state BITS jobs
- **Expanded WMI persistence check** — now also queries `root\default` namespace and enumerates all non-standard namespaces under `root\`
- **`-CreateBaseline` switch** — explicit opt-in for baseline export; baselines are no longer auto-saved on every run
- **`Test-IsTrustedSigner` helper** — validates a file has a valid digital signature from a trusted company before downgrading severity
- **Dual-theme report** — clean professional default, with a toggleable "Terminal Mode" for CRT scanlines, glitch title, and neon glow effects
- **No Baseline Found info** — emits an INFO finding when no baseline exists and `-CreateBaseline` is not used
- GitHub issue templates: bug report, false positive, detection request
- This CHANGELOG

### Changed
- **Baseline workflow** — removed unconditional `Export-Baseline` call from orchestrator; baseline export is now explicit via `-CreateBaseline`
- **Version info trust logic inverted** — unsigned binaries claiming a trusted company name are now WARNING/CRITICAL (possible impersonation), not INFO. Only files with valid signatures from trusted signers are downgraded.
- Report CRT toggle renamed from "CRT Mode" to "Terminal Mode"; effects are off by default (professional theme)
- Version bumped to 0.3.0

### Fixed
- **Baseline auto-save footgun** — previously every scan overwrote the baseline, potentially poisoning it with compromised-state data
- **False negative on spoofed version info** — unsigned executables with a trusted company in their version info were incorrectly downgraded to INFO

## [0.2.0] - 2026-03-04

### Added
- `-Offline` flag to disable all API calls (VirusTotal, AbuseIPDB)
- `-BaselinePath` for diff comparison against a previous system snapshot
- `-ExportJson` for machine-readable findings output
- Dynamic module discovery from `modules/` directory with metadata parsing
- Baseline export/import with diff for ports, services, accounts, Run keys, scheduled tasks, and Defender exclusions
- `Check-DefenseEvasion` module: event log clearing, AMSI integrity, Defender real-time protection, ETW tampering, tamper protection
- Advanced persistence checks: IFEO debugger injection, AppInit_DLLs, Winlogon Shell/Userinit hijacking, COM hijacking, WMI persistence
- Info-stealer artifact scan: browser profile archives, stealer output filenames, crypto wallet access patterns
- Reverse DNS for high-connection-count IPs with trusted domain downgrade
- Copy-to-clipboard for PowerShell remediation commands in the HTML report
- Retro-terminal/cyberpunk HTML report aesthetic
- `TrustedCompanies` and `TrustedDomainSuffixes` config options
- `tests/Invoke-MockScan.ps1` test harness
- `CONTRIBUTING.md`

### Changed
- Module loading switched from hardcoded to dynamic discovery
- False positive reduction for temp directory files using version info enrichment
- Report includes Expand All, Print Report, and CRT Mode buttons

## [0.1.0] - 2026-03-03

### Added
- Initial release
- Process & Service Analysis: unsigned process detection, suspicious parent-child relationships, temp directory processes, service path analysis, known attack tool detection
- Network Indicators: active connection analysis, AbuseIPDB integration, listening port audit, DNS configuration, hosts file check, proxy detection, firewall status
- Account & Authentication: local account enumeration, admin group audit, failed login analysis, RDP session history, credential dumping artifact detection, LSA protection check
- File System Red Flags: recently modified system binaries, suspicious files in temp/AppData, VirusTotal hash lookups, alternate data streams, autorun persistence, Defender exclusion audit
- Self-contained HTML report with severity filtering, collapsible categories, and technical detail expansion
- Configurable whitelists, thresholds, and API keys via `config.json`
