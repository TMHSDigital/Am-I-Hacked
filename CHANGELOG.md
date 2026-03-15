# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
