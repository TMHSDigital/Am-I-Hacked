# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.6.0] - 2026-11-22

### Added
- **Stable rule IDs and keys** -- every finding carries a rule ID (e.g. `AIH-FS-AUTORUN`, 101 in total, catalogued in `docs/RULES.md`) and a key naming the item it is about; both appear in the HTML report and JSON export (#20)
- **Rule/key suppressions** -- `Suppressions` entries can set `rule` and `key` as well as the title `pattern`; existing title patterns keep working (#20)
- **SARIF export** -- `-ExportSarif` writes a SARIF 2.1.0 log with rules, severity levels, fingerprints and file locations (#20)
- **Baseline integrity** -- `-CreateBaseline` prints the baseline's SHA-256; `-BaselineHash` makes a scan ignore a baseline that no longer matches, and scans report a baseline edited after it was created (#23)
- **Baseline diff of scheduled tasks and Defender exclusions** -- new tasks, changed task actions and new exclusions since the baseline are flagged (#12)
- **`-Modules` and `-ListModules`** -- run only some modules, list what exists; unknown names in `-Modules`/`-SkipModules` now produce a warning instead of being ignored (#28)
- **PAC and WinHTTP proxy detection** -- `AutoConfigURL` (user, machine and policy) and the machine-wide WinHTTP proxy are reported (#21)
- **PowerShell profile coverage** -- profile injection checks now read Windows PowerShell 5.1 and PowerShell 7 profiles, for all users (#22)
- **`CommonRemotePorts` setting** -- outbound ports that never raise "Connection on Uncommon Port" (#2)
- **CI** -- GitHub Actions runs BOM/parse checks under PowerShell 5.1 and 7, PSScriptAnalyzer, and the mock scan harness on every push (#27); pushing a version tag publishes a release with a zip and its SHA-256

### Changed
- **Root CA check** -- certificates are compared against Microsoft's trusted root list instead of name fragments, ending false "Unknown Root CA" findings for default Windows roots (#15)
- **Third-party antivirus** -- when another AV is active, Defender being passive is reported as one INFO instead of two CRITICALs (#7)
- **Severity escalation** -- a milder rule can no longer downgrade an autorun or scheduled task finding that an earlier rule rated CRITICAL (#6)
- **VirusTotal** -- lookups are capped by `MaxVTLookups` (counting every request), and rejected keys and rate limits are reported (#24)
- **FileSystem module** -- split into one function per check; a failing check records an INFO and the rest still run (#18)
- **Private address ranges** -- APIPA (169.254/16), CGNAT (100.64/10) and IPv6 ULA (fc00::/7) addresses count as private (#31)
- **README** -- rewritten, with a results guide, privacy table, FAQ, screenshots and an animated demo

### Fixed
- Trusted IP ranges with non-byte-aligned prefixes (`/12`, `/20`) never matched (#29)
- `-Redact`/`-CIMode` turned numbers, booleans and dates in finding details into empty objects, and one-item lists into single values (#30, #32)
- Failed signature checks were reported as unsigned binaries (#3)
- Normal outbound HTTPS and DNS connections raised "Connection on Uncommon Port" (#2)
- Report counts were wrong when a finding had only one severity (#1)
- WMI persistence binding count, default binding and remediation (#4); WMI checks now use `Get-CimInstance` (#14)
- Defender's non-admin exclusion placeholder was reported as an exclusion (#5)
- Ad-block hosts entries were flagged as blocking security sites (#8)
- Each event log clear is reported once (#9); RDP logons are filtered in the event log query (#13)
- Accounts without `PasswordLastSet` stopped account enumeration (#10)
- The Security module was re-imported for every signature check (#17)
- Smaller count, duplicate-finding and message issues (#25)

### Security
- The HTML report loads nothing from the network (no web fonts) and sets a Content-Security-Policy (#26)
- Hardened how finding data is written into the HTML report
- `-Redact` now also covers the report path, CI summary and status lines (#11)

## [0.5.0] - 2026-03-16

### Added
- **PowerShell profile injection detection** -- scans all four `$PROFILE` paths for suspicious patterns (IEX, encoded commands, download cradles, etc.) and emits WARNING + T1546.013
- **Root certificate store anomaly detection** -- compares `Cert:\LocalMachine\Root` against 46 well-known CA name fragments; flags unknown root CAs as WARNING + T1553.004 (catches rogue MITM certs)
- **Category breakdown chart in HTML report** -- stacked horizontal bar chart showing finding counts per module/category, placed between the stats grid and system info
- **Improved remediation click-to-copy** -- regex now also matches system commands (`sfc`, `netsh`, `reg`, `certutil`, `dism`, etc.) and the `Import-` verb prefix

### Changed
- Version bumped to 0.5.0
- SECURITY.md updated to mark 0.5.x as supported, 0.3.x as unsupported

## [0.4.9] - 2026-03-15

### Added
- **WinRM listener detection** -- flags ports 5985/5986 if not in TrustedPorts (WARNING, T1021.006)
- **SSH listener detection** -- flags port 22 if not in TrustedPorts (INFO, T1021.004)
- **Test assertions** -- `Assert-FindingCount` for Network and DefenseEvasion modules

### Fixed
- **TrustedCompanies config drift** -- `Get-DefaultConfig` expanded from 9 to 38 entries, synced with `config.example.json`
- **Report HTML injection hardening** -- finding details now use `[System.Net.WebUtility]::HtmlEncode()` instead of manual `<`/`>` replacement
- **Score formula documented** -- added comment explaining penalty weights and cap behavior

## [0.4.8] - 2026-03-15

### Added
- **Configurable network/API limits** -- `BackdoorPorts`, `KnownDNSServers`, `AbuseIPDBMaxChecks`, `MaxVTLookups` config fields with sensible defaults; `commonPorts` in Check-Network.ps1 now uses `TrustedPorts` from config
- **Module Logging detection** -- Check-DefenseEvasion.ps1 flags when PowerShell Module Logging is not enabled (INFO, T1562.002)
- **Transcription detection** -- Check-DefenseEvasion.ps1 flags when PowerShell Transcription is not enabled (INFO, T1562.002)
- **Report suppressed count** -- HTML report stats grid shows a "Suppressed" card when findings have been suppressed via config

## [0.4.7] - 2026-03-15

### Added
- **Startup folder persistence check** -- scans per-user and all-user startup folders for executables, scripts, and shortcuts (WARNING, T1547.001)

### Fixed
- **22 empty catch blocks** replaced with `Write-Verbose` across Check-Accounts.ps1, Check-DefenseEvasion.ps1, Check-FileSystem.ps1, and lib/Helpers.ps1 so failures are traceable with `-Verbose`
- **Report filterFindings JS bug** -- implicit `event.target` replaced with explicit button element parameter, fixing potential strict-mode errors
- **Redundant if/else in Check-FileSystem.ps1** -- collapsed identical branches for trusted-company severity assignment

## [0.4.6] - 2026-03-15

### Added
- **ServiceWhitelist implementation** -- `ServiceWhitelist` config field is now applied in Check-Processes.ps1 service analysis, skipping whitelisted services from unquoted-path, user-directory, and SYSTEM-outside-standard-dirs checks
- **Test assertions** -- `Assert-FindingCount` helper, double-extension detection assertion, category coverage checks, severity/remediation/MITRE field validation, CIMode JSON `suppressed` key check

### Fixed
- **Error handling** -- replaced empty `catch {}` blocks with `Write-Verbose`/`Write-Status`/`Write-Warning` in Check-Network.ps1 (DNS reverse-lookup, AbuseIPDB), lib/Helpers.ps1 (Run key enumeration), and AmIHacked.ps1 (config parse fallback)
- **`New-DefaultConfig` `$PSScriptRoot` fix** -- default path now resolves via `Split-Path $PSScriptRoot -Parent` at call-time instead of during `param()` evaluation (which pointed to `lib/` instead of project root)

## [0.4.5] - 2026-03-15

### Fixed
- **README CI JSON example** -- updated to include `suppressed` key and correct version
- **SECURITY.md** -- added 0.4.x to supported versions table
- **Dead code cleanup** -- removed unused `Get-ProcessParentId`, `Get-ProcessCommandLine` from Helpers.ps1, unused `$maxPenalty` from ReportGenerator.ps1, unused `$Color` parameter from CI summary writer
- **Redundant guard in Check-Processes.ps1** -- removed unreachable `System32 + whitelist` check (already handled by earlier whitelist guard)
- **`Get-DefaultConfig` missing fields** -- added `TrustedAppDirs` and `Suppressions` defaults so configless runs don't silently skip filtering

### Changed
- **`fix-bom.ps1` now tracked** -- removed from `.gitignore` and updated to use `$PSScriptRoot` instead of hardcoded path; new clones now include the BOM-fix utility referenced by the pre-commit hook and CONTRIBUTING.md

## [0.4.4] - 2026-03-15

### Added
- **Finding suppression system** -- `Suppressions` array in config lets users acknowledge known-benign findings by title pattern (wildcard `-like` matching). Suppressed count appears in summary box and CI JSON output.

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
