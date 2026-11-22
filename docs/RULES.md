# Finding rule IDs

Every finding carries a stable **rule ID** (what kind of finding it is) and, where it applies, a **key** (which item it is about: a file path, account, port, ...). Both appear in the HTML report under each finding, in the JSON export (`RuleId`, `Key`), and in the SARIF export (`ruleId`, `partialFingerprints`).

Rule IDs are a stable contract: they are not renamed once released. Titles may change wording; use rule IDs in suppressions and automation.

## Suppressing by rule and key

```jsonc
"Suppressions": [
  // one specific item
  { "rule": "AIH-NET-UNUSUAL-LISTENER", "key": "6463|*", "reason": "Discord RPC" },
  // every finding of a rule (wildcards work in rule and key)
  { "rule": "AIH-PROC-UNQUOTED-SERVICE-PATH", "reason": "Vendor bug, no write access" },
  // the original title pattern still works
  { "pattern": "Autorun Entry: OneDrive*", "reason": "Expected" }
]
```

An entry matches when every field it sets matches (`pattern` against the title, `rule` against the rule ID, `key` against the key). `key` on its own suppresses nothing. Matching is case-insensitive and supports `*` and `?`. Keys are redacted together with the rest of the output in `-Redact` / `-CIMode`, so write suppressions against the keys your runs actually show.

Findings from modules that do not set a rule ID get `CUSTOM-<CATEGORY>-<TITLE>`, built from the title text before the first `:` or `(`.

This file is checked by `tests/Invoke-MockScan.ps1`: every rule ID in the code must be listed here, and vice versa.

## Processes

| Rule ID | Severity | Finding | Key |
|---|---|---|---|
| `AIH-PROC-UNSIGNED` | varies | Unsigned/Invalid Process: … | executable path |
| `AIH-PROC-SUSPICIOUS-CHAIN` | CRITICAL | Suspicious Process Chain: … → … | parent\|child process |
| `AIH-PROC-RUNNING-FROM-TEMP` | varies | UNSIGNED / UNVERIFIED / Trusted Signed Process in Temp, Process Running from Temp | executable path |
| `AIH-PROC-SERVICE-USER-DIR` | CRITICAL | Service Running from User Directory: … | service name |
| `AIH-PROC-UNQUOTED-SERVICE-PATH` | WARNING | Unquoted Service Path: … | service name |
| `AIH-PROC-SYSTEM-SERVICE-PATH` | INFO | SYSTEM Service Outside Standard Dirs: … | service name |
| `AIH-PROC-ATTACK-TOOL` | CRITICAL | Known Attack Tool Detected: … | process name |

## Network

| Rule ID | Severity | Finding | Key |
|---|---|---|---|
| `AIH-NET-HIGH-CONNECTION-COUNT` | varies | High Connection Count to … (… connections) | remote IP |
| `AIH-NET-UNCOMMON-REMOTE-PORT` | WARNING | Connection on Uncommon Port: … → …:… | process\|IP:port |
| `AIH-NET-MALICIOUS-IP` | varies | Known Malicious IP: … (Abuse Score: …%) | remote IP |
| `AIH-NET-INTEL-SKIPPED-OFFLINE` | INFO | Threat Intel Skipped (Offline Mode) | — |
| `AIH-NET-INTEL-SKIPPED-NO-KEY` | INFO | Threat Intel Skipped (No API Key) | — |
| `AIH-NET-UNUSUAL-LISTENER` | varies | Unusual Listening Port: … (…) | port\|process |
| `AIH-NET-REMOTE-ACCESS-LISTENER` | WARNING / INFO | WinRM Listener Active: port 5985/5986, SSH Listener Active | port |
| `AIH-NET-UNUSUAL-DNS-SERVER` | WARNING | Unusual DNS Server: … | DNS server |
| `AIH-NET-HOSTS-BLOCKS-SECURITY` | CRITICAL | Hosts File Blocking Security Sites | — |
| `AIH-NET-HOSTS-CUSTOM-ENTRIES` | INFO | Custom Hosts File Entries (… entries) | — |
| `AIH-NET-SYSTEM-PROXY` | WARNING | System Proxy Enabled: … | proxy server |
| `AIH-NET-PAC-URL` | varies | Proxy Auto-Config (PAC) URL Set: … | PAC URL |
| `AIH-NET-WINHTTP-PROXY` | WARNING | WinHTTP Proxy Configured: … | proxy |
| `AIH-NET-FIREWALL-DISABLED` | CRITICAL | Windows Firewall DISABLED: … Profile | firewall profile |

## Accounts

| Rule ID | Severity | Finding | Key |
|---|---|---|---|
| `AIH-ACCT-NO-PASSWORD-DATE` | INFO | No Password Set Date: … | account name |
| `AIH-ACCT-NEW-ACCOUNT` | WARNING | Recently Created Account: … | account name |
| `AIH-ACCT-NO-PASSWORD-REQUIRED` | WARNING | No Password Required: … | account name |
| `AIH-ACCT-PASSWORD-NEVER-EXPIRES` | INFO | Password Never Expires: … | account name |
| `AIH-ACCT-HIDDEN-ACCOUNT` | CRITICAL | Hidden Account Detected: … | account name |
| `AIH-ACCT-UNEXPECTED-ADMIN` | WARNING | Unexpected Admin: … | member name |
| `AIH-ACCT-ADMIN-GROUP` | INFO | Admin Group: … members | — |
| `AIH-ACCT-BRUTE-FORCE` | varies | Brute Force: … failures from … | source IP |
| `AIH-ACCT-FAILED-LOGONS` | INFO | Failed Logins (24h): … attempts | — |
| `AIH-ACCT-EVENTLOG-ACCESS-DENIED` | INFO | Event Log Access Denied | — |
| `AIH-ACCT-RDP-LOGONS` | WARNING | RDP Logins Detected: … sessions | — |
| `AIH-ACCT-MEMORY-DUMP` | CRITICAL | Suspicious Memory Dump: … | file path |
| `AIH-ACCT-HIVE-COPY` | CRITICAL | Registry Hive Copy Found: … | file path |
| `AIH-ACCT-NTDS-COPY` | CRITICAL | NTDS.dit Copy Found | file path |
| `AIH-ACCT-LSA-PROTECTION` | INFO | LSA Protection Not Enabled | — |

## FileSystem

| Rule ID | Severity | Finding | Key |
|---|---|---|---|
| `AIH-FS-CHECK-ERROR` | INFO | FileSystem Check Error: … | check function name |
| `AIH-FS-MODIFIED-SYSTEM-EXE` | CRITICAL | Modified Unsigned System Exe: … | file path |
| `AIH-FS-MODIFIED-SYSTEM-DLL` | WARNING | Modified Unsigned System DLL: … | file path |
| `AIH-FS-TEMP-FILE` | varies | Suspicious File in Temp: … | file path |
| `AIH-FS-SIGNED-APP-FILES-SKIPPED` | INFO | Signed Files in App Directories: … skipped | — |
| `AIH-FS-VT-SKIPPED-OFFLINE` | INFO | VirusTotal Check Skipped (Offline Mode) | — |
| `AIH-FS-VT-SKIPPED-NO-KEY` | INFO | VirusTotal Check Skipped (No API Key) | — |
| `AIH-FS-ALTERNATE-DATA-STREAM` | varies | Alternate Data Stream: …:… | file path:stream |
| `AIH-FS-BROWSER-PROFILE-ARCHIVE` | CRITICAL | Suspicious Archive in Browser Profile: … | file path |
| `AIH-FS-STEALER-OUTPUT` | CRITICAL | Stealer Output File: … | file path |
| `AIH-FS-WALLET-ACCESS` | WARNING | Recent Crypto Wallet Access: … | wallet folder |
| `AIH-FS-AUTORUN-SUSPICIOUS` | varies | Suspicious Autorun: … | registry key\value name |
| `AIH-FS-AUTORUN` | INFO | Autorun Entry: … | registry key\value name |
| `AIH-FS-STARTUP-FOLDER` | WARNING | Startup Folder Entry: … | file path |
| `AIH-FS-IFEO-DEBUGGER` | CRITICAL | IFEO Debugger Hijack: … | target executable |
| `AIH-FS-APPINIT-DLLS` | CRITICAL | AppInit_DLLs Loaded: … | AppInit_DLLs value |
| `AIH-FS-WINLOGON-SHELL` | CRITICAL | Winlogon Shell Hijacked | — |
| `AIH-FS-WINLOGON-USERINIT` | CRITICAL | Winlogon Userinit Modified | — |
| `AIH-FS-COM-HIJACK` | WARNING | COM Hijack: … | CLSID |
| `AIH-FS-WMI-BINDING` | varies | WMI Persistence Binding Found (…) | namespace\|filter\|consumer |
| `AIH-FS-WMI-COMMANDLINE-CONSUMER` | varies | WMI CommandLine Consumer: … (…) | namespace\|consumer name |
| `AIH-FS-WMI-SCRIPT-CONSUMER` | varies | WMI Script Consumer: … (…) | namespace\|consumer name |
| `AIH-FS-WMI-NAMESPACE` | WARNING | Non-Standard WMI Namespace: root\… | namespace |
| `AIH-FS-SCHEDULED-TASK` | varies | Suspicious Scheduled Task: … | task path and name |
| `AIH-FS-GHOST-TASK` | CRITICAL | Ghost Task (Missing SD): … | task path |
| `AIH-FS-HIDDEN-TASK` | WARNING | Task Not Visible to API: … | task path |
| `AIH-FS-BITS-JOB` | varies | Suspicious BITS Job: … | job name |
| `AIH-FS-DEFENDER-EXCLUSIONS-UNREADABLE` | INFO | Defender Exclusions Not Readable | — |
| `AIH-FS-DEFENDER-EXCLUSION-PATH` | varies | Defender Exclusion (Path): … | excluded path |
| `AIH-FS-DEFENDER-EXCLUSION-PROCESS` | WARNING | Defender Exclusion (Process): … | excluded process |
| `AIH-FS-DEFENDER-EXCLUSION-EXTENSION` | WARNING | Defender Exclusion (Extension): … | excluded extension |

## DefenseEvasion

| Rule ID | Severity | Finding | Key |
|---|---|---|---|
| `AIH-DE-SECURITY-LOG-CLEARED` | varies | Security Event Log Cleared: … | time cleared |
| `AIH-DE-EVENT-LOG-CLEARED` | WARNING | Event Log Cleared: … (…) | log name\|time cleared |
| `AIH-DE-DEFENDER-POLICY-DISABLED` | CRITICAL | Windows Defender Disabled via Policy | — |
| `AIH-DE-AMSI-DLL-SIGNATURE` | CRITICAL | AMSI DLL Signature Invalid | — |
| `AIH-DE-AMSI-NO-PROVIDERS` | CRITICAL | No AMSI Providers Registered | — |
| `AIH-DE-AMSI-DISABLED` | CRITICAL | AMSI Explicitly Disabled via Registry | — |
| `AIH-DE-PS-SCRIPTBLOCK-LOGGING` | INFO | PowerShell Script Block Logging Not Enabled | — |
| `AIH-DE-PS-MODULE-LOGGING` | INFO | PowerShell Module Logging Not Enabled | — |
| `AIH-DE-PS-TRANSCRIPTION` | INFO | PowerShell Transcription Not Enabled | — |
| `AIH-DE-DEFENDER-PASSIVE` | INFO | Defender Passive; … Active | active antivirus product(s) |
| `AIH-DE-DEFENDER-REALTIME-DISABLED` | CRITICAL | Defender Real-Time Protection Disabled | — |
| `AIH-DE-ANTIVIRUS-DISABLED` | CRITICAL | Antivirus Engine Disabled | — |
| `AIH-DE-DEFENDER-SIGNATURES-OUTDATED` | WARNING | Defender Signatures Outdated (… days) | — |
| `AIH-DE-ETW-SECURITY-AUTOLOGGER` | CRITICAL | Security ETW Autologger Disabled | — |
| `AIH-DE-ETW-AUTOLOGGER` | WARNING | ETW Autologger Disabled: … | autologger name |
| `AIH-DE-TAMPER-PROTECTION` | WARNING | Tamper Protection Not Fully Enabled | — |
| `AIH-DE-PS-PROFILE` | WARNING | Suspicious PowerShell Profile: … | profile path |
| `AIH-DE-UNKNOWN-ROOT-CA` | WARNING | Unknown Root CA: … | certificate thumbprint |

## FileSystem (VirusTotal)

| Rule ID | Severity | Finding | Key |
|---|---|---|---|
| `AIH-FS-VT-DETECTION` | varies | VirusTotal Detection: … (… engines) | file path |
| `AIH-FS-VT-UNKNOWN` | INFO | Unknown to VirusTotal: … | file path |

## Baseline

| Rule ID | Severity | Finding | Key |
|---|---|---|---|
| `AIH-BASE-HASH-MISMATCH` | WARNING | Baseline Hash Mismatch | — |
| `AIH-BASE-MODIFIED` | INFO | Baseline Modified After Creation | — |
| `AIH-BASE-NEW-PORT` | WARNING | New Listening Port: … | port |
| `AIH-BASE-NEW-SERVICE` | WARNING | New Service: … | service name |
| `AIH-BASE-NEW-ACCOUNT` | CRITICAL | New Local Account: … | account name |
| `AIH-BASE-NEW-AUTORUN` | WARNING | New Autorun Entry: … | registry key\value name |
| `AIH-BASE-NEW-TASK` | WARNING | New Scheduled Task: … | task path and name |
| `AIH-BASE-TASK-ACTION-CHANGED` | WARNING | Scheduled Task Action Changed: … | task path and name |
| `AIH-BASE-NEW-EXCLUSION` | WARNING | New Defender Exclusion (…): … | exclusion type\|value |

## General

| Rule ID | Severity | Finding | Key |
|---|---|---|---|
| `AIH-GEN-NOT-ADMIN` | INFO | Not Running as Administrator | — |
| `AIH-GEN-BASELINE-NOT-FOUND` | WARNING | Baseline File Not Found | — |
| `AIH-GEN-NO-BASELINE` | INFO | No Baseline Found | — |
| `AIH-GEN-SIGNATURES-DEGRADED` | WARNING | Signature Verification Degraded | — |
| `AIH-GEN-MODULE-ERROR` | INFO | Module Error | module name |
