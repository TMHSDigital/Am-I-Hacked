# Contributing to Am I Hacked?

Thanks for considering a contribution. This guide covers module authoring, the test harness, and config contributions.

## Adding a New Module

### 1. Create the file

Drop `Check-YourModuleName.ps1` into the `modules/` directory. The orchestrator auto-discovers any file matching `Check-*.ps1`.

### 2. Add the metadata block

At the top of your file, include a metadata comment:

```powershell
<# MODULE
Name: YourModuleName
Description: What This Module Checks
Category: Security
Author: Your Name
#>
```

The `Description` field is displayed in the console and report. `Name` must match the `{Name}` portion of your filename (`Check-{Name}.ps1`).

### 3. Implement the function

Your file must contain a single function named `Invoke-{Name}Checks`:

```powershell
function Invoke-YourModuleNameChecks {
    Write-Status "Running your checks..."

    # Your detection logic here

    Add-Finding -Severity "WARNING" -Category "YourModuleName" `
        -Title "Something Suspicious" `
        -Description "Explain what was found and why it matters." `
        -Remediation "Remove-Whatever -Name 'thing'" `
        -Details @{ Key = "value" } `
        -MITRE @("T1547.001")

    Write-Status "YourModuleName analysis complete."
}
```

### 4. Key conventions

- **Severity levels**: `CRITICAL` = strong IOC requiring immediate action. `WARNING` = suspicious, needs investigation. `INFO` = informational, worth noting.
- **Remediation**: Include copy-pasteable PowerShell commands when possible. The report auto-detects cmdlet names and makes them clickable.
- **Error handling**: Use `-ErrorAction SilentlyContinue` for commands that may fail without admin. Wrap sections in `try/catch` and call `Write-Status` on failure.
- **Config access**: Reference `$script:Config` for whitelists and tuning parameters.
- **Offline mode**: Check `$script:OfflineMode` before making API calls.
- **No external dependencies**: PowerShell 5.1+ built-in cmdlets only.
- **MITRE ATT&CK**: Every finding should include a `-MITRE @("T1xxx.xxx")` array of relevant technique IDs.
- **Redaction**: Handled automatically by `Add-Finding`. Module authors do not need to mask sensitive data.
- **Non-interactive mode**: `$script:NonInteractive` is set when `-CIMode` is used or the environment is non-interactive. Modules do not need to check this -- it's handled at the orchestrator level.

## Running the Test Harness

```powershell
# From the repo root
.\tests\Invoke-MockScan.ps1

# Keep artifacts for debugging
.\tests\Invoke-MockScan.ps1 -KeepArtifacts
```

The test harness:
1. Creates safe mock IOCs (autorun entries, stealer-pattern files, double-extension files)
2. Runs `AmIHacked.ps1 -ExportJson -Offline`
3. Validates that expected findings appear in the JSON output
4. Validates HTML report structure (CRT toggle, copy buttons, etc.)
5. Cleans up all artifacts

Exit code is the number of failed tests (0 = all passed).

## Config Contributions

### Whitelists and trusted entities

Edit `config/config.example.json` to add (or `config/config.json` locally):

- **ProcessWhitelist**: Known-good process names (lowercase, no `.exe`)
- **TrustedIPs**: CIDR ranges or single IPs for legitimate services
- **TrustedPorts**: Expected listening ports
- **TrustedCompanies**: Version info `CompanyName` strings for legitimate software vendors
- **TrustedDomainSuffixes**: Domain suffixes (e.g., `.microsoft.com`) for reverse-DNS FP reduction
- **SuspiciousParentChild**: New parent-child process rules for malware detection

### Guidelines

- Whitelists should be conservative. Only add entries that generate false positives on a clean default Windows install.
- Include a comment or PR description explaining why the entry is needed.
- Test your config changes with the test harness before submitting.

## Code Style

- PowerShell verb-noun naming for functions
- Consistent indentation (4 spaces)
- Section headers with `# ── N. Section Name ──...` pattern
- Status messages via `Write-Status`, not `Write-Host`

## Submitting a PR

1. Fork the repo and create a feature branch
2. Add or modify your module/check
3. Run `.\tests\Invoke-MockScan.ps1` and ensure all tests pass
4. Submit a PR with:
   - What the check detects
   - False positive considerations
   - Any config additions needed
