---
name: Detection Request
about: Suggest a new detection or check for Am I Hacked?
title: "[DETECT] "
labels: enhancement, detection
assignees: ''
---

## Detection Summary
<!-- What should be detected? One-line summary. -->

## Threat Description
<!-- What attack technique or indicator does this detect? Why is it important? -->

## MITRE ATT&CK Mapping
- **Technique ID**: (e.g., T1547.001)
- **Tactic**: (e.g., Persistence, Defense Evasion)

## Implementation Suggestion
<!-- How would you implement this? Which module should it belong to? -->
- **Module**: Check-Processes / Check-Network / Check-Accounts / Check-FileSystem / Check-DefenseEvasion / New Module
- **Data Source**: (e.g., registry key, event log, WMI, file system)
- **Severity**: CRITICAL / WARNING / INFO

## Detection Logic (Pseudocode)
```powershell
# Example:
# $value = Get-ItemProperty "HKLM:\..." -Name "SomeKey"
# if ($value -eq "bad") { Add-Finding ... }
```

## False Positive Considerations
<!-- What legitimate scenarios could trigger this? How to filter them? -->

## References
- (Links to blog posts, MITRE pages, or threat reports)
