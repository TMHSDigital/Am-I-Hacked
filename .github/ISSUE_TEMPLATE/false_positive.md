---
name: False Positive
about: Report a finding that is incorrectly flagged as suspicious
title: "[FP] "
labels: false-positive
assignees: ''
---

## Finding Details
- **Title**: (e.g., "Unsigned/Invalid Process: example.exe")
- **Severity**: CRITICAL / WARNING / INFO
- **Category**: Process / Network / Account / FileSystem / DefenseEvasion
- **MITRE Tag**: (e.g., T1036.001)

## Why It's a False Positive
<!-- Explain why this finding is incorrect. What is the legitimate software/service? -->

## Suggested Fix
<!-- How should the detection be adjusted? Options: -->
- [ ] Add to default whitelist
- [ ] Adjust severity logic
- [ ] Add additional context/checks
- [ ] Other: ...

## Environment
- **OS**: Windows 10 / 11 (Build: )
- **Am I Hacked Version**:
- **Software Triggering FP**: (name, version, publisher)

## Evidence
<!-- Include any of the following to help verify: -->
- Digital signature info: `Get-AuthenticodeSignature "path\to\file"`
- Version info: `[System.Diagnostics.FileVersionInfo]::GetVersionInfo("path")`
- Screenshot of the finding in the report
