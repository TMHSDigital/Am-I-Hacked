<# MODULE
Name: Processes
Description: Process & Service Analysis
Category: Security
Author: Am I Hacked Project
#>

function Invoke-ProcessesChecks {
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $whitelist = @()
    if ($script:Config.ProcessWhitelist) {
        $whitelist = $script:Config.ProcessWhitelist | ForEach-Object { $_.ToLower() }
    }

    $serviceWhitelist = @()
    if ($script:Config.ServiceWhitelist) {
        $serviceWhitelist = $script:Config.ServiceWhitelist | ForEach-Object { $_.ToLower() }
    }

    $processCount = 0
    $flaggedCount = 0

    # ── 1. Unsigned / Suspicious Processes ────────────────────────────────

    Write-Status "Checking signatures... ($($processes.Count) processes)"

    $seenProcessPaths = @{}

    foreach ($proc in $processes) {
        $processCount++
        $procName = ($proc.Name -replace '\.exe$', '').ToLower()
        $procPath = $proc.ExecutablePath

        if ($whitelist -contains $procName) { continue }
        if (-not $procPath) { continue }
        if ($procPath -match '^C:\\Program Files\\WindowsApps\\') { continue }
        if ($script:Config.TrustedAppDirs) {
            $inTrustedDir = $false
            foreach ($dir in $script:Config.TrustedAppDirs) {
                if ($procPath -like "*$dir*") { $inTrustedDir = $true; break }
            }
            if ($inTrustedDir) { continue }
        }

        $pathKey = "$($proc.Name)|$procPath"
        if ($seenProcessPaths.ContainsKey($pathKey)) {
            $seenProcessPaths[$pathKey]++
            continue
        }
        $seenProcessPaths[$pathKey] = 1

        $sig = Get-FileSignature -FilePath $procPath
        if ($sig -and $sig.Status -ne "Valid") {
            $flaggedCount++
            $versionInfo = Get-FileVersionInfo -FilePath $procPath

            if (Test-IsTrustedSigner -Signature $sig -VersionInfo $versionInfo) {
                $severity = "INFO"
            } elseif ($versionInfo -and (Test-IsTrustedCompany $versionInfo.CompanyName)) {
                $severity = "CRITICAL"
            } elseif (-not $versionInfo -or (-not $versionInfo.CompanyName -and -not $versionInfo.OriginalFilename)) {
                $severity = "CRITICAL"
            } else {
                $severity = "WARNING"
            }

            Add-Finding -Severity $severity -Category "Process" `
                -Title "Unsigned/Invalid Process: $($proc.Name)" `
                -Description "Process '$($proc.Name)' (PID: $($proc.ProcessId)) is running from '$procPath' but its digital signature is: $($sig.Status).$(if ($versionInfo -and $versionInfo.CompanyName) { " Company: $($versionInfo.CompanyName)." })$(if ($severity -eq 'CRITICAL' -and $versionInfo -and (Test-IsTrustedCompany $versionInfo.CompanyName)) { ' UNSIGNED but claims trusted company — possible impersonation.' })" `
                -Remediation "Investigate this process. Check if it's legitimate software that isn't signed, or potentially malicious. Use 'Get-Process -Id $($proc.ProcessId) | Format-List *' for details." `
                -Details @{
                    PID = $proc.ProcessId
                    Path = $procPath
                    CommandLine = $proc.CommandLine
                    SignatureStatus = $sig.Status
                    Signer = $sig.SignerCertificate.Subject
                    VersionInfo = $versionInfo
                } `
                -MITRE @("T1036.001")
        }
    }

    foreach ($pathKey in $seenProcessPaths.Keys) {
        $count = $seenProcessPaths[$pathKey]
        if ($count -gt 1) {
            $flaggedCount += ($count - 1)
        }
    }

    Write-Status "Scanned $processCount processes, $flaggedCount unsigned."

    # ── 2. Suspicious Parent-Child Relationships ─────────────────────────

    Write-Status "Analyzing parent-child process relationships..."

    $suspiciousPairs = $script:Config.SuspiciousParentChild
    if (-not $suspiciousPairs) { $suspiciousPairs = @() }

    $pidLookup = @{}
    foreach ($p in $processes) {
        $pidLookup[$p.ProcessId] = $p
    }

    foreach ($proc in $processes) {
        $childName = $proc.Name.ToLower()
        $parentPid = $proc.ParentProcessId
        $parentProc = $pidLookup[$parentPid]

        if (-not $parentProc) { continue }
        $parentName = $parentProc.Name.ToLower()

        foreach ($pair in $suspiciousPairs) {
            if ($parentName -eq $pair.Parent.ToLower() -and $childName -eq $pair.Child.ToLower()) {
                Add-Finding -Severity "CRITICAL" -Category "Process" `
                    -Title "Suspicious Process Chain: $($parentProc.Name) → $($proc.Name)" `
                    -Description "Detected '$($parentProc.Name)' (PID: $parentPid) spawning '$($proc.Name)' (PID: $($proc.ProcessId)). This is a common technique used by macro-based malware and document exploits." `
                    -Remediation "This is a strong indicator of compromise. Immediately investigate: 1) Check if you opened a suspicious document, 2) Kill the child process, 3) Run a full antivirus scan, 4) Check for persistence mechanisms." `
                    -Details @{
                        ParentName = $parentProc.Name
                        ParentPID = $parentPid
                        ParentPath = $parentProc.ExecutablePath
                        ChildName = $proc.Name
                        ChildPID = $proc.ProcessId
                        ChildPath = $proc.ExecutablePath
                        ChildCommandLine = $proc.CommandLine
                    } `
                    -MITRE @("T1059.001","T1204.002")
            }
        }
    }

    # ── 3. Processes Running from Temp Directories ───────────────────────

    Write-Status "Checking for executables running from temp directories..."

    $tempPaths = @(
        $env:TEMP,
        $env:TMP,
        "$env:LOCALAPPDATA\Temp",
        "$env:APPDATA\Local\Temp",
        "$env:USERPROFILE\AppData\Local\Temp",
        "$env:SystemRoot\Temp",
        "$env:USERPROFILE\Downloads"
    ) | Where-Object { $_ } | Sort-Object -Unique

    foreach ($proc in $processes) {
        if (-not $proc.ExecutablePath) { continue }
        $path = $proc.ExecutablePath.ToLower()

        foreach ($tempDir in $tempPaths) {
            if ($path.StartsWith($tempDir.ToLower())) {
                $sig = Get-FileSignature -FilePath $proc.ExecutablePath
                $versionInfo = Get-FileVersionInfo -FilePath $proc.ExecutablePath

                if (Test-IsTrustedSigner -Signature $sig -VersionInfo $versionInfo) {
                    $severity = "INFO"
                    $title = "Trusted Signed Process in Temp: $($proc.Name)"
                } elseif ($versionInfo -and (Test-IsTrustedCompany $versionInfo.CompanyName)) {
                    $severity = "WARNING"
                    $title = "UNVERIFIED Process in Temp (claims trusted company): $($proc.Name)"
                } elseif (-not $sig -or $sig.Status -ne "Valid") {
                    $severity = "CRITICAL"
                    $title = "UNSIGNED Process in Temp: $($proc.Name)"
                } else {
                    $severity = "WARNING"
                    $title = "Process Running from Temp: $($proc.Name)"
                }

                Add-Finding -Severity $severity -Category "Process" `
                    -Title $title `
                    -Description "Process '$($proc.Name)' (PID: $($proc.ProcessId)) is executing from a temporary directory: '$($proc.ExecutablePath)'.$(if ($versionInfo -and $versionInfo.CompanyName) { " Company: $($versionInfo.CompanyName)." } else { " Legitimate software rarely runs from temp folders." })" `
                    -Remediation "Investigate this executable. Check its hash on VirusTotal. If you didn't intentionally run it, terminate the process and delete the file." `
                    -Details @{
                        PID = $proc.ProcessId
                        Path = $proc.ExecutablePath
                        CommandLine = $proc.CommandLine
                        TempDir = $tempDir
                        SignatureStatus = if ($sig) { $sig.Status } else { "Unknown" }
                        VersionInfo = $versionInfo
                    } `
                    -MITRE @("T1204.002")
                break
            }
        }
    }

    # ── 4. Service Analysis ──────────────────────────────────────────────

    Write-Status "Analyzing Windows services..."

    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue

    foreach ($svc in $services) {
        $svcPath = $svc.PathName
        if (-not $svcPath) { continue }
        if ($serviceWhitelist -contains $svc.Name.ToLower()) { continue }

        if ($svcPath -match "\\Temp\\" -or $svcPath -match "\\AppData\\" -or $svcPath -match "\\Users\\[^\\]+\\Desktop\\") {
            Add-Finding -Severity "CRITICAL" -Category "Process" `
                -Title "Service Running from User Directory: $($svc.Name)" `
                -Description "Service '$($svc.DisplayName)' ($($svc.Name)) binary is located in a user directory: '$svcPath'. Legitimate services are typically installed in Program Files or System32." `
                -Remediation "Investigate this service immediately. Malware often installs itself as a service in user-writable directories for persistence." `
                -Details @{
                    ServiceName = $svc.Name
                    DisplayName = $svc.DisplayName
                    Path = $svcPath
                    StartMode = $svc.StartMode
                    State = $svc.State
                    Account = $svc.StartName
                } `
                -MITRE @("T1543.003")
        }

        if ($svcPath -notmatch '^"' -and $svcPath -match ' ' -and $svcPath -notmatch '^[A-Za-z]:\\Windows\\') {
            Add-Finding -Severity "WARNING" -Category "Process" `
                -Title "Unquoted Service Path: $($svc.Name)" `
                -Description "Service '$($svc.DisplayName)' has an unquoted path with spaces: '$svcPath'. This is a known privilege escalation vulnerability (unquoted service path)." `
                -Remediation "Fix the service path by adding quotes. This is a vulnerability that allows attackers to hijack the service by placing a malicious executable in a parent directory." `
                -Details @{
                    ServiceName = $svc.Name
                    Path = $svcPath
                    StartMode = $svc.StartMode
                } `
                -MITRE @("T1574.009")
        }

        if ($svc.StartName -match "LocalSystem" -and $svcPath -notmatch "\\Windows\\" -and $svcPath -notmatch "\\Program Files") {
            Add-Finding -Severity "INFO" -Category "Process" `
                -Title "SYSTEM Service Outside Standard Dirs: $($svc.Name)" `
                -Description "Service '$($svc.DisplayName)' runs as SYSTEM but its binary is outside standard directories: '$svcPath'." `
                -Remediation "Verify this service is legitimate. Third-party services running as SYSTEM should be audited." `
                -Details @{
                    ServiceName = $svc.Name
                    Path = $svcPath
                    Account = $svc.StartName
                } `
                -MITRE @("T1543.003")
        }
    }

    # ── 5. Known-Suspicious Process Names ────────────────────────────────

    Write-Status "Checking for known-suspicious process names..."

    $suspiciousNames = @(
        "mimikatz", "lazagne", "procdump", "psexec",
        "cobaltstrike", "beacon", "meterpreter", "nc", "ncat",
        "rubeus", "seatbelt", "sharphound", "bloodhound",
        "certutil"
    )

    foreach ($proc in $processes) {
        $name = ($proc.Name -replace '\.exe$', '').ToLower()
        if ($suspiciousNames -contains $name) {
            Add-Finding -Severity "CRITICAL" -Category "Process" `
                -Title "Known Attack Tool Detected: $($proc.Name)" `
                -Description "Process '$($proc.Name)' (PID: $($proc.ProcessId)) matches a known offensive security/hacking tool. Path: '$($proc.ExecutablePath)'." `
                -Remediation "Unless you are actively performing authorized security testing, this is a strong indicator of compromise. Terminate the process, preserve the binary for analysis, and investigate how it was deployed." `
                -Details @{
                    PID = $proc.ProcessId
                    Path = $proc.ExecutablePath
                    CommandLine = $proc.CommandLine
                } `
                -MITRE @("T1588.002")
        }
    }

}
