<# MODULE
Name: Accounts
Description: Account & Authentication
Category: Security
Author: Am I Hacked Project
#>

function Invoke-AccountsChecks {

    $maxAgeDays = if ($script:Config.AccountMaxAgeDays) { $script:Config.AccountMaxAgeDays } else { 7 }
    $maxEvents = if ($script:Config.MaxEventLogEntries) { $script:Config.MaxEventLogEntries } else { 1000 }

    # ── 1. Local Account Enumeration ─────────────────────────────────────

    Write-Status "Enumerating local user accounts..."

    try {
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue

        foreach ($user in $localUsers) {
            if ($user.Enabled -and $user.Description -notmatch "Built-in" -and $user.Description -notmatch "Default") {
                $age = (Get-Date) - $user.PasswordLastSet

                if ($user.PasswordLastSet -and $age.TotalDays -le $maxAgeDays) {
                    Add-Finding -Severity "WARNING" -Category "Account" `
                        -Title "Recently Created Account: $($user.Name)" `
                        -Description "Local account '$($user.Name)' was created or had its password set within the last $maxAgeDays days (Password set: $($user.PasswordLastSet)). Attackers create local accounts for persistent access." `
                        -Remediation "Verify this account is legitimate. If you didn't create it, disable it immediately: Disable-LocalUser -Name '$($user.Name)'" `
                        -Details @{
                            Username = $user.Name
                            Enabled = $user.Enabled
                            PasswordLastSet = $user.PasswordLastSet
                            LastLogon = $user.LastLogon
                            Description = $user.Description
                            PasswordRequired = $user.PasswordRequired
                            UserMayChangePassword = $user.UserMayChangePassword
                        } `
                        -MITRE @("T1136.001")
                }

                if (-not $user.PasswordRequired -and $user.Enabled) {
                    Add-Finding -Severity "WARNING" -Category "Account" `
                        -Title "No Password Required: $($user.Name)" `
                        -Description "Local account '$($user.Name)' does not require a password. This is a significant security risk." `
                        -Remediation "Set a strong password: Set-LocalUser -Name '$($user.Name)' -PasswordRequired `$true" `
                        -Details @{ Username = $user.Name; Enabled = $user.Enabled } `
                        -MITRE @("T1078.003")
                }

                if ($user.PasswordExpires -eq $null -and $user.Enabled -and $user.Name -ne "Administrator") {
                    Add-Finding -Severity "INFO" -Category "Account" `
                        -Title "Password Never Expires: $($user.Name)" `
                        -Description "Account '$($user.Name)' has a password that never expires." `
                        -Remediation "Consider setting a password expiration policy for better security hygiene." `
                        -MITRE @("T1078.003")
                }
            }

            if ($user.Name.EndsWith('$') -and $user.Enabled) {
                Add-Finding -Severity "CRITICAL" -Category "Account" `
                    -Title "Hidden Account Detected: $($user.Name)" `
                    -Description "Account '$($user.Name)' ends with '$' which is a technique used to hide accounts from normal enumeration. This is a strong indicator of compromise." `
                    -Remediation "Investigate and disable this account immediately. Check how it was created using Event Viewer." `
                    -Details @{ Username = $user.Name; Enabled = $user.Enabled; Created = $user.PasswordLastSet } `
                    -MITRE @("T1136.001","T1564.002")
            }
        }
    } catch {
        Write-Status "Could not enumerate local users: $_" -Color Yellow
    }

    # ── 2. Administrator Group Members ───────────────────────────────────

    Write-Status "Checking local Administrators group membership..."

    try {
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

        $expectedAdmins = @($env:USERNAME, "Administrator")

        foreach ($member in $adminGroup) {
            $memberName = $member.Name.Split('\')[-1]

            if ($memberName -notin $expectedAdmins -and $member.ObjectClass -eq "User") {
                Add-Finding -Severity "WARNING" -Category "Account" `
                    -Title "Unexpected Admin: $($member.Name)" `
                    -Description "User '$($member.Name)' ($($member.ObjectClass)) is a member of the local Administrators group. Verify this is intentional." `
                    -Remediation "If unexpected, remove with: Remove-LocalGroupMember -Group 'Administrators' -Member '$($member.Name)'" `
                    -Details @{
                        Name = $member.Name
                        SID = $member.SID
                        ObjectClass = $member.ObjectClass
                        PrincipalSource = $member.PrincipalSource
                    } `
                    -MITRE @("T1098")
            }
        }

        Add-Finding -Severity "INFO" -Category "Account" `
            -Title "Admin Group: $($adminGroup.Count) members" `
            -Description "Local Administrators group contains $($adminGroup.Count) member(s): $(($adminGroup | ForEach-Object { $_.Name }) -join ', ')" `
            -Details @{ Members = $adminGroup | ForEach-Object { $_.Name } }

    } catch {
        Write-Status "Could not check admin group (may need admin)." -Color Yellow
    }

    # ── 3. Failed Login Analysis ─────────────────────────────────────────

    Write-Status "Analyzing failed login attempts..."

    try {
        $failedLogins = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4625
        } -MaxEvents $maxEvents -ErrorAction SilentlyContinue

        if ($failedLogins) {
            $grouped = $failedLogins | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $data = $xml.Event.EventData.Data
                [PSCustomObject]@{
                    Time = $_.TimeCreated
                    TargetAccount = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    SourceIP = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                    LogonType = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                    FailReason = ($data | Where-Object { $_.Name -eq 'SubStatus' }).'#text'
                }
            }

            $byIP = $grouped | Group-Object SourceIP | Sort-Object Count -Descending

            foreach ($ipGroup in $byIP) {
                if ($ipGroup.Count -ge 10) {
                    $severity = if ($ipGroup.Count -ge 50) { "CRITICAL" } else { "WARNING" }
                    $recentAttempts = $ipGroup.Group | Select-Object -First 5

                    Add-Finding -Severity $severity -Category "Account" `
                        -Title "Brute Force: $($ipGroup.Count) failures from $($ipGroup.Name)" `
                        -Description "Detected $($ipGroup.Count) failed login attempts from IP $($ipGroup.Name). Targeted accounts: $(($ipGroup.Group | ForEach-Object { $_.TargetAccount } | Sort-Object -Unique) -join ', '). This may indicate a brute force attack." `
                        -Remediation "Block this IP in your firewall. If it's a local IP, investigate which device it belongs to. Enable account lockout policies." `
                        -Details @{
                            SourceIP = $ipGroup.Name
                            TotalAttempts = $ipGroup.Count
                            RecentAttempts = $recentAttempts
                            TargetAccounts = ($ipGroup.Group | ForEach-Object { $_.TargetAccount } | Sort-Object -Unique)
                        } `
                        -MITRE @("T1110.001")
                }
            }

            $last24h = $failedLogins | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) }
            if ($last24h.Count -gt 0) {
                Add-Finding -Severity "INFO" -Category "Account" `
                    -Title "Failed Logins (24h): $($last24h.Count) attempts" `
                    -Description "There have been $($last24h.Count) failed login attempts in the last 24 hours (out of $($failedLogins.Count) total in log)." `
                    -Details @{ Total = $failedLogins.Count; Last24h = $last24h.Count } `
                    -MITRE @("T1110")
            }
        }
    } catch {
        Write-Status "Could not read Security event log (requires admin)." -Color Yellow
        Add-Finding -Severity "INFO" -Category "Account" `
            -Title "Event Log Access Denied" `
            -Description "Cannot read the Security event log for failed login analysis. Re-run as Administrator." `
            -Remediation "Run this tool as Administrator to enable event log analysis."
    }

    # ── 4. RDP Session History ───────────────────────────────────────────

    Write-Status "Checking RDP session history..."

    try {
        $rdpLogins = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4624
        } -MaxEvents $maxEvents -ErrorAction SilentlyContinue | Where-Object {
            $xml = [xml]$_.ToXml()
            $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            $logonType -eq "10"
        }

        if ($rdpLogins -and $rdpLogins.Count -gt 0) {
            $rdpDetails = $rdpLogins | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $data = $xml.Event.EventData.Data
                [PSCustomObject]@{
                    Time = $_.TimeCreated
                    Account = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    SourceIP = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                    SourceHost = ($data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
                }
            }

            $uniqueSources = $rdpDetails | ForEach-Object { $_.SourceIP } | Sort-Object -Unique

            Add-Finding -Severity "WARNING" -Category "Account" `
                -Title "RDP Logins Detected: $($rdpLogins.Count) sessions" `
                -Description "Found $($rdpLogins.Count) Remote Desktop (RDP) login events from $($uniqueSources.Count) unique source(s): $($uniqueSources -join ', '). Review these for unauthorized access." `
                -Remediation "If RDP is not needed, disable it. If needed, use Network Level Authentication and limit access with firewall rules." `
                -Details @{
                    Sessions = $rdpDetails | Select-Object -First 20
                    UniqueSources = $uniqueSources
                } `
                -MITRE @("T1021.001")
        }
    } catch {}

    # ── 5. Event Log Clearing Detection ──────────────────────────────────

    Write-Status "Checking for event log clearing..."

    try {
        $logClears = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102 } -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($logClears) {
            foreach ($evt in $logClears) {
                $daysAgo = ((Get-Date) - $evt.TimeCreated).TotalDays
                $severity = if ($daysAgo -le 30) { "CRITICAL" } else { "WARNING" }

                Add-Finding -Severity $severity -Category "Account" `
                    -Title "Security Log Cleared: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" `
                    -Description "The Security event log was cleared on $($evt.TimeCreated). Account: $($evt.Properties[1].Value). Attackers clear logs to cover their tracks." `
                    -Remediation "Investigate what happened around this time. Check other log sources for correlated activity." `
                    -Details @{
                        TimeCleared = $evt.TimeCreated
                        Account = $evt.Properties[1].Value
                        DaysAgo = [math]::Round($daysAgo, 1)
                    } `
                    -MITRE @("T1070.001")
            }
        }

        $sysClears = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=104 } -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($sysClears) {
            foreach ($evt in $sysClears) {
                Add-Finding -Severity "WARNING" -Category "Account" `
                    -Title "System Log Cleared: $($evt.TimeCreated.ToString('yyyy-MM-dd'))" `
                    -Description "The System event log was cleared on $($evt.TimeCreated)." `
                    -Remediation "Investigate why this log was cleared." `
                    -MITRE @("T1070.001")
            }
        }
    } catch {}

    # ── 6. Credential Dumping Artifacts ──────────────────────────────────

    Write-Status "Checking for credential dumping artifacts..."

    $suspiciousDumps = @(
        "$env:TEMP\*.dmp",
        "$env:LOCALAPPDATA\Temp\*.dmp",
        "$env:SystemRoot\Temp\*.dmp",
        "$env:USERPROFILE\Desktop\*.dmp",
        "$env:USERPROFILE\Documents\*.dmp"
    )

    foreach ($pattern in $suspiciousDumps) {
        $dumps = Get-ChildItem $pattern -ErrorAction SilentlyContinue
        foreach ($dump in $dumps) {
            if ($dump.Length -gt 10MB) {
                Add-Finding -Severity "CRITICAL" -Category "Account" `
                    -Title "Suspicious Memory Dump: $($dump.Name)" `
                    -Description "Found large dump file '$($dump.FullName)' ($(Format-ByteSize $dump.Length)). Large .dmp files in temp/user directories may be LSASS memory dumps used for credential theft." `
                    -Remediation "Investigate this file. If it's an LSASS dump, your credentials are likely compromised. Change all passwords immediately." `
                    -Details @{
                        Path = $dump.FullName
                        Size = Format-ByteSize $dump.Length
                        Created = $dump.CreationTime
                        Modified = $dump.LastWriteTime
                    } `
                    -MITRE @("T1003.001")
            }
        }
    }

    $hiveCopies = @(
        "$env:TEMP\SAM", "$env:TEMP\SYSTEM", "$env:TEMP\SECURITY",
        "$env:USERPROFILE\Desktop\SAM", "$env:USERPROFILE\Desktop\SYSTEM",
        "$env:LOCALAPPDATA\Temp\SAM", "$env:LOCALAPPDATA\Temp\SYSTEM"
    )

    foreach ($hive in $hiveCopies) {
        if (Test-Path $hive) {
            Add-Finding -Severity "CRITICAL" -Category "Account" `
                -Title "Registry Hive Copy Found: $(Split-Path $hive -Leaf)" `
                -Description "Found a copy of the $(Split-Path $hive -Leaf) registry hive at '$hive'. This is a strong indicator of credential theft — attackers copy SAM/SYSTEM hives to extract password hashes offline." `
                -Remediation "Delete this file immediately and change all local account passwords. Investigate how this file was created." `
                -Details @{ Path = $hive } `
                -MITRE @("T1003.002")
        }
    }

    $ntdsLocations = @("$env:TEMP\ntds.dit", "$env:USERPROFILE\Desktop\ntds.dit", "$env:LOCALAPPDATA\Temp\ntds.dit")
    foreach ($ntds in $ntdsLocations) {
        if (Test-Path $ntds) {
            Add-Finding -Severity "CRITICAL" -Category "Account" `
                -Title "NTDS.dit Copy Found" `
                -Description "Found a copy of the Active Directory database (ntds.dit) at '$ntds'. This contains ALL domain credentials and is a catastrophic compromise indicator." `
                -Remediation "This is an emergency. Initiate incident response procedures immediately. All domain passwords should be considered compromised." `
                -Details @{ Path = $ntds } `
                -MITRE @("T1003.003")
        }
    }

    # ── 7. Credential Guard & LSA Protection Status ──────────────────────

    Write-Status "Checking credential protection status..."

    try {
        $lsaPPL = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
        if (-not $lsaPPL -or $lsaPPL.RunAsPPL -ne 1) {
            Add-Finding -Severity "INFO" -Category "Account" `
                -Title "LSA Protection Not Enabled" `
                -Description "LSASS process protection (RunAsPPL) is not enabled. This makes it easier for attackers to dump credentials from memory." `
                -Remediation "Enable LSA Protection: Set registry HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL to 1 and reboot." `
                -MITRE @("T1003.001")
        }
    } catch {}

}
