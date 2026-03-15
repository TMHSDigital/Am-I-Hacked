<# MODULE
Name: Network
Description: Network Indicators
Category: Security
Author: Am I Hacked Project
#>

function Invoke-NetworkChecks {

    # ── 1. Active Network Connections ────────────────────────────────────

    Write-Status "Analyzing active network connections..."

    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -ne "::1" -and $_.RemoteAddress -ne "127.0.0.1" }

    $trustedPorts = @()
    if ($script:Config.TrustedPorts) { $trustedPorts = $script:Config.TrustedPorts }

    $procLookup = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $procLookup[$_.ProcessId] = $_
    }

    $externalIPs = @{}

    foreach ($conn in $connections) {
        $remoteIP = $conn.RemoteAddress
        $remotePort = $conn.RemotePort
        $localPort = $conn.LocalPort
        $procId = $conn.OwningProcess
        $proc = $procLookup[$procId]
        $procName = if ($proc) { $proc.Name } else { "Unknown (PID: $procId)" }

        if (Test-IsPrivateIP $remoteIP) { continue }
        if (Test-IsTrustedIP $remoteIP) { continue }

        if (-not $externalIPs.ContainsKey($remoteIP)) {
            $externalIPs[$remoteIP] = [System.Collections.ArrayList]::new()
        }
        $externalIPs[$remoteIP].Add(@{
            Process = $procName
            PID = $procId
            LocalPort = $localPort
            RemotePort = $remotePort
            Path = if ($proc) { $proc.ExecutablePath } else { "" }
        }) | Out-Null
    }

    foreach ($ip in $externalIPs.Keys) {
        $connList = $externalIPs[$ip]
        $uniqueProcs = $connList | ForEach-Object { $_.Process } | Sort-Object -Unique

        if ($connList.Count -ge 5) {
            $severity = "WARNING"
            $resolvedHost = $null

            try {
                $dnsResult = Resolve-DnsName $ip -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($dnsResult -and $dnsResult.NameHost) {
                    $resolvedHost = $dnsResult.NameHost
                    if (Test-IsTrustedDomain $resolvedHost) {
                        $severity = "INFO"
                    }
                }
            } catch {
                Write-Verbose "Reverse-DNS lookup failed for ${ip}: $_"
            }

            Add-Finding -Severity $severity -Category "Network" `
                -Title "High Connection Count to $ip ($($connList.Count) connections)" `
                -Description "Detected $($connList.Count) active connections to external IP $ip$(if ($resolvedHost) { " ($resolvedHost)" }) from processes: $($uniqueProcs -join ', '). High connection counts to a single IP may indicate data exfiltration or C2 beaconing." `
                -Remediation "Investigate this IP address. Check it against threat intelligence feeds (VirusTotal, AbuseIPDB). If unexpected, consider blocking it in your firewall." `
                -Details @{ Connections = $connList; ResolvedHostname = $resolvedHost } `
                -MITRE @("T1071.001")
        }

        $commonPorts = if ($script:Config.TrustedPorts) { $script:Config.TrustedPorts } else { @(80, 443, 8080, 8443, 993, 995, 587, 465, 53, 22) }
        foreach ($c in $connList) {
            if ($c.RemotePort -notin $commonPorts -and $c.RemotePort -lt 1024) {
                Add-Finding -Severity "WARNING" -Category "Network" `
                    -Title "Connection on Uncommon Port: $($c.Process) → ${ip}:$($c.RemotePort)" `
                    -Description "Process '$($c.Process)' (PID: $($c.PID)) has a connection to ${ip}:$($c.RemotePort). Low-numbered non-standard ports can indicate unusual protocols or C2 channels." `
                    -Remediation "Verify this connection is expected. Check the remote IP and port combination against known services." `
                    -Details $c `
                    -MITRE @("T1571")
            }
        }
    }

    # ── 2. AbuseIPDB Threat Intelligence Lookup ──────────────────────────

    $abuseKey = $script:Config.AbuseIPDBKey
    if (-not $script:OfflineMode -and $abuseKey -and $externalIPs.Count -gt 0) {
        Write-Status "Checking external IPs against AbuseIPDB..."

        $checkedCount = 0
        $maxChecks = if ($script:Config.AbuseIPDBMaxChecks) { [int]$script:Config.AbuseIPDBMaxChecks } else { 30 }

        foreach ($ip in $externalIPs.Keys) {
            if ($checkedCount -ge $maxChecks) {
                Write-Status "Rate limit reached ($maxChecks checks). Remaining IPs skipped." -Color Yellow
                break
            }

            try {
                $response = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check" `
                    -Method GET `
                    -Headers @{ Key = $abuseKey; Accept = "application/json" } `
                    -Body @{ ipAddress = $ip; maxAgeInDays = 90 } `
                    -ErrorAction Stop

                $data = $response.data
                $checkedCount++

                if ($data.abuseConfidenceScore -ge 50) {
                    $severity = if ($data.abuseConfidenceScore -ge 80) { "CRITICAL" } else { "WARNING" }
                    $procs = ($externalIPs[$ip] | ForEach-Object { $_.Process }) -join ", "

                    Add-Finding -Severity $severity -Category "Network" `
                        -Title "Known Malicious IP: $ip (Abuse Score: $($data.abuseConfidenceScore)%)" `
                        -Description "IP $ip has an abuse confidence score of $($data.abuseConfidenceScore)% on AbuseIPDB with $($data.totalReports) reports. Connected processes: $procs. ISP: $($data.isp), Country: $($data.countryCode)." `
                        -Remediation "Block this IP immediately in your firewall. Investigate the processes connecting to it. Consider this system potentially compromised." `
                        -Details @{
                            IP = $ip
                            AbuseScore = $data.abuseConfidenceScore
                            TotalReports = $data.totalReports
                            ISP = $data.isp
                            Country = $data.countryCode
                            Domain = $data.domain
                            UsageType = $data.usageType
                            ConnectedProcesses = $externalIPs[$ip]
                        } `
                        -MITRE @("T1071.001")
                }
            } catch {
                Write-Status "AbuseIPDB lookup failed for ${ip}: $_" -Color Yellow
            }
        }
        Write-Status "Checked $checkedCount IPs against AbuseIPDB."
    } elseif ($script:OfflineMode -and $externalIPs.Count -gt 0) {
        Add-Finding -Severity "INFO" -Category "Network" `
            -Title "Threat Intel Skipped (Offline Mode)" `
            -Description "Found $($externalIPs.Count) unique external IPs but offline mode is enabled. Re-run without -Offline for AbuseIPDB lookups."
    } elseif ($externalIPs.Count -gt 0) {
        Add-Finding -Severity "INFO" -Category "Network" `
            -Title "Threat Intel Skipped (No API Key)" `
            -Description "Found $($externalIPs.Count) unique external IPs but no AbuseIPDB API key is configured. Add your key to config.json for automatic threat intelligence lookups." `
            -Remediation "Get a free API key at https://www.abuseipdb.com/ and add it to config.json as 'AbuseIPDBKey'."
    }

    # ── 3. Listening Ports ───────────────────────────────────────────────

    Write-Status "Checking listening ports..."

    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    $seenListeners = @{}
    foreach ($listener in $listeners) {
        $port = $listener.LocalPort
        $procId = $listener.OwningProcess
        $proc = $procLookup[$procId]
        $procName = if ($proc) { $proc.Name } else { "Unknown (PID: $procId)" }
        $localAddr = $listener.LocalAddress

        if ($trustedPorts -contains $port) { continue }

        $isAllInterfaces = ($localAddr -eq "0.0.0.0" -or $localAddr -eq "::")
        $commonListenPorts = @(80, 443, 135, 139, 445, 3389, 5040, 5985, 5986, 7680, 8080) + @(49664..49680)

        if ($isAllInterfaces -and $port -notin $commonListenPorts) {
            $dedupKey = "$port|$procName"
            if ($seenListeners.ContainsKey($dedupKey)) {
                $seenListeners[$dedupKey].Addresses += $localAddr
                continue
            }
            $seenListeners[$dedupKey] = @{
                Port = $port
                Process = $procName
                PID = $procId
                Addresses = @($localAddr)
                ProcessPath = if ($proc) { $proc.ExecutablePath } else { "" }
            }
        }
    }

    foreach ($key in $seenListeners.Keys) {
        $entry = $seenListeners[$key]
        $severity = "WARNING"
        $backdoorPorts = if ($script:Config.BackdoorPorts) { $script:Config.BackdoorPorts } else { @(4444, 5555, 6666, 1234, 31337, 12345, 54321, 9999, 1337) }
        if ($entry.Port -in $backdoorPorts) { $severity = "CRITICAL" }
        $addrStr = ($entry.Addresses | Sort-Object -Unique) -join ", "

        Add-Finding -Severity $severity -Category "Network" `
            -Title "Unusual Listening Port: $($entry.Port) ($($entry.Process))" `
            -Description "Process '$($entry.Process)' (PID: $($entry.PID)) is listening on port $($entry.Port) on all interfaces ($addrStr). This port is not in the common/trusted list." `
            -Remediation "Verify this listener is expected. If you don't recognize the process or port, investigate further. Use 'netstat -ano | findstr $($entry.Port)' for details." `
            -Details @{
                Port = $entry.Port
                Process = $entry.Process
                PID = $entry.PID
                LocalAddresses = $addrStr
                ProcessPath = $entry.ProcessPath
            } `
            -MITRE @("T1571")
    }

    # WinRM and SSH listeners — always check regardless of commonListenPorts exclusions
    $specialListeners = @(
        @{ Port = 5985; Severity = "WARNING"; Title = "WinRM Listener Active: port 5985"; MITRE = "T1021.006"
           Description = "WinRM (HTTP) is listening on port 5985. WinRM enables remote PowerShell command execution and is commonly abused by attackers for lateral movement."
           Remediation = "If WinRM is not required, disable it: 'Disable-PSRemoting -Force'. Restrict access with firewall rules if it must remain enabled." }
        @{ Port = 5986; Severity = "WARNING"; Title = "WinRM Listener Active: port 5986"; MITRE = "T1021.006"
           Description = "WinRM (HTTPS) is listening on port 5986. WinRM enables remote PowerShell command execution and is commonly abused by attackers for lateral movement."
           Remediation = "If WinRM is not required, disable it: 'Disable-PSRemoting -Force'. Restrict access with firewall rules if it must remain enabled." }
        @{ Port = 22;   Severity = "INFO";    Title = "SSH Listener Active";             MITRE = "T1021.004"
           Description = "An OpenSSH server is listening on port 22. SSH enables remote command execution; verify this service is intentional and that key-based authentication is enforced."
           Remediation = "If SSH is not required, stop and disable the OpenSSH Server service. If required, ensure 'PasswordAuthentication no' is set in sshd_config and restrict access via firewall." }
    )
    foreach ($check in $specialListeners) {
        if ($trustedPorts -contains $check.Port) { continue }
        $match = $listeners | Where-Object { $_.LocalPort -eq $check.Port -and ($_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::") }
        if ($match) {
            $procId = $match[0].OwningProcess
            $proc = $procLookup[$procId]
            $procName = if ($proc) { $proc.Name } else { "Unknown (PID: $procId)" }
            Add-Finding -Severity $check.Severity -Category "Network" `
                -Title $check.Title `
                -Description "$($check.Description) Process: '$procName'." `
                -Remediation $check.Remediation `
                -Details @{ Port = $check.Port; Process = $procName; PID = $procId } `
                -MITRE @($check.MITRE)
        }
    }

    # ── 4. DNS Configuration ─────────────────────────────────────────────

    Write-Status "Checking DNS configuration..."

    $adapters = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses.Count -gt 0 }

    $knownDNS = if ($script:Config.KnownDNSServers) { $script:Config.KnownDNSServers } else { @("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112","208.67.222.222","208.67.220.220","76.76.2.0","76.76.10.0") }

    $seenDns = @{}
    foreach ($adapter in $adapters) {
        foreach ($dns in $adapter.ServerAddresses) {
            if ($dns -match '^fec0:' -or $dns -match '^fe[89ab]' -or $dns -eq '::1') { continue }
            if (Test-IsPrivateIP $dns) { continue }
            if ($dns -in $knownDNS) { continue }

            if (-not $seenDns.ContainsKey($dns)) {
                $seenDns[$dns] = [System.Collections.ArrayList]::new()
            }
            $seenDns[$dns].Add($adapter.InterfaceAlias) | Out-Null
        }
    }

    foreach ($dns in $seenDns.Keys) {
        $adapterList = $seenDns[$dns] | Sort-Object -Unique
        Add-Finding -Severity "WARNING" -Category "Network" `
            -Title "Unusual DNS Server: $dns" `
            -Description "DNS server $dns is configured on $($adapterList.Count) adapter(s): $($adapterList -join ', '). This is not a well-known public DNS provider. Malware sometimes changes DNS settings to redirect traffic." `
            -Remediation "Verify this DNS server is from your ISP or organization. If unexpected, change DNS to a known provider (8.8.8.8, 1.1.1.1, etc.) and investigate how it was changed." `
            -Details @{
                Adapters = $adapterList
                DNS = $dns
            } `
            -MITRE @("T1584.002")
    }

    # ── 5. Hosts File Check ──────────────────────────────────────────────

    Write-Status "Checking hosts file for modifications..."

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) {
        $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
        $suspiciousEntries = $hostsContent | Where-Object {
            $_ -and
            $_.Trim() -ne "" -and
            -not $_.Trim().StartsWith("#") -and
            $_ -notmatch "^\s*127\.0\.0\.1\s+localhost\s*$" -and
            $_ -notmatch "^\s*::1\s+localhost\s*$"
        }

        if ($suspiciousEntries.Count -gt 0) {
            $securityDomains = @("windowsupdate", "microsoft", "malwarebytes", "norton", "kaspersky",
                                 "avast", "avg", "bitdefender", "virustotal", "google", "bing")

            $blockedSecurity = $suspiciousEntries | Where-Object {
                $entry = $_
                $securityDomains | Where-Object { $entry -match $_ }
            }

            if ($blockedSecurity.Count -gt 0) {
                Add-Finding -Severity "CRITICAL" -Category "Network" `
                    -Title "Hosts File Blocking Security Sites" `
                    -Description "The hosts file contains entries that redirect security-related domains. This is a common malware technique to prevent updates and block access to security tools." `
                    -Remediation "Remove the suspicious entries from $hostsPath. This is a strong indicator that malware has modified your system configuration." `
                    -Details @{
                        Entries = $blockedSecurity
                        HostsPath = $hostsPath
                    } `
                    -MITRE @("T1565.001")
            } else {
                Add-Finding -Severity "INFO" -Category "Network" `
                    -Title "Custom Hosts File Entries ($($suspiciousEntries.Count) entries)" `
                    -Description "The hosts file contains $($suspiciousEntries.Count) custom entries beyond the defaults. While this may be intentional (ad blocking, development), it's worth reviewing." `
                    -Remediation "Review entries in $hostsPath and ensure they are all intentional." `
                    -Details @{ Entries = $suspiciousEntries }
            }
        }
    }

    # ── 6. Proxy Configuration ───────────────────────────────────────────

    Write-Status "Checking proxy settings..."

    try {
        $proxyReg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        if ($proxyReg.ProxyEnable -eq 1) {
            Add-Finding -Severity "WARNING" -Category "Network" `
                -Title "System Proxy Enabled: $($proxyReg.ProxyServer)" `
                -Description "A system-wide proxy is configured: '$($proxyReg.ProxyServer)'. If you didn't set this, malware may be intercepting your traffic." `
                -Remediation "If you didn't configure this proxy, disable it: Settings > Network > Proxy. Then investigate how it was enabled." `
                -Details @{
                    ProxyServer = $proxyReg.ProxyServer
                    ProxyOverride = $proxyReg.ProxyOverride
                    AutoConfigURL = $proxyReg.AutoConfigURL
                } `
                -MITRE @("T1090")
        }
    } catch {}

    # ── 7. Firewall Status ───────────────────────────────────────────────

    Write-Status "Checking Windows Firewall status..."

    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($profile in $fwProfiles) {
            if (-not $profile.Enabled) {
                Add-Finding -Severity "CRITICAL" -Category "Network" `
                    -Title "Windows Firewall DISABLED: $($profile.Name) Profile" `
                    -Description "The Windows Firewall '$($profile.Name)' profile is disabled. This leaves the system exposed to network-based attacks." `
                    -Remediation "Enable the firewall immediately: Set-NetFirewallProfile -Profile $($profile.Name) -Enabled True" `
                    -Details @{
                        Profile = $profile.Name
                        Enabled = $profile.Enabled
                        DefaultInbound = $profile.DefaultInboundAction
                        DefaultOutbound = $profile.DefaultOutboundAction
                    } `
                    -MITRE @("T1562.004")
            }
        }
    } catch {
        Write-Status "Could not check firewall status (may need admin)." -Color Yellow
    }

}
