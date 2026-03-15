<# MODULE
Name: DefenseEvasion
Description: Defense Evasion & Anti-Forensics
Category: Security
Author: Am I Hacked Project
#>

function Invoke-DefenseEvasionChecks {

    # ── 1. Cleared Event Logs ────────────────────────────────────────────

    Write-Status "Checking for cleared event logs..."

    try {
        $logClears = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102 } -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($logClears) {
            foreach ($evt in $logClears) {
                $daysAgo = ((Get-Date) - $evt.TimeCreated).TotalDays
                $severity = if ($daysAgo -le 30) { "CRITICAL" } else { "WARNING" }

                Add-Finding -Severity $severity -Category "DefenseEvasion" `
                    -Title "Security Event Log Cleared: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" `
                    -Description "The Security event log was cleared on $($evt.TimeCreated). Attackers clear logs to cover their tracks. Account: $($evt.Properties[1].Value)." `
                    -Remediation "Investigate what happened around this time. Check other log sources (Application, System, PowerShell) for correlated activity." `
                    -Details @{
                        TimeCleared = $evt.TimeCreated
                        Account = $evt.Properties[1].Value
                        DaysAgo = [math]::Round($daysAgo, 1)
                    } `
                    -MITRE @("T1070.001")
            }
        }

        $sysLogClears = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=104 } -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($sysLogClears) {
            foreach ($evt in $sysLogClears) {
                $clearedLog = $evt.Properties[0].Value
                Add-Finding -Severity "WARNING" -Category "DefenseEvasion" `
                    -Title "Event Log Cleared: $clearedLog ($($evt.TimeCreated.ToString('yyyy-MM-dd')))" `
                    -Description "The '$clearedLog' event log was cleared on $($evt.TimeCreated)." `
                    -Remediation "Investigate why this log was cleared. Cross-reference with other system activity." `
                    -Details @{ LogName = $clearedLog; TimeCleared = $evt.TimeCreated } `
                    -MITRE @("T1070.001")
            }
        }
    } catch {
        Write-Status "Could not check event log clearing (requires admin)." -Color Yellow
    }

    # ── 2. AMSI Tampering ────────────────────────────────────────────────

    Write-Status "Checking AMSI integrity..."

    try {
        $disableAS = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
        if ($disableAS -and $disableAS.DisableAntiSpyware -eq 1) {
            Add-Finding -Severity "CRITICAL" -Category "DefenseEvasion" `
                -Title "Windows Defender Disabled via Policy" `
                -Description "Registry key 'DisableAntiSpyware' is set to 1. This completely disables Windows Defender. Malware commonly sets this to blind the system's primary AV." `
                -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware'" `
                -Details @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Value = 1 } `
                -MITRE @("T1562.001")
        }
    } catch {
        Write-Verbose "Could not check Defender DisableAntiSpyware policy: $_"
    }

    $amsiDll = "$env:SystemRoot\System32\amsi.dll"
    if (Test-Path $amsiDll) {
        $sig = Get-FileSignature -FilePath $amsiDll
        if ($sig -and $sig.Status -eq "CheckFailed") {
            Write-Status "AMSI signature check unavailable (PS.Security module could not be loaded)." -Color DarkGray
        } elseif (-not $sig -or $sig.Status -ne "Valid") {
            Add-Finding -Severity "CRITICAL" -Category "DefenseEvasion" `
                -Title "AMSI DLL Signature Invalid" `
                -Description "amsi.dll at '$amsiDll' does not have a valid digital signature (Status: $(if ($sig) { $sig.Status } else { 'Missing' })). This may indicate the AMSI interface has been tampered with to bypass script scanning." `
                -Remediation "Run 'sfc /scannow' to restore the legitimate amsi.dll. Investigate how it was modified." `
                -Details @{ Path = $amsiDll; SignatureStatus = if ($sig) { $sig.Status } else { "No signature" } } `
                -MITRE @("T1562.001")
        }
    }

    try {
        $amsiProviders = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
        if (-not $amsiProviders -or $amsiProviders.Count -eq 0) {
            Add-Finding -Severity "CRITICAL" -Category "DefenseEvasion" `
                -Title "No AMSI Providers Registered" `
                -Description "No AMSI providers found in the registry. This means script-based malware (PowerShell, VBScript, JScript) cannot be scanned at runtime." `
                -Remediation "Re-register Windows Defender as an AMSI provider. Run 'sfc /scannow' and ensure Defender is properly installed." `
                -MITRE @("T1562.001")
        }
    } catch {
        Write-Verbose "Could not enumerate AMSI providers: $_"
    }

    try {
        $amsiEnable = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script\Settings" -Name "AmsiEnable" -ErrorAction SilentlyContinue
        if ($amsiEnable -and $amsiEnable.AmsiEnable -eq 0) {
            Add-Finding -Severity "CRITICAL" -Category "DefenseEvasion" `
                -Title "AMSI Explicitly Disabled via Registry" `
                -Description "HKLM:\SOFTWARE\Microsoft\Windows Script\Settings!AmsiEnable is set to 0. This explicitly disables AMSI for Windows Script Host (VBScript, JScript), allowing malicious scripts to run without AV scanning." `
                -Remediation "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script\Settings' -Name 'AmsiEnable'" `
                -Details @{ Key = "HKLM:\SOFTWARE\Microsoft\Windows Script\Settings\AmsiEnable"; Value = 0 } `
                -MITRE @("T1562.001")
        }
    } catch {
        Write-Verbose "Could not check AMSI Windows Script Settings: $_"
    }

    try {
        $sbl = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        if (-not $sbl -or -not $sbl.EnableScriptBlockLogging -or $sbl.EnableScriptBlockLogging -eq 0) {
            Add-Finding -Severity "INFO" -Category "DefenseEvasion" `
                -Title "PowerShell Script Block Logging Not Enabled" `
                -Description "Script block logging is not enabled via policy. When enabled, PowerShell logs all executed script blocks to the event log (Event ID 4104), which is valuable for detecting obfuscated or malicious scripts." `
                -Remediation "Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1" `
                -Details @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging"; Value = "absent or 0" } `
                -MITRE @("T1562.002")
        }
    } catch {
        Write-Verbose "Could not check ScriptBlockLogging policy: $_"
    }

    # ── 3. Windows Defender Real-Time Protection ─────────────────────────

    Write-Status "Checking Defender real-time protection..."

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mpStatus) {
            if (-not $mpStatus.RealTimeProtectionEnabled) {
                Add-Finding -Severity "CRITICAL" -Category "DefenseEvasion" `
                    -Title "Defender Real-Time Protection Disabled" `
                    -Description "Windows Defender real-time protection is disabled. The system has no active malware scanning." `
                    -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
                    -Details @{
                        RealTimeProtection = $mpStatus.RealTimeProtectionEnabled
                        AntivirusEnabled = $mpStatus.AntivirusEnabled
                        AntispywareEnabled = $mpStatus.AntispywareEnabled
                    } `
                    -MITRE @("T1562.001")
            }

            if (-not $mpStatus.AntivirusEnabled) {
                Add-Finding -Severity "CRITICAL" -Category "DefenseEvasion" `
                    -Title "Antivirus Engine Disabled" `
                    -Description "The Windows Defender antivirus engine is disabled." `
                    -Remediation "Re-enable Defender through Windows Security settings or Group Policy." `
                    -MITRE @("T1562.001")
            }

            $sigAge = $mpStatus.AntivirusSignatureAge
            if ($sigAge -gt 7) {
                Add-Finding -Severity "WARNING" -Category "DefenseEvasion" `
                    -Title "Defender Signatures Outdated ($sigAge days)" `
                    -Description "Antivirus definitions are $sigAge days old. Outdated signatures miss recent threats. Malware sometimes blocks update mechanisms." `
                    -Remediation "Update-MpSignature" `
                    -Details @{ SignatureAge = $sigAge; LastUpdate = $mpStatus.AntivirusSignatureLastUpdated } `
                    -MITRE @("T1562.001")
            }
        }
    } catch {
        Write-Status "Could not check Defender status (may need admin)." -Color Yellow
    }

    # ── 4. ETW Tampering Indicators ──────────────────────────────────────

    Write-Status "Checking for ETW tampering..."

    try {
        $etwSecurity = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" -Name "Start" -ErrorAction SilentlyContinue
        if ($etwSecurity -and $etwSecurity.Start -ne 1) {
            Add-Finding -Severity "CRITICAL" -Category "DefenseEvasion" `
                -Title "Security ETW Autologger Disabled" `
                -Description "The Security event log ETW autologger has been disabled (Start=$($etwSecurity.Start)). This prevents security events from being recorded, blinding audit and detection capabilities." `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security' -Name 'Start' -Value 1" `
                -Details @{ CurrentValue = $etwSecurity.Start; ExpectedValue = 1 } `
                -MITRE @("T1562.002")
        }
    } catch {
        Write-Verbose "Could not check ETW Security autologger: $_"
    }

    try {
        $disabledLoggers = @(
            "EventLog-Application",
            "EventLog-System"
        )
        foreach ($logger in $disabledLoggers) {
            $loggerReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$logger" -Name "Start" -ErrorAction SilentlyContinue
            if ($loggerReg -and $loggerReg.Start -ne 1) {
                Add-Finding -Severity "WARNING" -Category "DefenseEvasion" `
                    -Title "ETW Autologger Disabled: $logger" `
                    -Description "The $logger ETW autologger has been disabled. This reduces system audit coverage." `
                    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$logger' -Name 'Start' -Value 1" `
                    -MITRE @("T1562.002")
            }
        }
    } catch {
        Write-Verbose "Could not check ETW Application/System autologgers: $_"
    }

    # ── 5. Tamper Protection Check ───────────────────────────────────────

    Write-Status "Checking tamper protection..."

    try {
        $tamperProtection = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
        if ($tamperProtection -and $tamperProtection.TamperProtection -ne 5) {
            Add-Finding -Severity "WARNING" -Category "DefenseEvasion" `
                -Title "Tamper Protection Not Fully Enabled" `
                -Description "Windows Defender Tamper Protection is not in the expected state (Value: $($tamperProtection.TamperProtection), Expected: 5). This makes it easier for malware to disable Defender." `
                -Remediation "Enable Tamper Protection through Windows Security > Virus & threat protection settings." `
                -MITRE @("T1562.001")
        }
    } catch {
        Write-Verbose "Could not check Defender TamperProtection: $_"
    }

}
