<# MODULE
Name: FileSystem
Description: File System Red Flags
Category: Security
Author: Am I Hacked Project
#>

function Invoke-FileSystemChecks {

    $maxAgeDays = if ($script:Config.FileSystemMaxAgeDays) { $script:Config.FileSystemMaxAgeDays } else { 3 }
    $suspiciousExtensions = if ($script:Config.SuspiciousTempExtensions) {
        $script:Config.SuspiciousTempExtensions
    } else {
        @(".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".hta")
    }

    # ── 1. Recently Modified System Executables ──────────────────────────

    Write-Status "Checking for recently modified executables in system directories..."

    $systemDirs = @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64"
    )

    $cutoffDate = (Get-Date).AddDays(-$maxAgeDays)
    $suspiciousSystemFiles = [System.Collections.ArrayList]::new()

    foreach ($dir in $systemDirs) {
        if (-not (Test-Path $dir)) { continue }

        try {
            $recentExes = Get-ChildItem $dir -Filter "*.exe" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoffDate }

            foreach ($file in $recentExes) {
                $sig = Get-FileSignature -FilePath $file.FullName
                if (-not $sig -or $sig.Status -ne "Valid") {
                    $suspiciousSystemFiles.Add($file) | Out-Null

                    Add-Finding -Severity "CRITICAL" -Category "FileSystem" `
                        -Title "Modified Unsigned System Exe: $($file.Name)" `
                        -Description "File '$($file.FullName)' was modified within the last $maxAgeDays day(s) (Modified: $($file.LastWriteTime)) and is NOT digitally signed. Modification of system executables is extremely suspicious." `
                        -Remediation "This may indicate a system binary was replaced by malware (DLL hijacking/binary replacement). Run 'sfc /scannow' and compare the file hash against known-good values." `
                        -Details @{
                            Path = $file.FullName
                            Size = Format-ByteSize $file.Length
                            Modified = $file.LastWriteTime
                            Created = $file.CreationTime
                            SignatureStatus = if ($sig) { $sig.Status } else { "No signature" }
                        } `
                        -MITRE @("T1036.005","T1574.001")
                }
            }

            $recentDlls = Get-ChildItem $dir -Filter "*.dll" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoffDate }

            foreach ($file in $recentDlls) {
                $sig = Get-FileSignature -FilePath $file.FullName
                if (-not $sig -or $sig.Status -ne "Valid") {
                    Add-Finding -Severity "WARNING" -Category "FileSystem" `
                        -Title "Modified Unsigned System DLL: $($file.Name)" `
                        -Description "DLL '$($file.FullName)' was modified within the last $maxAgeDays day(s) and lacks a valid signature. This could indicate DLL hijacking." `
                        -Remediation "Verify the file hash. Run 'sfc /scannow' to check system file integrity." `
                        -Details @{
                            Path = $file.FullName
                            Size = Format-ByteSize $file.Length
                            Modified = $file.LastWriteTime
                            SignatureStatus = if ($sig) { $sig.Status } else { "No signature" }
                        } `
                        -MITRE @("T1574.001")
                }
            }
        } catch {
            Write-Status "Could not scan $dir : $_" -Color Yellow
        }
    }

    # ── 2. Suspicious Files in Temp/AppData ──────────────────────────────

    Write-Status "Scanning temp and AppData for suspicious files..."

    $tempDirs = @(
        $env:TEMP,
        "$env:LOCALAPPDATA\Temp",
        "$env:SystemRoot\Temp"
    ) | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique

    $trustedAppDirs = @("WindowsApps", "Microsoft\\WindowsApps")
    if ($script:Config.TrustedAppDirs) {
        $trustedAppDirs += $script:Config.TrustedAppDirs
    }

    $suspiciousFiles = [System.Collections.ArrayList]::new()
    $vtCandidates = [System.Collections.ArrayList]::new()
    $skippedSigned = [System.Collections.ArrayList]::new()

    foreach ($dir in $tempDirs) {
        try {
            $files = Get-ChildItem $dir -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $ext = $_.Extension.ToLower()
                    $ext -in $suspiciousExtensions
                }

            foreach ($file in $files) {
                if ($file.Name -match '^ps-script-[0-9a-f\-]+\.ps1$') { continue }
                if ($file.Name -match '^remoteIpMoProxy_') { continue }  # PS implicit remoting proxy — scanner artifact

                $inTrustedDir = $false
                foreach ($pattern in $trustedAppDirs) {
                    if ($file.FullName -like "*\$pattern\*" -or $file.DirectoryName -like "*\$pattern*") {
                        $inTrustedDir = $true
                        break
                    }
                }

                $severity = "WARNING"
                $sig = $null
                $versionInfo = $null

                if ($file.Extension -in @(".exe", ".dll", ".scr")) {
                    $sig = Get-FileSignature -FilePath $file.FullName
                    $versionInfo = Get-FileVersionInfo -FilePath $file.FullName

                    $isTrustedSigner = Test-IsTrustedSigner -Signature $sig -VersionInfo $versionInfo
                    $hasValidSig = $sig -and $sig.Status -eq "Valid"

                    if ($isTrustedSigner -or ($hasValidSig -and $inTrustedDir)) {
                        $skippedSigned.Add($file) | Out-Null
                        continue
                    } elseif ($hasValidSig) {
                        $severity = "INFO"
                    } elseif ($versionInfo -and (Test-IsTrustedCompany $versionInfo.CompanyName)) {
                        if ($inTrustedDir) {
                            $severity = "WARNING"
                        } else {
                            $severity = "WARNING"
                        }
                    } elseif (-not $hasValidSig) {
                        if ($inTrustedDir) {
                            $severity = "WARNING"
                        } else {
                            $severity = "CRITICAL"
                            $vtCandidates.Add($file) | Out-Null
                        }
                    }
                } else {
                    if ($inTrustedDir) { continue }
                }

                $doubleExt = $false
                $nameParts = $file.Name -split '\.'
                if ($nameParts.Count -ge 3) {
                    $deceptiveExts = @('.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.jpg','.jpeg','.png','.gif','.bmp','.txt','.csv','.zip','.rar','.7z','.mp3','.mp4','.avi','.mov','.htm','.html','.rtf','.odt','.iso')
                    $secondToLast = ".$($nameParts[-2])"
                    if ($deceptiveExts -contains $secondToLast.ToLower()) {
                        $doubleExt = $true
                    }
                }
                if ($doubleExt) { $severity = "CRITICAL" }

                $suspiciousFiles.Add($file) | Out-Null

                Add-Finding -Severity $severity -Category "FileSystem" `
                    -Title "Suspicious File in Temp: $($file.Name)" `
                    -Description "Found '$($file.Name)' in '$($file.DirectoryName)'. $(if ($doubleExt) { 'WARNING: Double extension detected!' }) Size: $(Format-ByteSize $file.Length), Modified: $($file.LastWriteTime).$(if ($versionInfo -and $versionInfo.CompanyName) { " Company: $($versionInfo.CompanyName).$(if (-not $hasValidSig -and (Test-IsTrustedCompany $versionInfo.CompanyName)) { ' UNSIGNED.' })" })" `
                    -Remediation "Investigate this file. Check its hash on VirusTotal. If you didn't create it, delete it." `
                    -Details @{
                        Path = $file.FullName
                        Size = Format-ByteSize $file.Length
                        Modified = $file.LastWriteTime
                        Created = $file.CreationTime
                        DoubleExtension = $doubleExt
                        SignatureStatus = if ($sig) { $sig.Status } else { "Not checked" }
                        VersionInfo = $versionInfo
                    } `
                    -MITRE @("T1204.002")
            }
        } catch {
            Write-Status "Error scanning $dir : $_" -Color Yellow
        }
    }

    if ($skippedSigned.Count -gt 0) {
        Add-Finding -Severity "INFO" -Category "FileSystem" `
            -Title "Signed Files in App Directories: $($skippedSigned.Count) skipped" `
            -Description "$($skippedSigned.Count) validly signed files in known application directories were skipped. These are typically legitimate." `
            -Remediation "No action needed. Review the list if you suspect tampering." `
            -Details @{
                Count = $skippedSigned.Count
                SamplePaths = ($skippedSigned | Select-Object -First 10 | ForEach-Object { $_.FullName })
            }
    }

    Write-Status "Found $($suspiciousFiles.Count) suspicious files ($($skippedSigned.Count) signed files in known app dirs skipped)."

    # ── 3. VirusTotal Hash Lookups ───────────────────────────────────────

    $vtKey = $script:Config.VirusTotalAPIKey
    if (-not $script:OfflineMode -and $vtKey -and $vtCandidates.Count -gt 0) {
        Write-Status "Checking file hashes against VirusTotal..."

        $checked = 0
        $maxVT = 4

        foreach ($file in $vtCandidates) {
            if ($checked -ge $maxVT) {
                Write-Status "VirusTotal rate limit reached. Remaining files skipped." -Color Yellow
                break
            }

            try {
                $hash = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                if (-not $hash) { continue }

                $vtResponse = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" `
                    -Headers @{ "x-apikey" = $vtKey } `
                    -Method GET -ErrorAction Stop

                $checked++
                $stats = $vtResponse.data.attributes.last_analysis_stats
                $detections = $stats.malicious + $stats.suspicious

                if ($detections -gt 0) {
                    $severity = if ($detections -ge 5) { "CRITICAL" } else { "WARNING" }

                    Add-Finding -Severity $severity -Category "FileSystem" `
                        -Title "VirusTotal Detection: $($file.Name) ($detections engines)" `
                        -Description "File '$($file.Name)' (SHA256: $hash) is flagged by $detections VirusTotal engines ($($stats.malicious) malicious, $($stats.suspicious) suspicious out of $($stats.undetected + $detections) total)." `
                        -Remediation "Delete this file immediately. Run a full system scan. Consider this system potentially compromised." `
                        -Details @{
                            Path = $file.FullName
                            SHA256 = $hash
                            Detections = $detections
                            Malicious = $stats.malicious
                            Suspicious = $stats.suspicious
                            Harmless = $stats.harmless
                            Undetected = $stats.undetected
                            VTLink = "https://www.virustotal.com/gui/file/$hash"
                        } `
                        -MITRE @("T1204.002")
                }
            } catch {
                if ($_.Exception.Response.StatusCode -eq 404) {
                    Add-Finding -Severity "INFO" -Category "FileSystem" `
                        -Title "Unknown to VirusTotal: $($file.Name)" `
                        -Description "File '$($file.Name)' hash is not in the VirusTotal database. This means it's either very new, custom-built, or rarely seen — which can be suspicious for executables." `
                        -Details @{ Path = $file.FullName }
                }
            }
        }
    } elseif ($script:OfflineMode -and $vtCandidates.Count -gt 0) {
        Add-Finding -Severity "INFO" -Category "FileSystem" `
            -Title "VirusTotal Check Skipped (Offline Mode)" `
            -Description "Found $($vtCandidates.Count) unsigned executables in temp directories but offline mode is enabled."
    } elseif ($vtCandidates.Count -gt 0) {
        Add-Finding -Severity "INFO" -Category "FileSystem" `
            -Title "VirusTotal Check Skipped (No API Key)" `
            -Description "Found $($vtCandidates.Count) unsigned executables in temp directories but no VirusTotal API key is configured." `
            -Remediation "Get a free API key at https://www.virustotal.com/ and add it to config.json as 'VirusTotalAPIKey'."
    }

    # ── 4. Alternate Data Streams ────────────────────────────────────────

    Write-Status "Checking for Alternate Data Streams (ADS)..."

    $adsScanDirs = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Documents",
        $env:TEMP
    ) | Where-Object { $_ -and (Test-Path $_) }

    $adsCount = 0
    foreach ($dir in $adsScanDirs) {
        try {
            $files = Get-ChildItem $dir -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                $benignStreams = @(':$DATA', 'Zone.Identifier', 'StreamedFileState', 'encryptable', 'SummaryInformation', 'DocumentSummaryInformation', 'SmartScreen', 'motw')
                $streams = Get-Item $file.FullName -Stream * -ErrorAction SilentlyContinue |
                    Where-Object { $_.Stream -notin $benignStreams }

                foreach ($stream in $streams) {
                    $adsCount++
                    $severity = "WARNING"

                    if ($stream.Stream -match '\.(exe|dll|vbs|ps1|bat|cmd|js)$') {
                        $severity = "CRITICAL"
                    }

                    Add-Finding -Severity $severity -Category "FileSystem" `
                        -Title "Alternate Data Stream: $($file.Name):$($stream.Stream)" `
                        -Description "File '$($file.FullName)' has a hidden Alternate Data Stream named '$($stream.Stream)' ($($stream.Length) bytes). ADS can be used to hide malicious payloads within innocent-looking files." `
                        -Remediation "Inspect the stream content: Get-Content '$($file.FullName)' -Stream '$($stream.Stream)'. Remove with: Remove-Item '$($file.FullName)' -Stream '$($stream.Stream)'" `
                        -Details @{
                            FilePath = $file.FullName
                            StreamName = $stream.Stream
                            StreamSize = $stream.Length
                        } `
                        -MITRE @("T1564.004")
                }
            }
        } catch {}
    }

    if ($adsCount -eq 0) {
        Write-Status "No suspicious Alternate Data Streams found."
    }

    # ── 5. Info-Stealer Artifact Scan ────────────────────────────────────

    Write-Status "Checking for info-stealer artifacts..."

    $browserProfiles = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    )

    foreach ($profileDir in $browserProfiles) {
        if (-not (Test-Path $profileDir)) { continue }
        try {
            $stagingFiles = Get-ChildItem $profileDir -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @(".zip", ".rar", ".7z") -and $_.CreationTime -gt (Get-Date).AddDays(-7) }

            foreach ($archive in $stagingFiles) {
                Add-Finding -Severity "CRITICAL" -Category "FileSystem" `
                    -Title "Suspicious Archive in Browser Profile: $($archive.Name)" `
                    -Description "Found archive '$($archive.Name)' ($(Format-ByteSize $archive.Length)) inside browser profile directory '$profileDir'. Info-stealers stage browser credential databases into archives for exfiltration." `
                    -Remediation "Investigate this file immediately. Check if your browser credentials have been exported. Change all saved passwords." `
                    -Details @{
                        Path = $archive.FullName
                        Size = Format-ByteSize $archive.Length
                        Created = $archive.CreationTime
                    } `
                    -MITRE @("T1555.003","T1560.001")
            }
        } catch {}
    }

    $stealerPatterns = @("passwords.txt", "credentials.txt", "wallets.txt", "cookies.txt", "autofill.txt", "credit_cards.txt")
    try {
        $tempFiles = Get-ChildItem $env:TEMP -File -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-3) }

        foreach ($f in $tempFiles) {
            if ($stealerPatterns -contains $f.Name.ToLower()) {
                Add-Finding -Severity "CRITICAL" -Category "FileSystem" `
                    -Title "Stealer Output File: $($f.Name)" `
                    -Description "Found '$($f.Name)' in temp directory. This filename matches common info-stealer output patterns used to stage stolen credentials for exfiltration." `
                    -Remediation "Examine this file's contents, then delete it. Change all affected passwords immediately." `
                    -Details @{ Path = $f.FullName; Size = Format-ByteSize $f.Length; Created = $f.CreationTime } `
                    -MITRE @("T1555","T1005")
            }
        }
    } catch {}

    $walletPaths = @(
        "$env:APPDATA\Electrum\wallets",
        "$env:APPDATA\Exodus\exodus.wallet",
        "$env:APPDATA\Ethereum\keystore",
        "$env:APPDATA\atomic\Local Storage",
        "$env:APPDATA\Bitcoin\wallets"
    )
    foreach ($wp in $walletPaths) {
        if (-not (Test-Path $wp)) { continue }
        try {
            $recentAccess = Get-ChildItem $wp -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastAccessTime -gt (Get-Date).AddDays(-1) -and $_.LastWriteTime -lt (Get-Date).AddDays(-7) }

            if ($recentAccess.Count -gt 0) {
                Add-Finding -Severity "WARNING" -Category "FileSystem" `
                    -Title "Recent Crypto Wallet Access: $(Split-Path $wp -Leaf)" `
                    -Description "Wallet files in '$wp' were recently accessed ($($recentAccess.Count) files) but not recently modified. This can indicate credential harvesting by an info-stealer." `
                    -Remediation "Verify your wallet integrity. Consider moving funds to a new wallet generated on a clean system." `
                    -Details @{ Path = $wp; FilesAccessed = $recentAccess.Count } `
                    -MITRE @("T1005","T1555")
            }
        } catch {}
    }

    # ── 6. Persistence via Common Autorun Locations ──────────────────────

    Write-Status "Checking common persistence/autorun locations..."

    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($key in $runKeys) {
        try {
            $entries = Get-ItemProperty $key -ErrorAction SilentlyContinue
            if (-not $entries) { continue }

            $props = $entries.PSObject.Properties | Where-Object {
                $_.Name -notmatch '^PS' -and $_.Name -ne "(default)"
            }

            foreach ($prop in $props) {
                $value = $prop.Value
                if (-not $value) { continue }

                $severity = "INFO"
                $suspicious = $false

                if ($value -match "\\Temp\\" -or $value -match "\\AppData\\Local\\Temp") {
                    $severity = "CRITICAL"
                    $suspicious = $true
                }
                if ($value -match "powershell.*-enc" -or $value -match "powershell.*-e " -or $value -match "-WindowStyle\s+Hidden") {
                    $severity = "CRITICAL"
                    $suspicious = $true
                }
                if ($value -match "mshta|wscript|cscript|regsvr32|rundll32.*javascript") {
                    $severity = "WARNING"
                    $suspicious = $true
                }
                if ($value -match "\^|``|%[a-z]") {
                    $severity = "WARNING"
                    $suspicious = $true
                }

                if ($suspicious) {
                    Add-Finding -Severity $severity -Category "FileSystem" `
                        -Title "Suspicious Autorun: $($prop.Name)" `
                        -Description "Registry key '$key' contains a suspicious autorun entry '$($prop.Name)' with value: '$value'. This persistence mechanism will execute every time the system/user starts." `
                        -Remediation "If you don't recognize this entry, remove it: Remove-ItemProperty -Path '$key' -Name '$($prop.Name)'" `
                        -Details @{
                            RegistryKey = $key
                            EntryName = $prop.Name
                            Value = $value
                        } `
                        -MITRE @("T1547.001")
                } else {
                    Add-Finding -Severity "INFO" -Category "FileSystem" `
                        -Title "Autorun Entry: $($prop.Name)" `
                        -Description "Autorun at '$key': '$($prop.Name)' = '$value'" `
                        -Details @{
                            RegistryKey = $key
                            EntryName = $prop.Name
                            Value = $value
                        } `
                        -MITRE @("T1547.001")
                }
            }
        } catch {}
    }

    # ── 7. Advanced Persistence: IFEO, AppInit_DLLs, Winlogon ────────────

    Write-Status "Checking advanced persistence mechanisms..."

    try {
        $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $ifeoKeys = Get-ChildItem $ifeoPath -ErrorAction SilentlyContinue
        foreach ($ifeoKey in $ifeoKeys) {
            $debugger = Get-ItemProperty $ifeoKey.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($debugger -and $debugger.Debugger) {
                Add-Finding -Severity "CRITICAL" -Category "FileSystem" `
                    -Title "IFEO Debugger Hijack: $($ifeoKey.PSChildName)" `
                    -Description "Image File Execution Options for '$($ifeoKey.PSChildName)' has a Debugger set to '$($debugger.Debugger)'. This causes a different executable to run when the target is launched — a technique used for silent process injection and persistence." `
                    -Remediation "Remove-ItemProperty -Path '$($ifeoKey.PSPath)' -Name 'Debugger'" `
                    -Details @{
                        TargetExe = $ifeoKey.PSChildName
                        Debugger = $debugger.Debugger
                        RegistryPath = $ifeoKey.PSPath
                    } `
                    -MITRE @("T1546.012")
            }
        }
    } catch {}

    try {
        $appInitReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue
        if ($appInitReg -and $appInitReg.LoadAppInit_DLLs -eq 1 -and $appInitReg.AppInit_DLLs) {
            Add-Finding -Severity "CRITICAL" -Category "FileSystem" `
                -Title "AppInit_DLLs Loaded: $($appInitReg.AppInit_DLLs)" `
                -Description "AppInit_DLLs is enabled and set to '$($appInitReg.AppInit_DLLs)'. These DLLs are loaded into every user-mode process, providing system-wide code injection — a powerful persistence and hooking mechanism." `
                -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'LoadAppInit_DLLs' -Value 0" `
                -Details @{ DLLs = $appInitReg.AppInit_DLLs; LoadEnabled = $appInitReg.LoadAppInit_DLLs } `
                -MITRE @("T1546.010")
        }
    } catch {}

    try {
        $winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
        if ($winlogon) {
            if ($winlogon.Shell -and $winlogon.Shell -ne "explorer.exe") {
                Add-Finding -Severity "CRITICAL" -Category "FileSystem" `
                    -Title "Winlogon Shell Hijacked" `
                    -Description "Winlogon Shell is set to '$($winlogon.Shell)' instead of 'explorer.exe'. This controls what runs as the user's desktop shell — modification is a strong persistence indicator." `
                    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Shell' -Value 'explorer.exe'" `
                    -Details @{ CurrentShell = $winlogon.Shell; ExpectedShell = "explorer.exe" } `
                    -MITRE @("T1547.004")
            }

            $expectedUserinit = "C:\Windows\system32\userinit.exe,"
            if ($winlogon.Userinit -and $winlogon.Userinit.Trim() -ne $expectedUserinit -and $winlogon.Userinit.Trim() -ne $expectedUserinit.TrimEnd(',')) {
                Add-Finding -Severity "CRITICAL" -Category "FileSystem" `
                    -Title "Winlogon Userinit Modified" `
                    -Description "Winlogon Userinit is set to '$($winlogon.Userinit)' instead of the default. Additional entries execute at every logon — a persistence technique." `
                    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit' -Value '$expectedUserinit'" `
                    -Details @{ CurrentUserinit = $winlogon.Userinit; ExpectedUserinit = $expectedUserinit } `
                    -MITRE @("T1547.004")
            }
        }
    } catch {}

    # ── 8. COM Hijacking ─────────────────────────────────────────────────

    Write-Status "Checking for COM object hijacking..."

    try {
        $knownComDlls = @('mscoree.dll', 'oleaut32.dll', 'shell32.dll', 'combase.dll', 'ole32.dll', 'actxprxy.dll')
        $comKeys = Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue
        foreach ($clsid in $comKeys) {
            try {
                $inproc = Get-ItemProperty "$($clsid.PSPath)\InProcServer32" -ErrorAction SilentlyContinue
                if (-not $inproc) { continue }
                $dllPath = $inproc.'(default)'
                if (-not $dllPath) { continue }

                if (-not [System.IO.Path]::IsPathRooted($dllPath)) {
                    $dllName = [System.IO.Path]::GetFileName($dllPath)
                    if ($knownComDlls -contains $dllName.ToLower()) { continue }
                    $resolved = Join-Path $env:SystemRoot "System32\$dllPath"
                    if (Test-Path $resolved) {
                        $dllPath = $resolved
                    } else {
                        $resolved = Join-Path $env:SystemRoot "SysWOW64\$dllPath"
                        if (Test-Path $resolved) {
                            $dllPath = $resolved
                        } else {
                            continue
                        }
                    }
                }

                if ($dllPath -notmatch "^C:\\Windows\\" -and $dllPath -notmatch "^C:\\Program Files") {
                    if (-not (Test-Path $dllPath)) { continue }  # stale registration — file gone, can't be exploited
                    $comSig = Get-FileSignature -FilePath $dllPath
                    if ($comSig -and $comSig.Status -eq "Valid") { continue }

                    Add-Finding -Severity "WARNING" -Category "FileSystem" `
                        -Title "COM Hijack: $($clsid.PSChildName)" `
                        -Description "User-level COM object '$($clsid.PSChildName)' points to unsigned DLL '$dllPath' outside standard system directories." `
                        -Remediation "Remove-Item -Path '$($clsid.PSPath)' -Recurse" `
                        -Details @{
                            CLSID = $clsid.PSChildName
                            DLLPath = $dllPath
                            RegistryPath = $clsid.PSPath
                            SignatureStatus = if ($comSig) { $comSig.Status } else { "File not found" }
                        } `
                        -MITRE @("T1546.015")
                }
            } catch {}
        }
    } catch {}

    # ── 9. WMI Persistence ───────────────────────────────────────────────

    Write-Status "Checking for WMI persistence subscriptions..."

    $wmiNamespaces = @("root\subscription", "root\default")

    foreach ($ns in $wmiNamespaces) {
        try {
            $wmiBindings = Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
            $wmiCmdConsumers = Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
            $wmiScriptConsumers = Get-WmiObject -Namespace $ns -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue

            $nsLabel = if ($ns -eq "root\subscription") { "" } else { " [NON-STANDARD: $ns]" }
            $nsSeverity = if ($ns -eq "root\subscription") { "CRITICAL" } else { "CRITICAL" }

            if ($wmiBindings -and $wmiBindings.Count -gt 0) {
                foreach ($binding in $wmiBindings) {
                    Add-Finding -Severity $nsSeverity -Category "FileSystem" `
                        -Title "WMI Persistence Binding Found$nsLabel" `
                        -Description "WMI event subscription binding detected in '$ns': Filter='$($binding.Filter)' Consumer='$($binding.Consumer)'. WMI persistence survives reboots and is nearly invisible to standard tools — heavily used by advanced threats." `
                        -Remediation "Get-WmiObject -Namespace '$ns' -Class __FilterToConsumerBinding | Remove-WmiObject" `
                        -Details @{
                            Namespace = $ns
                            Filter = $binding.Filter
                            Consumer = $binding.Consumer
                        } `
                        -MITRE @("T1546.003")
                }
            }

            if ($wmiCmdConsumers) {
                foreach ($consumer in $wmiCmdConsumers) {
                    Add-Finding -Severity $nsSeverity -Category "FileSystem" `
                        -Title "WMI CommandLine Consumer: $($consumer.Name)$nsLabel" `
                        -Description "WMI CommandLineEventConsumer '$($consumer.Name)' in '$ns' executes: '$($consumer.CommandLineTemplate)'. This will run automatically when the associated WMI event fires." `
                        -Remediation "Get-WmiObject -Namespace '$ns' -Class CommandLineEventConsumer -Filter `"Name='$($consumer.Name)'`" | Remove-WmiObject" `
                        -Details @{ Namespace = $ns; Name = $consumer.Name; Command = $consumer.CommandLineTemplate } `
                        -MITRE @("T1546.003")
                }
            }

            if ($wmiScriptConsumers) {
                foreach ($consumer in $wmiScriptConsumers) {
                    Add-Finding -Severity $nsSeverity -Category "FileSystem" `
                        -Title "WMI Script Consumer: $($consumer.Name)$nsLabel" `
                        -Description "WMI ActiveScriptEventConsumer '$($consumer.Name)' in '$ns' runs script code when triggered. This is a fileless persistence mechanism." `
                        -Remediation "Get-WmiObject -Namespace '$ns' -Class ActiveScriptEventConsumer -Filter `"Name='$($consumer.Name)'`" | Remove-WmiObject" `
                        -Details @{ Namespace = $ns; Name = $consumer.Name; ScriptingEngine = $consumer.ScriptingEngine } `
                        -MITRE @("T1546.003")
                }
            }
        } catch {
            Write-Status "Could not check WMI subscriptions in $ns (may need admin)." -Color Yellow
        }
    }

    # Enumerate non-standard WMI namespaces under root\
    Write-Status "Enumerating WMI namespaces..."
    try {
        $standardNamespaces = @("subscription","cimv2","default","directory","Microsoft","WMI","SECURITY","RSOP","StandardCimv2","msdtc","Cli","nap","MSPS","SecurityCenter","SecurityCenter2","Interop","Hardware","ServiceModel","aspnet","Policy","HyperVCluster","virtualization","Appv","Intel","HP","MSCluster","MSFS","MicrosoftDfs","AccessLogging","PEH")
        $allNamespaces = Get-WmiObject -Namespace root -Class __Namespace -ErrorAction SilentlyContinue
        foreach ($nsObj in $allNamespaces) {
            $nsName = $nsObj.Name
            if ($nsName -notin $standardNamespaces) {
                Add-Finding -Severity "WARNING" -Category "FileSystem" `
                    -Title "Non-Standard WMI Namespace: root\$nsName" `
                    -Description "WMI namespace 'root\$nsName' is not a standard Windows namespace. Attackers create custom namespaces to store payloads and maintain persistence outside normal visibility." `
                    -Remediation "Investigate contents: Get-WmiObject -Namespace 'root\$nsName' -Class __Namespace -ErrorAction SilentlyContinue" `
                    -Details @{ Namespace = "root\$nsName" } `
                    -MITRE @("T1546.003")
            }
        }
    } catch {}

    # ── 10. Scheduled Tasks Check ────────────────────────────────────────

    Write-Status "Checking scheduled tasks for suspicious entries..."

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.State -ne "Disabled" }

        $knownLegitTaskPaths = @(
            "*\OneDrive\*\OneDriveLauncher.exe*",
            "*\OneDrive*\OneDriveStandaloneUpdater.exe*",
            "*\Opera\autoupdate\opera_autoupdate.exe*",
            "*\Zoom\bin\Zoom.exe*",
            "*\Discord\Update.exe*",
            "*\Teams\*\Teams.exe*",
            "*\Update.exe*--processStart*"
        )

        foreach ($task in $tasks) {
            try {
                $actions = $task.Actions
                foreach ($action in $actions) {
                    $execute = $action.Execute
                    if (-not $execute) { continue }
                    $taskArgs = $action.Arguments

                    $suspicious = $false
                    $severity = "INFO"

                    # Known-legitimate updater paths
                    $isKnownLegit = $false
                    foreach ($pattern in $knownLegitTaskPaths) {
                        if ($execute -like $pattern -or "$execute $taskArgs" -like $pattern) {
                            $isKnownLegit = $true; break
                        }
                    }
                    if ($isKnownLegit) { continue }

                    if ($execute -match "\\Temp\\" -or $execute -match "\\AppData\\") {
                        $suspicious = $true
                        $severity = "WARNING"
                    }

                    if ($execute -match "powershell" -and $taskArgs -match "-enc|-e |-WindowStyle\s+Hidden") {
                        $suspicious = $true
                        $severity = "CRITICAL"
                    }

                    if ($execute -match "mshta|wscript|cscript|certutil|bitsadmin") {
                        $suspicious = $true
                        $severity = "WARNING"
                    }

                    if ($suspicious) {
                        Add-Finding -Severity $severity -Category "FileSystem" `
                            -Title "Suspicious Scheduled Task: $($task.TaskName)" `
                            -Description "Scheduled task '$($task.TaskName)' (Path: $($task.TaskPath)) executes: '$execute' with arguments: '$taskArgs'. This task runs as: $($task.Principal.UserId)." `
                            -Remediation "If you don't recognize this task, disable it: Disable-ScheduledTask -TaskName '$($task.TaskName)' -TaskPath '$($task.TaskPath)'" `
                            -Details @{
                                TaskName = $task.TaskName
                                TaskPath = $task.TaskPath
                                Execute = $execute
                                Arguments = $taskArgs
                                RunAs = $task.Principal.UserId
                                State = $task.State.ToString()
                            } `
                            -MITRE @("T1053.005")
                    }
                }
            } catch {}
        }
    } catch {
        Write-Status "Could not enumerate scheduled tasks." -Color Yellow
    }

    # ── 11. Ghost Scheduled Tasks (Registry-based) ───────────────────────

    Write-Status "Checking for ghost/hidden scheduled tasks..."

    try {
        $taskCachePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
        if (Test-Path $taskCachePath) {
            $apiTaskNames = @()
            try {
                $apiTaskNames = Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $_.TaskName }
            } catch {}

            function Walk-TaskCache {
                param([string]$Path, [string]$TaskPathPrefix)
                $subKeys = Get-ChildItem $Path -ErrorAction SilentlyContinue
                foreach ($subKey in $subKeys) {
                    $taskName = $subKey.PSChildName
                    $fullTaskPath = "$TaskPathPrefix$taskName"

                    $sd = Get-ItemProperty $subKey.PSPath -Name "SD" -ErrorAction SilentlyContinue
                    $id = Get-ItemProperty $subKey.PSPath -Name "Id" -ErrorAction SilentlyContinue

                    if ($id -and $id.Id) {
                        if (-not $sd) {
                            Add-Finding -Severity "CRITICAL" -Category "FileSystem" `
                                -Title "Ghost Task (Missing SD): $fullTaskPath" `
                                -Description "Scheduled task '$fullTaskPath' in the registry TaskCache has no Security Descriptor (SD value). Tasks without SD values are hidden from normal tools like Task Scheduler and schtasks. This is a known persistence technique." `
                                -Remediation "Investigate the task GUID $($id.Id) in HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$($id.Id)" `
                                -Details @{
                                    RegistryPath = $subKey.PSPath
                                    TaskGUID = $id.Id
                                    TaskPath = $fullTaskPath
                                } `
                                -MITRE @("T1053.005","T1564.004")
                        }

                        if ($taskName -notin $apiTaskNames -and $fullTaskPath -notmatch '^\\Microsoft\\Windows\\') {
                            Add-Finding -Severity "WARNING" -Category "FileSystem" `
                                -Title "Task Not Visible to API: $fullTaskPath" `
                                -Description "Scheduled task '$fullTaskPath' exists in the registry TaskCache but was not returned by Get-ScheduledTask. This may indicate a tampered or hidden task." `
                                -Remediation "Inspect the task registry entry at $($subKey.PSPath) and check the associated action in TaskCache\Tasks." `
                                -Details @{
                                    RegistryPath = $subKey.PSPath
                                    TaskGUID = $id.Id
                                    TaskPath = $fullTaskPath
                                } `
                                -MITRE @("T1053.005","T1564")
                        }
                    }

                    Walk-TaskCache -Path $subKey.PSPath -TaskPathPrefix "$fullTaskPath\"
                }
            }

            Walk-TaskCache -Path $taskCachePath -TaskPathPrefix "\"
        }
    } catch {
        Write-Status "Could not check ghost scheduled tasks (may need admin)." -Color Yellow
    }

    # ── 12. BITS Job Abuse ───────────────────────────────────────────────

    Write-Status "Checking for suspicious BITS transfer jobs..."

    try {
        $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
        if ($bitsJobs) {
            $knownUpdateUrls = @("mozilla\.org", "mozilla\.com", "mozilla\.net", "google\.com", "googleapis\.com", "microsoft\.com", "windowsupdate\.com", "\.windows\.com", "\.edge\.microsoft\.com", "\.download\.prss\.microsoft\.com")
            $knownPattern = ($knownUpdateUrls -join "|")
            $seenJobs = @{}

            foreach ($job in $bitsJobs) {
                $jobKey = "$($job.DisplayName)|$($job.JobId)"
                if ($seenJobs.ContainsKey($jobKey)) { continue }
                $seenJobs[$jobKey] = $true

                $suspicious = $false
                $severity = "INFO"
                $reasons = @()

                $url = $job.FileList | ForEach-Object { $_.RemoteName } | Select-Object -First 1
                if (-not $url) { $url = "" }

                if ($url -and $url -notmatch $knownPattern) {
                    $suspicious = $true
                    $severity = "WARNING"
                    $reasons += "Non-standard URL"
                }

                if ($url -match "^\d+\.\d+\.\d+\.\d+") {
                    $suspicious = $true
                    $severity = "CRITICAL"
                    $reasons += "Raw IP target"
                }

                if ($job.JobState -in @("Suspended", "Error", "TransientError")) {
                    $suspicious = $true
                    if ($severity -ne "CRITICAL") { $severity = "WARNING" }
                    $reasons += "Abnormal state: $($job.JobState)"
                }

                if ($suspicious) {
                    Add-Finding -Severity $severity -Category "FileSystem" `
                        -Title "Suspicious BITS Job: $($job.DisplayName)" `
                        -Description "BITS transfer job '$($job.DisplayName)' flagged: $($reasons -join '; '). URL: '$url'. BITS jobs can be used for stealthy file downloads that survive reboots and bypass many security tools." `
                        -Remediation "Remove-BitsTransfer -BitsJob (Get-BitsTransfer -Name '$($job.DisplayName)' -AllUsers)" `
                        -Details @{
                            JobName = $job.DisplayName
                            JobState = $job.JobState
                            URL = $url
                            Owner = $job.OwnerAccount
                            CreationTime = $job.CreationTime
                            Reasons = $reasons
                        } `
                        -MITRE @("T1197")
                }
            }
        }
    } catch {
        Write-Status "Could not check BITS jobs (may need admin)." -Color Yellow
    }

    # ── 13. Windows Defender Exclusions ──────────────────────────────────

    Write-Status "Checking Windows Defender exclusions..."

    try {
        $prefs = Get-MpPreference -ErrorAction SilentlyContinue

        $exclusionPaths = $prefs.ExclusionPath
        $exclusionProcesses = $prefs.ExclusionProcess
        $exclusionExtensions = $prefs.ExclusionExtension

        if ($exclusionPaths -and $exclusionPaths.Count -gt 0) {
            foreach ($path in $exclusionPaths) {
                $severity = "WARNING"
                if ($path -match "\\Temp\\" -or $path -match "\\AppData\\" -or $path -match "C:\\$") {
                    $severity = "CRITICAL"
                }

                Add-Finding -Severity $severity -Category "FileSystem" `
                    -Title "Defender Exclusion (Path): $path" `
                    -Description "Windows Defender is configured to exclude path '$path' from scanning. Attackers commonly add exclusions to hide malware." `
                    -Remediation "If you didn't add this exclusion, remove it: Remove-MpPreference -ExclusionPath '$path'" `
                    -Details @{ ExclusionType = "Path"; Value = $path } `
                    -MITRE @("T1562.001")
            }
        }

        if ($exclusionProcesses -and $exclusionProcesses.Count -gt 0) {
            foreach ($proc in $exclusionProcesses) {
                Add-Finding -Severity "WARNING" -Category "FileSystem" `
                    -Title "Defender Exclusion (Process): $proc" `
                    -Description "Windows Defender excludes process '$proc' from scanning." `
                    -Remediation "Remove if unexpected: Remove-MpPreference -ExclusionProcess '$proc'" `
                    -Details @{ ExclusionType = "Process"; Value = $proc } `
                    -MITRE @("T1562.001")
            }
        }

        if ($exclusionExtensions -and $exclusionExtensions.Count -gt 0) {
            foreach ($ext in $exclusionExtensions) {
                Add-Finding -Severity "WARNING" -Category "FileSystem" `
                    -Title "Defender Exclusion (Extension): $ext" `
                    -Description "Windows Defender excludes all '*$ext' files from scanning." `
                    -Remediation "Remove if unexpected: Remove-MpPreference -ExclusionExtension '$ext'" `
                    -Details @{ ExclusionType = "Extension"; Value = $ext } `
                    -MITRE @("T1562.001")
            }
        }
    } catch {
        Write-Status "Could not check Defender exclusions (may need admin)." -Color Yellow
    }

}
