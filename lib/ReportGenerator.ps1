<#
.SYNOPSIS
    Generates a polished HTML report from scan findings.
#>

function Generate-HtmlReport {
    param(
        [System.Collections.ArrayList]$Findings,
        [hashtable]$SystemInfo,
        [string]$OutputFile,
        [timespan]$Duration,
        [string]$Version
    )

    $critCount = ($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $warnCount = ($Findings | Where-Object { $_.Severity -eq "WARNING" }).Count
    $infoCount = ($Findings | Where-Object { $_.Severity -eq "INFO" }).Count
    $totalCount = $Findings.Count

    $maxPenalty = [math]::Max(1, $totalCount)
    $penalty = ($critCount * 25) + ($warnCount * 5) + ($infoCount * 0.5)
    $score = [math]::Max(0, [math]::Min(100, [math]::Round(100 - $penalty)))
    $scoreColor = if ($score -ge 80) { "#22c55e" } elseif ($score -ge 50) { "#f59e0b" } else { "#ef4444" }

    $verdict = "CLEAN"
    $verdictColor = "#22c55e"
    $verdictIcon = "&#x2714;"
    $verdictMessage = "No critical issues detected. Your system appears clean."

    if ($critCount -gt 0) {
        $verdict = "COMPROMISED"
        $verdictColor = "#ef4444"
        $verdictIcon = "&#x2718;"
        $verdictMessage = "Critical indicators of compromise detected. Immediate action required."
    } elseif ($warnCount -gt 3) {
        $verdict = "SUSPICIOUS"
        $verdictColor = "#f59e0b"
        $verdictIcon = "&#x26A0;"
        $verdictMessage = "Multiple warnings detected. Investigation recommended."
    } elseif ($warnCount -gt 0) {
        $verdict = "CAUTION"
        $verdictColor = "#eab308"
        $verdictIcon = "&#x26A0;"
        $verdictMessage = "Some warnings found. Review the findings below."
    }

    $categories = $Findings | Group-Object Category | Sort-Object @{
        Expression = {
            $group = $_
            $maxSev = "INFO"
            foreach ($f in $group.Group) {
                if ($f.Severity -eq "CRITICAL") { $maxSev = "CRITICAL"; break }
                if ($f.Severity -eq "WARNING") { $maxSev = "WARNING" }
            }
            switch ($maxSev) { "CRITICAL" { 0 } "WARNING" { 1 } "INFO" { 2 } }
        }
    }

    $findingsHtml = ""
    foreach ($cat in $categories) {
        $catCrit = ($cat.Group | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $catWarn = ($cat.Group | Where-Object { $_.Severity -eq "WARNING" }).Count
        $catInfo = ($cat.Group | Where-Object { $_.Severity -eq "INFO" }).Count

        $catIcon = switch ($cat.Name) {
            "Process"         { "&#x2699;" }
            "Network"         { "&#x1F310;" }
            "Account"         { "&#x1F464;" }
            "FileSystem"      { "&#x1F4C1;" }
            "DefenseEvasion"  { "&#x1F6E1;" }
            "Baseline"        { "&#x1F4CA;" }
            default           { "&#x1F50D;" }
        }

        $catDisplayName = switch ($cat.Name) {
            "Process"         { "Process &amp; Service Analysis" }
            "Network"         { "Network Indicators" }
            "Account"         { "Account &amp; Authentication" }
            "FileSystem"      { "File System Red Flags" }
            "DefenseEvasion"  { "Defense Evasion &amp; Anti-Forensics" }
            "Baseline"        { "Baseline Comparison" }
            default           { $cat.Name }
        }

        $findingsHtml += @"
        <div class="category-section">
            <div class="category-header" onclick="toggleCategory(this)">
                <div class="category-title">
                    <span class="category-icon">$catIcon</span>
                    <h2>$catDisplayName</h2>
                    <div class="category-badges">
                        $(if ($catCrit -gt 0) { "<span class='badge badge-critical'>$catCrit CRITICAL</span>" })
                        $(if ($catWarn -gt 0) { "<span class='badge badge-warning'>$catWarn WARNING</span>" })
                        $(if ($catInfo -gt 0) { "<span class='badge badge-info'>$catInfo INFO</span>" })
                    </div>
                </div>
                <span class="toggle-icon">&#x25BC;</span>
            </div>
            <div class="category-body">
"@

        $sortedFindings = $cat.Group | Sort-Object @{
            Expression = { switch ($_.Severity) { "CRITICAL" { 0 } "WARNING" { 1 } "INFO" { 2 } } }
        }

        foreach ($finding in $sortedFindings) {
            $sevClass = $finding.Severity.ToLower()
            $sevIcon = switch ($finding.Severity) {
                "CRITICAL" { "&#x1F534;" }
                "WARNING"  { "&#x1F7E1;" }
                "INFO"     { "&#x1F535;" }
            }

            $mitreHtml = ""
            if ($finding.MITRE -and $finding.MITRE.Count -gt 0) {
                $mitreHtml = "<span class='mitre-tags'>"
                foreach ($tid in $finding.MITRE) {
                    $urlPath = ($tid -replace '\.', '/')
                    $mitreHtml += "<a class='mitre-badge' href='https://attack.mitre.org/techniques/$urlPath/' target='_blank' rel='noopener'>$tid</a>"
                }
                $mitreHtml += "</span>"
            }

            $detailsHtml = ""
            if ($finding.Details) {
                $detailsHtml = @"
                <div class="finding-details">
                    <button class="details-toggle" onclick="toggleDetails(this)">Show Technical Details</button>
                    <pre class="details-content" style="display:none;">$($finding.Details | ConvertTo-Json -Depth 3 | ForEach-Object { $_ -replace '<','&lt;' -replace '>','&gt;' })</pre>
                </div>
"@
            }

            $remediationHtml = ""
            if ($finding.Remediation) {
                $escapedRemediation = $finding.Remediation -replace '<','&lt;' -replace '>','&gt;'
                $remediationWithCopy = $escapedRemediation -replace '((?:Remove-|Set-|Disable-|Enable-|Get-|Stop-|Start-|Update-|New-|Add-|Unregister-)[A-Za-z\-]+(?:\s+[^\r\n]*?)?)(?=\s*$|\.)', '<code class="ps-cmd" onclick="copyCmd(this)">$1</code>'
                $remediationHtml = "<div class='finding-remediation'><strong>&#x1F6E0; Remediation:</strong> $remediationWithCopy</div>"
            }

            $escapedDescription = $finding.Description -replace '<','&lt;' -replace '>','&gt;'

            $findingsHtml += @"
                <div class="finding finding-$sevClass" data-severity="$sevClass">
                    <div class="finding-header">
                        <span class="finding-severity">$sevIcon $($finding.Severity)</span>
                        <span class="finding-title">$($finding.Title)</span>
                        $mitreHtml
                    </div>
                    <div class="finding-body">
                        <p>$escapedDescription</p>
                        $remediationHtml
                        $detailsHtml
                    </div>
                </div>
"@
        }

        $findingsHtml += @"
            </div>
        </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Am I Hacked? — Security Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

        :root {
            --bg-primary: #0f1117;
            --bg-secondary: #161822;
            --bg-card: #1c1f2e;
            --bg-card-hover: #252838;
            --border: #2a2d3e;
            --text-primary: #e4e4e7;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --critical: #ef4444;
            --critical-bg: rgba(239,68,68,0.06);
            --critical-border: rgba(239,68,68,0.18);
            --warning: #f59e0b;
            --warning-bg: rgba(245,158,11,0.06);
            --warning-border: rgba(245,158,11,0.18);
            --info: #3b82f6;
            --info-bg: rgba(59,130,246,0.06);
            --info-border: rgba(59,130,246,0.18);
            --green: #22c55e;
            --accent: #8b5cf6;

            /* Terminal Mode overrides */
            --neon-red: #ff1744;
            --neon-amber: #ffd600;
            --neon-blue: #00b0ff;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        /* ── Terminal Mode ── */
        body.terminal-mode {
            background-image:
                radial-gradient(ellipse at 20% 50%, rgba(139,92,246,0.04) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 20%, rgba(255,26,68,0.03) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 80%, rgba(0,176,255,0.03) 0%, transparent 50%);
        }

        body.terminal-mode::after {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background:
                repeating-linear-gradient(0deg, rgba(0,0,0,0.06) 0px, rgba(0,0,0,0.06) 1px, transparent 1px, transparent 3px),
                radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,0.4) 100%);
            pointer-events: none;
            z-index: 9999;
        }

        body.terminal-mode .report-header h1 {
            background: linear-gradient(135deg, var(--neon-red) 0%, #b388ff 40%, var(--neon-blue) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: glitch-skew 4s infinite linear alternate-reverse;
        }

        body.terminal-mode .verdict-banner {
            animation: verdict-pulse 3s ease-in-out infinite;
        }

        body.terminal-mode .finding-critical { border-left-color: var(--neon-red); }
        body.terminal-mode .finding-critical:hover { box-shadow: -4px 0 12px rgba(255,23,68,0.15); }
        body.terminal-mode .finding-warning { border-left-color: var(--neon-amber); }
        body.terminal-mode .finding-warning:hover { box-shadow: -4px 0 12px rgba(255,214,0,0.1); }
        body.terminal-mode .finding-info { border-left-color: var(--neon-blue); }

        body.terminal-mode .category-section:hover { border-color: rgba(179,136,255,0.3); }
        body.terminal-mode .stat-card:hover { box-shadow: 0 0 15px rgba(179,136,255,0.15); }

        @keyframes glitch-skew {
            0%, 95% { transform: none; }
            96% { transform: skewX(-2deg) translateX(-2px); }
            97% { transform: skewX(1deg) translateX(1px); }
            98% { transform: skewX(-1deg); }
            100% { transform: none; }
        }

        @keyframes verdict-pulse {
            0%, 100% { box-shadow: 0 0 20px ${verdictColor}15, 0 0 60px ${verdictColor}08; }
            50% { box-shadow: 0 0 30px ${verdictColor}25, 0 0 80px ${verdictColor}12; }
        }

        .container {
            max-width: 1100px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Header */
        .report-header {
            text-align: center;
            padding: 3rem 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }

        .report-header h1 {
            font-family: 'Share Tech Mono', 'JetBrains Mono', monospace;
            font-size: 2.8rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
        }

        .report-header .subtitle {
            font-size: 0.9rem;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }

        .header-actions {
            display: flex;
            justify-content: center;
            gap: 0.5rem;
            margin-top: 1rem;
        }

        .header-btn {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            padding: 0.35rem 0.75rem;
            border-radius: 4px;
            border: 1px solid var(--border);
            background: var(--bg-card);
            color: var(--text-muted);
            cursor: pointer;
            transition: all 0.2s;
        }
        .header-btn:hover { background: var(--bg-card-hover); color: var(--text-primary); }
        .header-btn.active { border-color: var(--accent); color: var(--accent); }

        /* Verdict Banner */
        .verdict-banner {
            background: var(--bg-secondary);
            border: 2px solid ${verdictColor};
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
        }

        .verdict-banner::before {
            content: '';
            position: absolute;
            top: -50%; left: -50%; width: 200%; height: 200%;
            background: radial-gradient(circle, ${verdictColor}08 0%, transparent 70%);
            pointer-events: none;
        }

        .verdict-icon { font-size: 3rem; margin-bottom: 0.5rem; }

        .verdict-label {
            font-family: 'Share Tech Mono', monospace;
            font-size: 2rem;
            font-weight: 700;
            color: ${verdictColor};
            margin-bottom: 0.5rem;
            letter-spacing: 0.15em;
        }

        .verdict-message { color: var(--text-secondary); font-size: 1rem; }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            text-align: center;
            transition: border-color 0.3s, box-shadow 0.3s;
        }
        .stat-card:hover { border-color: var(--accent); box-shadow: 0 0 12px rgba(139,92,246,0.1); }

        /* Score Ring */
        .score-section {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        .score-ring-container { position: relative; width: 120px; height: 120px; }
        .score-ring { transform: rotate(-90deg); }
        .score-ring-bg { fill: none; stroke: var(--border); stroke-width: 8; }
        .score-ring-fill { fill: none; stroke-width: 8; stroke-linecap: round; transition: stroke-dashoffset 1.5s ease-out; }
        .score-value {
            position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
            font-family: 'Share Tech Mono', monospace; font-size: 2rem; font-weight: 700;
        }
        .score-label {
            font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;
            letter-spacing: 0.1em; text-align: center; margin-top: 0.25rem;
        }

        .stat-value {
            font-family: 'Share Tech Mono', monospace;
            font-size: 2rem;
            font-weight: 700;
        }

        .stat-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .stat-critical .stat-value { color: var(--critical); }
        .stat-warning .stat-value { color: var(--warning); }
        .stat-info .stat-value { color: var(--info); }
        .stat-total .stat-value { color: var(--text-primary); }

        /* System Info */
        .system-info {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 2rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.75rem;
            font-size: 0.85rem;
        }

        .system-info div { display: flex; flex-direction: column; }
        .system-info .label { color: var(--text-muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .system-info .value { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: var(--text-primary); }

        /* Category Sections */
        .category-section {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 1rem;
            overflow: hidden;
            transition: border-color 0.3s;
        }

        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.25rem;
            cursor: pointer;
            user-select: none;
            transition: background 0.2s;
        }

        .category-header:hover { background: var(--bg-card); }

        .category-title { display: flex; align-items: center; gap: 0.75rem; }
        .category-title h2 { font-size: 1rem; font-weight: 600; }
        .category-icon { font-size: 1.25rem; }
        .category-badges { display: flex; gap: 0.5rem; }

        .badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
        }

        .badge-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical-border); }
        .badge-warning { background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning-border); }
        .badge-info { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }

        .toggle-icon { color: var(--text-muted); font-size: 0.8rem; transition: transform 0.3s; }
        .collapsed .toggle-icon { transform: rotate(-90deg); }
        .collapsed + .category-body { display: none; }
        .category-body { padding: 0 1.25rem 1.25rem; }

        /* Findings */
        .finding {
            border-radius: 8px;
            margin-bottom: 0.75rem;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.3s;
        }
        .finding:hover { transform: translateX(2px); }

        .finding-critical {
            background: var(--critical-bg);
            border: 1px solid var(--critical-border);
            border-left: 3px solid var(--critical);
        }

        .finding-warning {
            background: var(--warning-bg);
            border: 1px solid var(--warning-border);
            border-left: 3px solid var(--warning);
        }

        .finding-info {
            background: var(--info-bg);
            border: 1px solid var(--info-border);
            border-left: 3px solid var(--info);
        }

        .finding-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            flex-wrap: wrap;
        }

        .finding-severity {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 700;
            white-space: nowrap;
        }

        .finding-title { font-weight: 600; font-size: 0.9rem; }

        .finding-body {
            padding: 0 1rem 0.75rem;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        .finding-body p { margin-bottom: 0.5rem; }

        /* MITRE ATT&CK badges */
        .mitre-tags { display: inline-flex; gap: 0.35rem; margin-left: auto; flex-wrap: wrap; }

        .mitre-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.6rem;
            font-weight: 600;
            padding: 0.1rem 0.4rem;
            border-radius: 3px;
            background: rgba(139,92,246,0.1);
            color: var(--accent);
            border: 1px solid rgba(139,92,246,0.25);
            text-decoration: none;
            transition: all 0.2s;
            white-space: nowrap;
        }
        .mitre-badge:hover {
            background: rgba(139,92,246,0.2);
            border-color: var(--accent);
            color: #c4b5fd;
        }

        .finding-remediation {
            background: rgba(139,92,246,0.04);
            border-radius: 4px;
            padding: 0.5rem 0.75rem;
            margin-top: 0.5rem;
            font-size: 0.8rem;
            border-left: 3px solid var(--accent);
        }

        .ps-cmd {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            background: rgba(0,0,0,0.3);
            border: 1px solid var(--border);
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            cursor: pointer;
            color: var(--info);
            position: relative;
            transition: background 0.2s, border-color 0.2s;
        }
        .ps-cmd:hover { background: rgba(59,130,246,0.1); border-color: var(--info); }
        .ps-cmd.copied { border-color: var(--green); color: var(--green); }
        .ps-cmd::after { content: ' ⧉'; font-size: 0.65rem; opacity: 0.5; }
        .ps-cmd.copied::after { content: ' ✓'; opacity: 1; }

        .details-toggle {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 0.5rem;
            transition: all 0.2s;
        }
        .details-toggle:hover { background: rgba(255,255,255,0.08); }

        .details-content {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 0.75rem;
            margin-top: 0.5rem;
            overflow-x: auto;
            color: var(--text-secondary);
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* Filter Controls */
        .filter-bar {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }

        .filter-btn {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            padding: 0.4rem 1rem;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: var(--bg-card);
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
        }
        .filter-btn:hover { background: var(--bg-card-hover); }
        .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(139,92,246,0.08); }

        /* Footer */
        .report-footer {
            text-align: center;
            padding: 2rem 0;
            margin-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.8rem;
        }
        .report-footer a { color: var(--accent); text-decoration: none; }

        /* Notification toast */
        .toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--bg-card);
            border: 1px solid var(--green);
            color: var(--green);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            opacity: 0;
            transform: translateY(10px);
            transition: all 0.3s;
            z-index: 10000;
            pointer-events: none;
        }
        .toast.show { opacity: 1; transform: translateY(0); }

        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .container { padding: 1rem; }
            .report-header h1 { font-size: 1.75rem; }
        }

        @media print {
            body, body.terminal-mode::after { background: white !important; color: black !important; }
            body.terminal-mode::after { display: none !important; }
            .filter-bar, .header-actions, .toast { display: none !important; }
            .verdict-banner { animation: none !important; box-shadow: none !important; border-color: #333 !important; }
            .finding { break-inside: avoid; animation: none !important; }
            .report-header h1 { -webkit-text-fill-color: #333 !important; background: none !important; color: #333 !important; }
            .category-body { display: block !important; }
            .details-content { display: block !important; background: #f5f5f5 !important; color: #333 !important; }
            .stat-card, .system-info, .category-section, .finding {
                background: #fafafa !important; border-color: #ddd !important; color: #333 !important;
            }
            .finding-remediation { border-left-color: #666 !important; background: #f0f0f0 !important; }
            .ps-cmd { background: #e8e8e8 !important; color: #333 !important; border-color: #ccc !important; }
            .ps-cmd::after { display: none; }
            .stat-value, .verdict-label { color: #333 !important; }
            .report-footer, .system-info .label, .stat-label { color: #666 !important; }
            .badge { background: #eee !important; color: #333 !important; border-color: #ccc !important; }
            .mitre-badge { background: #eee !important; color: #555 !important; border-color: #ccc !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>AM I HACKED?</h1>
            <div class="subtitle">Windows Security Assessment Report &mdash; v${Version}</div>
            <div class="header-actions">
                <button class="header-btn" onclick="toggleTerminalMode(this)">Terminal Mode</button>
                <button class="header-btn" onclick="expandAll()">Expand All</button>
                <button class="header-btn" onclick="collapseAll()">Collapse All</button>
                <button class="header-btn" onclick="window.print()">Print</button>
            </div>
        </div>

        <div class="verdict-banner">
            <div class="verdict-icon">${verdictIcon}</div>
            <div class="verdict-label">${verdict}</div>
            <div class="verdict-message">${verdictMessage}</div>
        </div>

        <div class="score-section">
            <div>
                <div class="score-ring-container">
                    <svg class="score-ring" viewBox="0 0 120 120" width="120" height="120">
                        <circle class="score-ring-bg" cx="60" cy="60" r="52"/>
                        <circle class="score-ring-fill" cx="60" cy="60" r="52"
                            stroke="${scoreColor}"
                            stroke-dasharray="326.73"
                            stroke-dashoffset="326.73"
                            data-target="$([math]::Round(326.73 * (1 - $score / 100), 2))"/>
                    </svg>
                    <div class="score-value" style="color:${scoreColor}">${score}</div>
                </div>
                <div class="score-label">Security Score</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card stat-critical">
                <div class="stat-value">${critCount}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card stat-warning">
                <div class="stat-value">${warnCount}</div>
                <div class="stat-label">Warnings</div>
            </div>
            <div class="stat-card stat-info">
                <div class="stat-value">${infoCount}</div>
                <div class="stat-label">Info</div>
            </div>
            <div class="stat-card stat-total">
                <div class="stat-value">${totalCount}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>

        <div class="system-info">
            <div><span class="label">Computer</span><span class="value">$($SystemInfo.ComputerName)</span></div>
            <div><span class="label">User</span><span class="value">$($SystemInfo.Domain)\$($SystemInfo.UserName)</span></div>
            <div><span class="label">OS</span><span class="value">$($SystemInfo.OSVersion)</span></div>
            <div><span class="label">Build</span><span class="value">$($SystemInfo.OSBuild)</span></div>
            <div><span class="label">Admin</span><span class="value">$(if ($SystemInfo.IsAdmin) { 'Yes' } else { 'No' })</span></div>
            <div><span class="label">Scan Time</span><span class="value">$($SystemInfo.ScanTime.ToString('yyyy-MM-dd HH:mm:ss'))</span></div>
            <div><span class="label">Duration</span><span class="value">$([math]::Round($Duration.TotalSeconds, 1))s</span></div>
            <div><span class="label">PowerShell</span><span class="value">$($SystemInfo.PSVersion)</span></div>
        </div>

        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterFindings('all')">All ($totalCount)</button>
            <button class="filter-btn" onclick="filterFindings('critical')">Critical ($critCount)</button>
            <button class="filter-btn" onclick="filterFindings('warning')">Warning ($warnCount)</button>
            <button class="filter-btn" onclick="filterFindings('info')">Info ($infoCount)</button>
        </div>

        ${findingsHtml}

        <div class="report-footer">
            <p><strong>Am I Hacked?</strong> v${Version} &mdash; Generated $($SystemInfo.ScanTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
            <p>This report is a point-in-time assessment. It does not guarantee security.</p>
            <p style="margin-top:0.5rem;"><a href="https://github.com/TMHSDigital/Am-I-Hacked">github.com/TMHSDigital/Am-I-Hacked</a></p>
        </div>
    </div>

    <div class="toast" id="copyToast">Copied to clipboard</div>

    <script>
        function toggleCategory(header) {
            header.classList.toggle('collapsed');
            const body = header.nextElementSibling;
            body.style.display = body.style.display === 'none' ? 'block' : 'none';
        }

        function toggleDetails(btn) {
            const pre = btn.nextElementSibling;
            if (pre.style.display === 'none') {
                pre.style.display = 'block';
                btn.textContent = 'Hide Technical Details';
            } else {
                pre.style.display = 'none';
                btn.textContent = 'Show Technical Details';
            }
        }

        function filterFindings(level) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            document.querySelectorAll('.finding').forEach(f => {
                if (level === 'all') {
                    f.style.display = 'block';
                } else {
                    f.style.display = f.dataset.severity === level ? 'block' : 'none';
                }
            });
        }

        function toggleTerminalMode(btn) {
            document.body.classList.toggle('terminal-mode');
            btn.classList.toggle('active');
        }

        function expandAll() {
            document.querySelectorAll('.category-header').forEach(h => {
                h.classList.remove('collapsed');
                const body = h.nextElementSibling;
                if (body) body.style.display = 'block';
            });
            document.querySelectorAll('.details-content').forEach(d => {
                d.style.display = 'block';
                const btn = d.previousElementSibling;
                if (btn) btn.textContent = 'Hide Technical Details';
            });
        }

        function copyCmd(el) {
            const text = el.textContent.replace(/ [⧉✓]$/, '');
            navigator.clipboard.writeText(text).then(() => {
                el.classList.add('copied');
                showToast('Copied to clipboard');
                setTimeout(() => el.classList.remove('copied'), 2000);
            }).catch(() => {
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                el.classList.add('copied');
                showToast('Copied to clipboard');
                setTimeout(() => el.classList.remove('copied'), 2000);
            });
        }

        function showToast(msg) {
            const t = document.getElementById('copyToast');
            t.textContent = msg;
            t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 2000);
        }

        function collapseAll() {
            document.querySelectorAll('.category-header').forEach(h => {
                h.classList.add('collapsed');
                const body = h.nextElementSibling;
                if (body) body.style.display = 'none';
            });
        }

        // Auto-collapse INFO-only categories and animate score ring on load
        document.addEventListener('DOMContentLoaded', () => {
            document.querySelectorAll('.category-section').forEach(s => {
                const hasCrit = s.querySelector('.finding-critical');
                const hasWarn = s.querySelector('.finding-warning');
                if (!hasCrit && !hasWarn) {
                    const header = s.querySelector('.category-header');
                    if (header) {
                        header.classList.add('collapsed');
                        const body = header.nextElementSibling;
                        if (body) body.style.display = 'none';
                    }
                }
            });

            const ring = document.querySelector('.score-ring-fill');
            if (ring) {
                const target = ring.dataset.target;
                setTimeout(() => { ring.style.strokeDashoffset = target; }, 200);
            }
        });
    </script>
</body>
</html>
"@

    $html | Set-Content $OutputFile -Encoding UTF8
    Write-Status "HTML report generated: $OutputFile"
}
