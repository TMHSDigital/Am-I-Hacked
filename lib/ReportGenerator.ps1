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
        [string]$Version,
        [int]$SuppressedCount = 0
    )

    $critCount = ($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $warnCount = ($Findings | Where-Object { $_.Severity -eq "WARNING" }).Count
    $infoCount = ($Findings | Where-Object { $_.Severity -eq "INFO" }).Count
    $totalCount = $Findings.Count

    # Score weights: CRITICAL=-25, WARNING=-5, INFO=-0.5; result clamped to [0,100] (4+ criticals always score 0)
    $penalty = ($critCount * 25) + ($warnCount * 5) + ($infoCount * 0.5)
    $score = [math]::Max(0, [math]::Min(100, [math]::Round(100 - $penalty)))
    $scoreColor = if ($score -ge 80) { "#22c55e" } elseif ($score -ge 50) { "#f59e0b" } else { "#ef4444" }

    $verdict = "CLEAN"
    $verdictColor = "#22c55e"
    $verdictIcon = "check"
    $verdictMessage = "No critical issues detected. Your system appears clean."

    if ($critCount -gt 0) {
        $verdict = "COMPROMISED"
        $verdictColor = "#ef4444"
        $verdictIcon = "critical"
        $verdictMessage = "Critical indicators of compromise detected. Immediate action required."
    } elseif ($warnCount -gt 3) {
        $verdict = "SUSPICIOUS"
        $verdictColor = "#f59e0b"
        $verdictIcon = "warning"
        $verdictMessage = "Multiple warnings detected. Investigation recommended."
    } elseif ($warnCount -gt 0) {
        $verdict = "CAUTION"
        $verdictColor = "#eab308"
        $verdictIcon = "warning"
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
                    <pre class="details-content" style="display:none;">$([System.Net.WebUtility]::HtmlEncode(($finding.Details | ConvertTo-Json -Depth 3)))</pre>
                </div>
"@
            }

            $remediationHtml = ""
            if ($finding.Remediation) {
                $escapedRemediation = $finding.Remediation -replace '<','&lt;' -replace '>','&gt;'
                $remediationWithCopy = $escapedRemediation -replace '((?:Remove-|Set-|Disable-|Enable-|Get-|Stop-|Start-|Update-|New-|Add-|Unregister-)[A-Za-z\-]+(?:\s+[^\r\n]*?)?)(?=\s*$|\.)', '<code class="ps-cmd" onclick="copyCmd(this)">$1</code>'
                $remediationHtml = "<div class='finding-remediation'><span class='remediation-label'>Remediation:</span> $remediationWithCopy</div>"
            }

            $escapedDescription = $finding.Description -replace '<','&lt;' -replace '>','&gt;'

            $findingsHtml += @"
                <div class="finding finding-$sevClass" data-severity="$sevClass">
                    <div class="finding-header">
                        <span class="sev-indicator sev-$sevClass"></span>
                        <span class="finding-severity">$($finding.Severity)</span>
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
    <title>Am I Hacked? -- Security Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700;800;900&display=swap');

        :root {
            --bg-primary: #0d0f14;
            --bg-secondary: #141720;
            --bg-card: #1a1d2a;
            --bg-card-hover: #21253a;
            --border: #262a3d;
            --border-subtle: #1e2235;
            --text-primary: #e8e8ec;
            --text-secondary: #a0a0b0;
            --text-muted: #6b6b80;
            --critical: #f04444;
            --critical-bg: rgba(240,68,68,0.05);
            --critical-border: rgba(240,68,68,0.15);
            --warning: #eba020;
            --warning-bg: rgba(235,160,32,0.05);
            --warning-border: rgba(235,160,32,0.15);
            --info: #4488ee;
            --info-bg: rgba(68,136,238,0.05);
            --info-border: rgba(68,136,238,0.15);
            --green: #22c55e;
            --accent: #7c6cf0;
            --accent-border: rgba(124,108,240,0.25);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.65;
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
        }

        /* -- Terminal Mode -- */
        body.terminal-mode {
            background-image:
                radial-gradient(ellipse at 20% 50%, rgba(124,108,240,0.04) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 20%, rgba(240,68,68,0.03) 0%, transparent 50%);
        }

        body.terminal-mode::after {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: repeating-linear-gradient(
                0deg, rgba(0,0,0,0.05) 0px, rgba(0,0,0,0.05) 1px, transparent 1px, transparent 3px
            );
            pointer-events: none;
            z-index: 9999;
        }

        body.terminal-mode .report-header h1 {
            background: linear-gradient(135deg, var(--critical) 0%, #b388ff 50%, var(--info) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        body.terminal-mode .verdict-banner { animation: verdict-pulse 4s ease-in-out infinite; }
        body.terminal-mode .finding-critical { border-left-color: #ff2244; }
        body.terminal-mode .finding-critical:hover { box-shadow: -4px 0 16px rgba(255,34,68,0.12); }
        body.terminal-mode .category-section:hover { border-color: rgba(124,108,240,0.3); }

        @keyframes verdict-pulse {
            0%, 100% { box-shadow: 0 0 20px ${verdictColor}10, 0 0 60px ${verdictColor}05; }
            50% { box-shadow: 0 0 30px ${verdictColor}18, 0 0 80px ${verdictColor}08; }
        }

        .container {
            max-width: 1060px;
            margin: 0 auto;
            padding: 2.5rem 2rem;
        }

        /* -- Header -- */
        .report-header {
            text-align: center;
            padding: 3rem 0 2.5rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2.5rem;
        }

        .report-header h1 {
            font-family: 'Inter', sans-serif;
            font-size: 2.4rem;
            font-weight: 900;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
        }

        .report-header .subtitle {
            font-size: 0.85rem;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: 0.02em;
        }

        .header-actions {
            display: flex;
            justify-content: center;
            gap: 0.5rem;
            margin-top: 1.25rem;
        }

        .header-btn {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            padding: 0.4rem 0.85rem;
            border-radius: 4px;
            border: 1px solid var(--border);
            background: var(--bg-card);
            color: var(--text-muted);
            cursor: pointer;
            transition: all 0.2s;
            letter-spacing: 0.02em;
        }
        .header-btn:hover { background: var(--bg-card-hover); color: var(--text-primary); }
        .header-btn.active { border-color: var(--accent); color: var(--accent); }

        /* -- Verdict Banner -- */
        .verdict-banner {
            background: var(--bg-secondary);
            border: 1px solid ${verdictColor}40;
            border-radius: 10px;
            padding: 2.5rem 2rem;
            text-align: center;
            margin-bottom: 2.5rem;
            position: relative;
            overflow: hidden;
        }

        .verdict-banner::before {
            content: '';
            position: absolute;
            top: -50%; left: -50%; width: 200%; height: 200%;
            background: radial-gradient(circle, ${verdictColor}06 0%, transparent 70%);
            pointer-events: none;
        }

        .verdict-icon {
            width: 48px; height: 48px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: white;
        }

        .verdict-icon.icon-check { background: var(--green); }
        .verdict-icon.icon-warning { background: var(--warning); }
        .verdict-icon.icon-critical { background: var(--critical); }

        .verdict-label {
            font-family: 'Inter', sans-serif;
            font-size: 1.6rem;
            font-weight: 800;
            color: ${verdictColor};
            margin-bottom: 0.5rem;
            letter-spacing: 0.15em;
            text-transform: uppercase;
        }

        .verdict-message { color: var(--text-secondary); font-size: 0.9rem; }

        /* -- Score Ring -- */
        .score-section {
            display: flex;
            justify-content: center;
            margin-bottom: 2.5rem;
        }
        .score-ring-wrap { text-align: center; }
        .score-ring-container { position: relative; width: 110px; height: 110px; }
        .score-ring { transform: rotate(-90deg); }
        .score-ring-bg { fill: none; stroke: var(--border); stroke-width: 7; }
        .score-ring-fill { fill: none; stroke-width: 7; stroke-linecap: round; transition: stroke-dashoffset 1.5s ease-out; }
        .score-value {
            position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
            font-family: 'JetBrains Mono', monospace; font-size: 1.75rem; font-weight: 700;
        }
        .score-label {
            font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;
            letter-spacing: 0.1em; margin-top: 0.5rem;
        }

        /* -- Stats Grid -- */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2.5rem;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem 1rem;
            text-align: center;
            transition: border-color 0.3s;
        }
        .stat-card:hover { border-color: var(--accent); }

        .stat-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 0.35rem;
        }

        .stat-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            font-weight: 500;
        }

        .stat-critical .stat-value { color: var(--critical); }
        .stat-warning .stat-value { color: var(--warning); }
        .stat-info .stat-value { color: var(--info); }
        .stat-total .stat-value { color: var(--text-primary); }
        .stat-suppressed .stat-value { color: var(--text-secondary); }

        /* -- System Info -- */
        .system-info {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 2.5rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            font-size: 0.85rem;
        }

        .system-info div { display: flex; flex-direction: column; gap: 0.15rem; }
        .system-info .label { color: var(--text-muted); font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }
        .system-info .value { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--text-primary); }

        /* -- Filter Controls -- */
        .filter-bar {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }

        .filter-btn {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            padding: 0.45rem 1rem;
            border-radius: 5px;
            border: 1px solid var(--border);
            background: var(--bg-card);
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
            font-weight: 500;
        }
        .filter-btn:hover { background: var(--bg-card-hover); }
        .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(124,108,240,0.06); }

        /* -- Category Sections -- */
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
            padding: 1rem 1.5rem;
            cursor: pointer;
            user-select: none;
            transition: background 0.2s;
        }
        .category-header:hover { background: var(--bg-card); }

        .category-title { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
        .category-title h2 { font-size: 0.95rem; font-weight: 700; letter-spacing: 0.01em; }
        .category-badges { display: flex; gap: 0.5rem; }

        .badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.65rem;
            font-weight: 600;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            letter-spacing: 0.02em;
        }

        .badge-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical-border); }
        .badge-warning { background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning-border); }
        .badge-info { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-border); }

        .toggle-icon { color: var(--text-muted); font-size: 0.75rem; transition: transform 0.3s; }
        .collapsed .toggle-icon { transform: rotate(-90deg); }
        .collapsed + .category-body { display: none; }
        .category-body { padding: 0 1.5rem 1.5rem; }

        /* -- Findings -- */
        .finding {
            border-radius: 8px;
            margin-bottom: 0.75rem;
            overflow: hidden;
            transition: transform 0.15s;
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
            gap: 0.65rem;
            padding: 0.85rem 1.15rem;
            flex-wrap: wrap;
        }

        .sev-indicator {
            width: 8px; height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .sev-critical { background: var(--critical); box-shadow: 0 0 6px var(--critical); }
        .sev-warning { background: var(--warning); box-shadow: 0 0 6px var(--warning); }
        .sev-info { background: var(--info); }

        .finding-severity {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            font-weight: 700;
            white-space: nowrap;
            letter-spacing: 0.04em;
        }

        .finding-title { font-weight: 600; font-size: 0.88rem; }

        .finding-body {
            padding: 0 1.15rem 0.85rem;
            font-size: 0.83rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }
        .finding-body p { margin-bottom: 0.5rem; }

        /* -- MITRE ATT&CK badges -- */
        .mitre-tags { display: inline-flex; gap: 0.35rem; margin-left: auto; flex-wrap: wrap; }

        .mitre-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.58rem;
            font-weight: 600;
            padding: 0.12rem 0.45rem;
            border-radius: 3px;
            background: rgba(124,108,240,0.08);
            color: var(--accent);
            border: 1px solid var(--accent-border);
            text-decoration: none;
            transition: all 0.2s;
            white-space: nowrap;
            letter-spacing: 0.02em;
        }
        .mitre-badge:hover {
            background: rgba(124,108,240,0.16);
            border-color: var(--accent);
            color: #c4b5fd;
        }

        /* -- Remediation -- */
        .finding-remediation {
            background: rgba(124,108,240,0.04);
            border-radius: 5px;
            padding: 0.6rem 0.85rem;
            margin-top: 0.5rem;
            font-size: 0.78rem;
            border-left: 3px solid var(--accent);
            line-height: 1.6;
        }

        .remediation-label {
            font-weight: 700;
            color: var(--text-primary);
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .ps-cmd {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            background: rgba(0,0,0,0.35);
            border: 1px solid var(--border);
            padding: 0.15rem 0.45rem;
            border-radius: 3px;
            cursor: pointer;
            color: var(--info);
            transition: background 0.2s, border-color 0.2s;
        }
        .ps-cmd:hover { background: rgba(68,136,238,0.1); border-color: var(--info); }
        .ps-cmd.copied { border-color: var(--green); color: var(--green); }
        .ps-cmd::after { content: ' ^'; font-size: 0.6rem; opacity: 0.4; }
        .ps-cmd.copied::after { content: ' ok'; opacity: 1; }

        /* -- Details -- */
        .details-toggle {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.68rem;
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.3rem 0.85rem;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 0.5rem;
            transition: all 0.2s;
        }
        .details-toggle:hover { background: rgba(255,255,255,0.06); color: var(--text-secondary); }

        .details-content {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.68rem;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 5px;
            padding: 0.85rem;
            margin-top: 0.5rem;
            overflow-x: auto;
            color: var(--text-secondary);
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.5;
        }

        /* -- Footer -- */
        .report-footer {
            text-align: center;
            padding: 2.5rem 0;
            margin-top: 2.5rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.78rem;
            line-height: 1.8;
        }
        .report-footer a { color: var(--accent); text-decoration: none; }

        /* -- Toast -- */
        .toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--bg-card);
            border: 1px solid var(--green);
            color: var(--green);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
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
            .container { padding: 1.25rem; }
            .report-header h1 { font-size: 1.5rem; }
        }

        @media print {
            body, body.terminal-mode::after { background: white !important; color: #1a1a1a !important; }
            body.terminal-mode::after { display: none !important; }
            .filter-bar, .header-actions, .toast { display: none !important; }
            .verdict-banner { animation: none !important; box-shadow: none !important; border-color: #ccc !important; }
            .finding { break-inside: avoid; }
            .report-header h1 { -webkit-text-fill-color: #1a1a1a !important; background: none !important; color: #1a1a1a !important; }
            .category-body { display: block !important; }
            .details-content { display: block !important; background: #f5f5f5 !important; color: #333 !important; }
            .stat-card, .system-info, .category-section, .finding {
                background: #fafafa !important; border-color: #ddd !important; color: #333 !important;
            }
            .finding-remediation { border-left-color: #888 !important; background: #f0f0f0 !important; }
            .ps-cmd { background: #e8e8e8 !important; color: #333 !important; border-color: #ccc !important; }
            .ps-cmd::after { display: none; }
            .stat-value, .verdict-label { color: #333 !important; }
            .report-footer, .system-info .label, .stat-label { color: #666 !important; }
            .badge { background: #eee !important; color: #333 !important; border-color: #ccc !important; }
            .mitre-badge { background: #eee !important; color: #555 !important; border-color: #ccc !important; }
            .sev-indicator { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>AM I HACKED?</h1>
            <div class="subtitle">Security Assessment Report &mdash; v${Version}</div>
            <div class="header-actions">
                <button class="header-btn" onclick="toggleTerminalMode(this)">Terminal Mode</button>
                <button class="header-btn" onclick="expandAll()">Expand All</button>
                <button class="header-btn" onclick="collapseAll()">Collapse All</button>
                <button class="header-btn" onclick="window.print()">Print</button>
            </div>
        </div>

        <div class="verdict-banner">
            <div class="verdict-icon icon-${verdictIcon}">$(switch ($verdictIcon) { "check" { "&#x2713;" } "warning" { "!" } "critical" { "&#x2715;" } })</div>
            <div class="verdict-label">${verdict}</div>
            <div class="verdict-message">${verdictMessage}</div>
        </div>

        <div class="score-section">
            <div class="score-ring-wrap">
                <div class="score-ring-container">
                    <svg class="score-ring" viewBox="0 0 120 120" width="110" height="110">
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
            $(if ($SuppressedCount -gt 0) { "<div class=`"stat-card stat-suppressed`"><div class=`"stat-value`">$SuppressedCount</div><div class=`"stat-label`">Suppressed</div></div>" })
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
            <button class="filter-btn active" onclick="filterFindings(this, 'all')">All ($totalCount)</button>
            <button class="filter-btn" onclick="filterFindings(this, 'critical')">Critical ($critCount)</button>
            <button class="filter-btn" onclick="filterFindings(this, 'warning')">Warning ($warnCount)</button>
            <button class="filter-btn" onclick="filterFindings(this, 'info')">Info ($infoCount)</button>
        </div>

        ${findingsHtml}

        <div class="report-footer">
            <p><strong>Am I Hacked?</strong> v${Version} &mdash; $($SystemInfo.ScanTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
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

        function filterFindings(btn, level) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.finding').forEach(f => {
                f.style.display = (level === 'all' || f.dataset.severity === level) ? 'block' : 'none';
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

        function collapseAll() {
            document.querySelectorAll('.category-header').forEach(h => {
                h.classList.add('collapsed');
                const body = h.nextElementSibling;
                if (body) body.style.display = 'none';
            });
        }

        function copyCmd(el) {
            const text = el.textContent.replace(/ [\^]$/, '').replace(/ ok$/, '');
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
