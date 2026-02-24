
from datetime import datetime
import json
import html

def generate_report(user, url, vulnerabilities, scan_summary=None):
    # --- Data Processing & Logic ---
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file = "report.html"

    # Statistics
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    type_counts = {}
    
    for v in vulnerabilities:
        sev = v.get("severity", "Low")
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        typ = v.get("type", "Other")
        type_counts[typ] = type_counts.get(typ, 0) + 1

    # Security Score Calculation
    base_score = 100
    deductions = (severity_counts["Critical"] * 25) + (severity_counts["High"] * 10) + (severity_counts["Medium"] * 5) + (severity_counts["Low"] * 1)
    security_score = max(0, base_score - deductions)
    
    grade = "F"
    grade_color = "text-red-500"
    if security_score >= 90: grade, grade_color = "A", "text-emerald-500"
    elif security_score >= 80: grade, grade_color = "B", "text-blue-500"
    elif security_score >= 70: grade, grade_color = "C", "text-yellow-500"
    elif security_score >= 60: grade, grade_color = "D", "text-orange-500"

    # Executive Summary Text
    primary_threats = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    threat_text = ", ".join([t[0] for t in primary_threats]) if primary_threats else "None"
    
    analysis_text = f"Assessment of <strong>{html.escape(url)}</strong> resulted in a Security Score of <strong class='{grade_color}'>{security_score}/100 ({grade})</strong>. "
    
    if grade in ['A', 'B']:
        analysis_text += "The target demonstrates a <strong>strong security posture</strong>. "
    elif grade == 'C':
        analysis_text += "The target exhibits a <strong>moderate risk profile</strong> with actionable gaps. "
    else:
        analysis_text += "The target is in a <strong>CRITICAL RISK STATE</strong>. Immediate remediation is required. "

    if severity_counts['Critical'] > 0:
        analysis_text += f"CRITICAL Findings Detected: <strong>{severity_counts['Critical']}</strong>. "

    # Remediation Library
    try:
        from core.remediation import RemediationLibrary
        remedy_lib = RemediationLibrary()
        fixes_data = remedy_lib.fixes
    except ImportError:
        fixes_data = {}

    # --- HTML Generation ---
    stats = {
        "total": len(vulnerabilities),
        "critical": severity_counts.get("Critical", 0),
        "high": severity_counts.get("High", 0),
        "medium": severity_counts.get("Medium", 0),
        "low": severity_counts.get("Low", 0), 
        "by_type": type_counts,
        "security_score": security_score,
        "grade": grade,
        "grade_color": grade_color,
        "analysis": analysis_text
    }

    # Prepare JSON Payloads
    findings_json = json.dumps(vulnerabilities).replace("</script>", "<\\/script>")
    stats_json = json.dumps(stats).replace("</script>", "<\\/script>")
    meta_json = json.dumps({"url": url, "user": user, "date": now}).replace("</script>", "<\\/script>")
    fixes_json = json.dumps(fixes_data).replace("</script>", "<\\/script>")

    # Use Raw String Layout
    html_template = r"""
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSeeker Threat Report - __URL_PLACEHOLDER__</title>
    
    <!-- Fonts: Inter + JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    
    <!-- Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                    colors: {
                        bg: '#0b1121', // Deep Navy/Black
                        surface: '#151e32', // Lighter Navy
                        accent: '#3b82f6', // Corporate Blue
                        cyber: '#0ea5e9', // Cyber Cyan
                        danger: '#ef4444',
                        warning: '#f59e0b',
                        success: '#10b981',
                        border: '#1e293b'
                    }
                }
            }
        }
    </script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        body { background-color: #0b1121; color: #e2e8f0; }
        
        /* Cyber-Corp Aesthetics */
        .glass-panel {
            background: rgba(21, 30, 50, 0.7);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(59, 130, 246, 0.1);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        .neon-border-b { border-bottom: 1px solid rgba(14, 165, 233, 0.3); }
        .neon-text { text-shadow: 0 0 10px rgba(59, 130, 246, 0.5); }
        
        .vuln-row:hover { background-color: rgba(30, 41, 59, 0.5); }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #0b1121; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
    </style>
</head>
<body class="antialiased min-h-screen flex flex-col">

    <!-- Navbar -->
    <nav class="fixed top-0 w-full z-50 glass-panel border-b border-white/5 h-16 flex items-center justify-between px-6">
        <div class="flex items-center gap-3">
            <div class="h-8 w-8 rounded bg-gradient-to-br from-blue-600 to-cyan-500 flex items-center justify-center text-white font-bold shadow-[0_0_15px_rgba(59,130,246,0.5)]">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div>
                <h1 class="font-bold text-lg tracking-tight text-white">WebSeeker <span class="text-cyber font-mono text-xs">PRO</span></h1>
            </div>
        </div>
        
        <div class="flex items-center gap-4">
             <div class="hidden md:flex flex-col items-end mr-4">
                <span class="text-xs text-slate-400 uppercase tracking-wider">Target</span>
                <span class="font-mono text-sm text-cyan-400">__URL_PLACEHOLDER__</span>
            </div>
            <button onclick="window.print()" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm font-medium transition-colors shadow-lg shadow-blue-900/50 flex items-center gap-2">
                <i class="fa-solid fa-file-export"></i> Export Report
            </button>
        </div>
    </nav>
    
    <div class="h-16"></div> <!-- Spacer -->

    <main class="container mx-auto p-6 space-y-6">
    
        <!-- EXECUTIVE DASHBOARD ROW -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            <!-- Security Score Card -->
            <div class="lg:col-span-4 glass-panel rounded-xl p-6 relative overflow-hidden group">
                <div class="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition"><i class="fa-solid fa-crosshairs text-9xl"></i></div>
                <h2 class="text-slate-400 text-xs font-bold uppercase tracking-widest mb-4">Security Score</h2>
                <div class="flex items-end gap-2">
                    <span class="text-7xl font-black text-white" id="score-val">0</span>
                    <span class="text-xl font-bold text-slate-500 mb-2">/100</span>
                </div>
                <!-- Grade Badge -->
                <div id="grade-badge" class="mt-4 inline-flex items-center px-3 py-1 rounded border bg-opacity-20 text-sm font-bold">
                    GRADE -
                </div>
                <p class="mt-4 text-sm text-slate-400 leading-relaxed" id="exec-summary">Initializing analysis...</p>
            </div>

            <!-- Stats Grid -->
            <div class="lg:col-span-8 grid grid-cols-2 md:grid-cols-4 gap-4">
                <!-- Critical -->
                <div class="glass-panel rounded-xl p-5 border-l-4 border-l-red-500 hover:bg-red-500/5 transition cursor-pointer" onclick="filter('Critical')">
                    <div class="flex justify-between items-start">
                        <div>
                            <div class="text-slate-400 text-[10px] font-bold uppercase tracking-widest">CRITICAL</div>
                            <div class="text-3xl font-bold text-white mt-1" id="stat-critical">0</div>
                        </div>
                        <i class="fa-solid fa-skull-crossbones text-red-500/50"></i>
                    </div>
                </div>
                <!-- High -->
                <div class="glass-panel rounded-xl p-5 border-l-4 border-l-orange-500 hover:bg-orange-500/5 transition cursor-pointer" onclick="filter('High')">
                    <div class="flex justify-between items-start">
                        <div>
                            <div class="text-slate-400 text-[10px] font-bold uppercase tracking-widest">HIGH</div>
                            <div class="text-3xl font-bold text-white mt-1" id="stat-high">0</div>
                        </div>
                        <i class="fa-solid fa-fire text-orange-500/50"></i>
                    </div>
                </div>
                <!-- Medium -->
                <div class="glass-panel rounded-xl p-5 border-l-4 border-l-yellow-500 hover:bg-yellow-500/5 transition cursor-pointer" onclick="filter('Medium')">
                    <div class="flex justify-between items-start">
                        <div>
                            <div class="text-slate-400 text-[10px] font-bold uppercase tracking-widest">MEDIUM</div>
                            <div class="text-3xl font-bold text-white mt-1" id="stat-medium">0</div>
                        </div>
                        <i class="fa-solid fa-triangle-exclamation text-yellow-500/50"></i>
                    </div>
                </div>
                <!-- Total -->
                <div class="glass-panel rounded-xl p-5 border-l-4 border-l-blue-500 hover:bg-blue-500/5 transition cursor-pointer" onclick="filter('all')">
                    <div class="flex justify-between items-start">
                        <div>
                            <div class="text-slate-400 text-[10px] font-bold uppercase tracking-widest">TOTAL ISSUES</div>
                            <div class="text-3xl font-bold text-white mt-1" id="stat-total">0</div>
                        </div>
                        <i class="fa-solid fa-bug text-blue-500/50"></i>
                    </div>
                </div>

                <!-- Chart -->
                <div class="col-span-2 md:col-span-4 glass-panel rounded-xl p-4 h-40 flex items-center justify-center relative">
                    <canvas id="vulnChart" style="max-height: 100%; width: 100%;"></canvas>
                </div>
            </div>
        </div>

        <!-- FINDINGS DASHBOARD -->
        <div class="glass-panel rounded-xl overflow-hidden min-h-[600px] flex flex-col">
            <!-- Toolbar -->
            <div class="p-4 border-b border-slate-700/50 flex flex-col md:flex-row gap-4 justify-between items-center bg-slate-900/50">
                <div class="flex items-center gap-2">
                    <h3 class="font-bold text-white"><i class="fa-solid fa-list-ul mr-2 text-cyber"></i> Detailed Findings</h3>
                    <span class="px-2 py-0.5 bg-slate-800 rounded text-xs text-slate-400" id="finding-count-badge">0</span>
                </div>
                
                <div class="relative w-full md:w-96">
                    <i class="fa-solid fa-search absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"></i>
                    <input type="text" id="search-input" placeholder="Search vulnerabilities, payloads, URLs..." 
                           class="w-full bg-slate-950 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-200 focus:border-cyber focus:outline-none transition-colors">
                </div>
            </div>

            <!-- Table Header -->
            <div class="grid grid-cols-12 bg-slate-900/80 px-4 py-3 text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <div class="col-span-2">Severity</div>
                <div class="col-span-3">Vulnerability Type</div>
                <div class="col-span-6">Location / Endpoint</div>
                <div class="col-span-1 text-right">Action</div>
            </div>

            <!-- List Container -->
            <div id="findings-list" class="divide-y divide-slate-800/50 overflow-y-auto flex-1">
                <!-- Injected via JS -->
            </div>
        </div>

    </main>

    <!-- JS Logic -->
    <script>
        const DATA = {
            stats: __STATS_JSON__,
            findings: __FINDINGS_JSON__,
            fixes: __FIXES_JSON__,
            meta: __META_JSON__
        };

        // --- Render Logic ---
        document.addEventListener('DOMContentLoaded', () => {
            initDashboard();
            renderFindings(DATA.findings);
            initChart();
        });

        function initDashboard() {
            // Stats
            document.getElementById('score-val').textContent = DATA.stats.security_score;
            document.getElementById('exec-summary').innerHTML = DATA.stats.analysis;
            
            // Badge Color
            const gradeColors = {'A': 'bg-emerald-500', 'B': 'bg-blue-500', 'C': 'bg-yellow-500', 'D': 'bg-orange-500', 'F': 'bg-red-500'};
            const gBadge = document.getElementById('grade-badge');
            gBadge.textContent = 'GRADE ' + (DATA.stats.grade || 'F');
            gBadge.classList.add(gradeColors[DATA.stats.grade] || 'bg-slate-500', 'text-white', 'border-transparent');

            // Counts
            document.getElementById('stat-critical').textContent = DATA.stats.critical;
            document.getElementById('stat-high').textContent = DATA.stats.high;
            document.getElementById('stat-medium').textContent = DATA.stats.medium;
            document.getElementById('stat-total').textContent = DATA.stats.total;

            // Search
            document.getElementById('search-input').addEventListener('input', (e) => {
                const q = e.target.value.toLowerCase();
                const filtered = DATA.findings.filter(f => 
                    f.type.toLowerCase().includes(q) || 
                    f.location.toLowerCase().includes(q) || 
                    (f.payload && f.payload.toLowerCase().includes(q))
                );
                renderFindings(filtered);
            });
        }

        function filter(sev) {
            if (sev === 'all') {
                renderFindings(DATA.findings);
            } else {
                renderFindings(DATA.findings.filter(f => f.severity === sev));
            }
        }

        function renderFindings(list) {
            const container = document.getElementById('findings-list');
            document.getElementById('finding-count-badge').textContent = list.length;
            
            if (list.length === 0) {
                container.innerHTML = '<div class="p-8 text-center text-slate-500 italic">No findings match your criteria.</div>';
                return;
            }

            container.innerHTML = list.map((f, i) => {
                const config = getSevConfig(f.severity);
                // Unique ID for expansion
                const id = 'vuln-' + Math.random().toString(36).substr(2, 9);
                
                return `
                <div class="vuln-row transition-colors group">
                    <div class="grid grid-cols-12 px-4 py-4 items-center cursor-pointer" onclick="toggle('${id}')">
                        <div class="col-span-2">
                            <span class="inline-flex items-center gap-2 px-2.5 py-1 rounded-md border ${config.bg} ${config.border} ${config.text} text-xs font-bold uppercase shadow-sm">
                                <i class="fa-solid ${config.icon}"></i> ${f.severity}
                            </span>
                        </div>
                        <div class="col-span-3 text-sm font-semibold text-white group-hover:text-cyber transition-colors">
                            ${escapeHtml(f.type)}
                        </div>
                        <div class="col-span-6 text-xs font-mono text-slate-400 truncate pr-4">
                            ${escapeHtml(f.location)}
                        </div>
                        <div class="col-span-1 text-right">
                            <i class="fa-solid fa-chevron-down text-slate-600 transition-transform duration-300" id="icon-${id}"></i>
                        </div>
                    </div>
                    
                    <!-- Expanded Details -->
                    <div id="${id}" class="hidden bg-slate-950/50 border-y border-slate-800/50 px-4 py-6">
                        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 pl-2 border-l-2 border-slate-700 ml-2">
                            <div class="space-y-4">
                                <div>
                                    <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest mb-1">Impact Analysis</h4>
                                    <p class="text-sm text-slate-300 leading-relaxed">${escapeHtml(f.impact || 'Unknown impact.')}</p>
                                </div>
                                <div class="bg-black/40 rounded border border-slate-800 p-3">
                                    <h4 class="text-[10px] font-bold text-red-400 uppercase mb-2"><i class="fa-solid fa-bug mr-1"></i> Payload Evidence</h4>
                                    <code class="text-xs font-mono text-red-200 break-all block">${escapeHtml(f.payload || 'N/A')}</code>
                                </div>
                            </div>
                            
                            <div class="space-y-4">
                                <div>
                                    <h4 class="text-xs font-bold text-emerald-500 uppercase tracking-widest mb-1">Remediation Strategy</h4>
                                    <p class="text-sm text-slate-300">${escapeHtml(f.recommendation || DATA.fixes[f.type]?.recommendation || 'Review code manually.')}</p>
                                </div>
                                <div class="p-3 rounded bg-blue-900/10 border border-blue-500/20">
                                    <h4 class="text-[10px] font-bold text-blue-400 uppercase mb-2">Technical Guidance</h4>
                                    <pre class="text-[10px] font-mono text-blue-200 overflow-x-auto"><code>${escapeHtml(DATA.fixes[f.type]?.secure_code || '# Secure coding pattern not available')}</code></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                `;
            }).join('');
        }

        function toggle(id) {
            const el = document.getElementById(id);
            const icon = document.getElementById('icon-' + id);
            
            if (el.classList.contains('hidden')) {
                el.classList.remove('hidden');
                icon.classList.add('rotate-180');
            } else {
                el.classList.add('hidden');
                icon.classList.remove('rotate-180');
            }
        }

        function initChart() {
            const ctx = document.getElementById('vulnChart').getContext('2d');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        label: 'Count',
                        data: [DATA.stats.critical, DATA.stats.high, DATA.stats.medium, DATA.stats.low],
                        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
                        borderRadius: 4,
                        maxBarThickness: 40
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { display: false },
                        x: { 
                            grid: { display: false },
                            ticks: { color: '#64748b', font: { size: 10, weight: 'bold' } }
                        }
                    }
                }
            });
        }

        function getSevConfig(sev) {
            switch(sev) {
                case 'Critical': return { bg: 'bg-red-500/10', border: 'border-red-500/20', text: 'text-red-500', icon: 'fa-skull' };
                case 'High': return { bg: 'bg-orange-500/10', border: 'border-orange-500/20', text: 'text-orange-500', icon: 'fa-fire' };
                case 'Medium': return { bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', text: 'text-yellow-500', icon: 'fa-triangle-exclamation' };
                case 'Low': return { bg: 'bg-blue-500/10', border: 'border-blue-500/20', text: 'text-blue-500', icon: 'fa-info' };
                default: return { bg: 'bg-slate-500/10', border: 'border-slate-500/20', text: 'text-slate-500', icon: 'fa-question' };
            }
        }

        function escapeHtml(unsafe) {
            if (!unsafe) return '';
            return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }
    </script>
</body>
</html>
"""

    # Inject Data
    html_content = html_template.replace("__STATS_JSON__", stats_json) \
                                .replace("__FINDINGS_JSON__", findings_json) \
                                .replace("__FIXES_JSON__", fixes_json) \
                                .replace("__META_JSON__", meta_json) \
                                .replace("__URL_PLACEHOLDER__", html.escape(url)) \
                                .replace("__USER_NAME__", html.escape(user)) \
                                .replace("__SCAN_DATE__", now)

    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    return report_file
