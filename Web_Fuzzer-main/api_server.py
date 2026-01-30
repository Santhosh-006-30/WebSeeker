"""
Web Fuzzer API Server for n8n Integration
Run this server and use n8n to trigger vulnerability scans
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import uuid
import time
import requests
import urllib3
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)  # Enable CORS for n8n

# Store scan results
scan_results = {}
scan_status = {}

# Import scanners
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.api_discovery import APIDiscovery
from scanners import sql_injection, xss, injection, file_attacks, misconfig, ssrf, auth, sensitive_data, csrf, integrity
from analysis.risk import RiskAnalyzer


def run_scan(scan_id, target_url):
    """Run the vulnerability scan in background"""
    try:
        scan_status[scan_id] = {
            "status": "running",
            "progress": 0,
            "message": "Initializing scan..."
        }
        
        results = {
            "scan_id": scan_id,
            "target_url": target_url,
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "endpoints_discovered": [],
            "vulnerabilities": [],
            "summary": {},
            "risk_score": 0,
            "grade": "A"
        }
        
        # Headers for requests
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/html, */*',
        }
        
        # Step 1: Validate target
        scan_status[scan_id]["message"] = "Validating target..."
        scan_status[scan_id]["progress"] = 5
        
        try:
            response = requests.get(target_url, timeout=30, verify=False, headers=headers)
            results["target_status"] = response.status_code
            results["target_reachable"] = True
        except Exception as e:
            results["target_reachable"] = False
            results["error"] = f"Could not reach target: {str(e)}"
            scan_status[scan_id] = {"status": "failed", "progress": 100, "message": str(e)}
            scan_results[scan_id] = results
            return
        
        # Step 2: Discover API endpoints
        scan_status[scan_id]["message"] = "Discovering API endpoints..."
        scan_status[scan_id]["progress"] = 15
        
        try:
            api_discovery = APIDiscovery(target_url, timeout=15)
            discovered_urls = api_discovery.discover()
            results["endpoints_discovered"] = list(discovered_urls)
        except Exception as e:
            discovered_urls = [target_url]
            results["endpoints_discovered"] = [target_url]
        
        if not discovered_urls:
            discovered_urls = [target_url]
            results["endpoints_discovered"] = [target_url]
        
        # Step 3: Run vulnerability scans
        scan_status[scan_id]["message"] = f"Scanning {len(discovered_urls)} endpoints..."
        scan_status[scan_id]["progress"] = 30
        
        all_vulnerabilities = []
        vuln_summary = {
            "SQL Injection": [],
            "Cross-Site Scripting (XSS)": [],
            "Command Injection": [],
            "Directory Traversal": [],
            "IDOR": [],
            "SSRF": [],
            "Sensitive Data Exposure": [],
            "Broken Authentication": [],
            "Security Misconfiguration": [],
            "CSRF": []
        }
        
        # Limit endpoints to scan
        endpoints_to_scan = discovered_urls[:20]  # Max 20 endpoints for speed
        total = len(endpoints_to_scan)
        
        for idx, endpoint in enumerate(endpoints_to_scan):
            progress = 30 + int((idx / total) * 50)
            scan_status[scan_id]["progress"] = progress
            scan_status[scan_id]["message"] = f"Scanning endpoint {idx+1}/{total}..."
            
            try:
                # Run quick scans
                cmd_results = injection.scan_command_injection(endpoint)
                if cmd_results:
                    vuln_summary["Command Injection"].extend(cmd_results)
                    all_vulnerabilities.extend(cmd_results)
                
                dir_results = file_attacks.scan_directory_traversal(endpoint)
                if dir_results:
                    vuln_summary["Directory Traversal"].extend(dir_results)
                    all_vulnerabilities.extend(dir_results)
                
                idor_results = misconfig.scan_idor(endpoint)
                if idor_results:
                    vuln_summary["IDOR"].extend(idor_results)
                    all_vulnerabilities.extend(idor_results)
                
                # SQL Injection (limited payloads for speed)
                sql_results = sql_injection.scan(endpoint)
                if sql_results:
                    vuln_summary["SQL Injection"].extend(sql_results)
                    all_vulnerabilities.extend(sql_results)
                
                # XSS
                xss_results = xss.scan(endpoint)
                if xss_results:
                    vuln_summary["Cross-Site Scripting (XSS)"].extend(xss_results)
                    all_vulnerabilities.extend(xss_results)
                
            except Exception as e:
                pass
        
        # Step 4: Global scans
        scan_status[scan_id]["message"] = "Running global security checks..."
        scan_status[scan_id]["progress"] = 85
        
        try:
            base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
            
            sensitive_results = sensitive_data.scan(base_url)
            if sensitive_results:
                vuln_summary["Sensitive Data Exposure"].extend(sensitive_results)
                all_vulnerabilities.extend(sensitive_results)
            
            auth_results = auth.scan(base_url)
            if auth_results:
                vuln_summary["Broken Authentication"].extend(auth_results)
                all_vulnerabilities.extend(auth_results)
            
            misconfig_results = misconfig.scan_security_misconfiguration(base_url)
            if misconfig_results:
                vuln_summary["Security Misconfiguration"].extend(misconfig_results)
                all_vulnerabilities.extend(misconfig_results)
                
        except Exception as e:
            pass
        
        # Step 5: Analyze and calculate risk
        scan_status[scan_id]["message"] = "Analyzing results..."
        scan_status[scan_id]["progress"] = 95
        
        # Calculate risk score
        severity_weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
        total_score = 0
        
        for vuln in all_vulnerabilities:
            severity = vuln.get("severity", "Low")
            total_score += severity_weights.get(severity, 1)
        
        # Normalize score (0-100)
        risk_score = min(100, total_score)
        
        # Calculate grade
        if risk_score == 0:
            grade = "A+"
        elif risk_score <= 10:
            grade = "A"
        elif risk_score <= 25:
            grade = "B"
        elif risk_score <= 50:
            grade = "C"
        elif risk_score <= 75:
            grade = "D"
        else:
            grade = "F"
        
        # Prepare vulnerability summary for n8n
        vuln_count = {k: len(v) for k, v in vuln_summary.items()}
        
        results["vulnerabilities"] = all_vulnerabilities
        results["summary"] = vuln_count
        results["total_vulnerabilities"] = len(all_vulnerabilities)
        results["risk_score"] = risk_score
        results["grade"] = grade
        results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Prepare formatted output for n8n
        results["formatted_report"] = format_report_for_n8n(results)
        
        scan_status[scan_id] = {"status": "completed", "progress": 100, "message": "Scan completed!"}
        scan_results[scan_id] = results
        
    except Exception as e:
        scan_status[scan_id] = {"status": "failed", "progress": 100, "message": str(e)}
        scan_results[scan_id] = {"error": str(e), "scan_id": scan_id}


def format_report_for_n8n(results):
    """Format the report in a readable format for n8n output"""
    report = []
    report.append("=" * 60)
    report.append("[SECURITY] WEB FUZZER SECURITY SCAN REPORT")
    report.append("=" * 60)
    report.append(f"")
    report.append(f"[TARGET] {results.get('target_url', 'N/A')}")
    report.append(f"[TIME] {results.get('start_time', 'N/A')} - {results.get('end_time', 'N/A')}")
    report.append(f"")
    report.append("-" * 60)
    report.append(f"[GRADE] OVERALL SECURITY GRADE: {results.get('grade', 'N/A')}")
    report.append(f"[SCORE] Risk Score: {results.get('risk_score', 0)}/100")
    report.append(f"[SCAN] Endpoints Scanned: {len(results.get('endpoints_discovered', []))}")
    report.append(f"[ALERT] Total Vulnerabilities: {results.get('total_vulnerabilities', 0)}")
    report.append("-" * 60)
    report.append("")
    report.append("[BREAKDOWN] VULNERABILITY BREAKDOWN:")
    report.append("")
    
    for vuln_type, count in results.get("summary", {}).items():
        if count > 0:
            report.append(f"  [X] {vuln_type}: {count} found")
        else:
            report.append(f"  [OK] {vuln_type}: None found")
    
    report.append("")
    report.append("-" * 60)
    
    # Top vulnerabilities details
    if results.get("vulnerabilities"):
        report.append("[CRITICAL] TOP VULNERABILITIES FOUND:")
        report.append("")
        for idx, vuln in enumerate(results["vulnerabilities"][:10], 1):
            report.append(f"  {idx}. [{vuln.get('severity', 'N/A')}] {vuln.get('type', 'N/A')}")
            report.append(f"     URL: {vuln.get('url', 'N/A')}")
            if vuln.get('parameter'):
                report.append(f"     Parameter: {vuln.get('parameter')}")
            if vuln.get('payload'):
                report.append(f"     Payload: {vuln.get('payload', '')[:100]}...")
            report.append("")
    else:
        report.append("[OK] No vulnerabilities found! Your application appears secure.")
    
    report.append("=" * 60)
    report.append("Report generated by Web Fuzzer")
    report.append("=" * 60)
    
    return "\n".join(report)


# ============ API ENDPOINTS ============

@app.route('/', methods=['GET'])
def home():
    """API Home - Health check"""
    return jsonify({
        "status": "online",
        "service": "Web Fuzzer API",
        "version": "1.0.0",
        "endpoints": {
            "POST /scan": "Start a new vulnerability scan",
            "GET /scan/<scan_id>": "Get scan results",
            "GET /scan/<scan_id>/status": "Get scan status"
        }
    })


@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    data = request.get_json() or {}
    target_url = data.get('url') or request.args.get('url')
    
    if not target_url:
        return jsonify({"error": "URL is required. Send {'url': 'https://example.com'}"}), 400
    
    # Ensure URL has protocol
    if not target_url.startswith('http'):
        target_url = 'https://' + target_url
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())[:8]
    
    # Initialize status
    scan_status[scan_id] = {"status": "queued", "progress": 0, "message": "Scan queued..."}
    
    # Start scan in background
    thread = threading.Thread(target=run_scan, args=(scan_id, target_url))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "message": "Scan started",
        "status_url": f"/scan/{scan_id}/status",
        "results_url": f"/scan/{scan_id}"
    })


@app.route('/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of a scan"""
    if scan_id not in scan_status:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify({
        "scan_id": scan_id,
        **scan_status[scan_id]
    })


@app.route('/scan/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    """Get the results of a completed scan"""
    if scan_id not in scan_status:
        return jsonify({"error": "Scan not found"}), 404
    
    status = scan_status[scan_id]
    
    if status["status"] == "running":
        return jsonify({
            "scan_id": scan_id,
            "status": "running",
            "progress": status["progress"],
            "message": status["message"]
        })
    
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    
    return jsonify({"error": "Results not available"}), 404


@app.route('/quick-scan', methods=['POST', 'GET'])
def quick_scan():
    """
    Synchronous quick scan - waits for results
    Better for n8n HTTP Request node
    """
    if request.method == 'GET':
        target_url = request.args.get('url')
    else:
        data = request.get_json() or {}
        target_url = data.get('url') or request.args.get('url')
    
    if not target_url:
        return jsonify({"error": "URL is required"}), 400
    
    if not target_url.startswith('http'):
        target_url = 'https://' + target_url
    
    scan_id = str(uuid.uuid4())[:8]
    
    # Run scan synchronously
    run_scan(scan_id, target_url)
    
    # Return results
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    
    return jsonify({"error": "Scan failed"}), 500


if __name__ == '__main__':
    print("=" * 60)
    print("       WEB FUZZER API SERVER FOR n8n")
    print("=" * 60)
    print("  Server running at: http://localhost:5000")
    print("")
    print("  API Endpoints:")
    print("  - POST /scan         : Start async scan")
    print("  - GET  /scan/<id>    : Get scan results")
    print("  - POST /quick-scan   : Synchronous scan (for n8n)")
    print("")
    print("  Use /quick-scan in n8n HTTP Request node")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)

