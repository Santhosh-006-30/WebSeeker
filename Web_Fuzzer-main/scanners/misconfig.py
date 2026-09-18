
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.network import requester
from config import Colors

# ── Sensitive file list (expanded) ───────────────────────────────────────────
SENSITIVE_FILES = [
    "/robots.txt", "/.git/", "/.git/config", "/.htaccess", "/.env",
    "/.DS_Store", "/config.php", "/config.json", "/web.config",
    "/backup.zip", "/backup.sql", "/database.sql", "/dump.sql",
    "/admin/", "/dashboard/", "/phpinfo.php", "/info.php",
    "/aws.yml", "/docker-compose.yml", "/Dockerfile",
    "/id_rsa", "/id_rsa.pub", "/known_hosts",
    "/sitemap.xml", "/trace.axd", "/server-status",
    "/.svn/entries", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/server-info", "/elmah.axd", "/api/swagger.json",
    "/swagger/index.html", "/api-docs", "/openapi.json",
]


def scan_idor(url):
    """IDOR check — parallel ID probing."""
    vulnerabilities = []
    test_ids = [1, 2, 999, 1000]

    def probe(tid):
        test_url = url.replace("{id}", str(tid))
        response = requester.get(test_url, allow_redirects=False)
        if response and response.status_code not in (403, 401, 404):
            return {
                "type": "Insecure Direct Object Reference (IDOR)",
                "payload": test_url,
                "location": "URL Path (ID Parameter)",
                "impact": "Attacker can access unauthorized data by modifying ID parameters.",
                "severity": "High",
                "recommendation": "Implement proper authorization checks before granting access to resources."
            }
        return None

    with ThreadPoolExecutor(max_workers=len(test_ids)) as ex:
        for r in as_completed([ex.submit(probe, i) for i in test_ids]):
            v = r.result()
            if v:
                vulnerabilities.append(v)

    return vulnerabilities


def scan_security_misconfiguration(url):
    """Parallel sensitive-file probing + header analysis."""
    vulnerabilities = []

    def probe_file(file):
        test_url = url.rstrip('/') + file
        try:
            response = requester.get(test_url)
            if response and response.status_code == 200 and len(response.content) > 0:
                return {
                    "type": "Security Misconfiguration",
                    "payload": file,
                    "location": f"URL Path: {test_url}",
                    "impact": "Exposure of sensitive configuration files.",
                    "severity": "Medium",
                    "recommendation": "Restrict public access to sensitive files and configure proper access control."
                }
        except Exception:
            pass
        return None

    # Probe all files in parallel
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = [ex.submit(probe_file, f) for f in SENSITIVE_FILES]
        for future in as_completed(futures):
            v = future.result()
            if v:
                vulnerabilities.append(v)

    # Header checks (single request)
    response = requester.get(url)
    if response:
        server_info = response.headers.get("server", "")
        if server_info and any(c.isdigit() for c in server_info):
            vulnerabilities.append({
                "type": "Vulnerable and Outdated Components",
                "payload": f"Server Header: {server_info}",
                "evidence": f"Header Value: {server_info}",
                "location": "HTTP Response Header",
                "impact": "Disclosure of server version helps attackers exploit known vulnerabilities.",
                "severity": "Low",
                "recommendation": "Remove Server header banner or update to the latest secure version."
            })

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        if "x-request-id" not in headers_lower and "x-correlation-id" not in headers_lower:
            vulnerabilities.append({
                "type": "Logging Failure",
                "payload": "Missing X-Request-ID/X-Correlation-ID",
                "location": "HTTP Response Header",
                "impact": "Lack of request correlation identifiers makes incident response difficult (A09).",
                "severity": "Low",
                "recommendation": "Implement centralized logging with unique request identifiers for all transactions."
            })

    return vulnerabilities


def scan_multiple_login_attempts(url):
    """Rate-limiting check — parallel rapid login attempts."""
    vulnerabilities = []
    LOGIN_URL = url.rstrip('/') + "/login"
    LOGIN_PAYLOAD = {'username': 'admin', 'password': 'incorrect_test_pass'}

    def attempt(_):
        try:
            r = requests.post(LOGIN_URL, data=LOGIN_PAYLOAD, timeout=3, verify=False)
            return r.status_code
        except Exception:
            return None

    # Fire 10 rapid login attempts in parallel
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(attempt, i) for i in range(10)]
        statuses = [f.result() for f in as_completed(futures)]

    non_blocked = [s for s in statuses if s is not None and s != 429]
    if len(non_blocked) >= 8:
        vulnerabilities.append({
            "type": "Brute Force / Multiple Login Attempts",
            "payload": "High frequency login attempts (10 parallel)",
            "location": f"Login Endpoint: {LOGIN_URL}",
            "impact": "Attacker can guess passwords via brute force or credential stuffing.",
            "severity": "Medium",
            "recommendation": "Implement rate limiting and account lockout mechanisms for failed login attempts."
        })

    return vulnerabilities
