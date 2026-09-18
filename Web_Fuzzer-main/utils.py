import os
import threading
from config import TIMEOUT
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ── Payload Cache ─────────────────────────────────────────────────────────────
# Payloads are read from disk ONCE per process and cached — scanners previously
# re-read the same files on every endpoint call (100s of redundant disk reads).
_payload_cache = {}
_payload_cache_lock = threading.Lock()

def load_payloads_from_file(file_path):
    """Loads payloads from a single file, caching the result."""
    with _payload_cache_lock:
        if file_path in _payload_cache:
            return _payload_cache[file_path]

    payloads = []
    if not os.path.exists(file_path):
        return payloads
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [l.strip() for l in f if l.strip()]
    except Exception:
        pass

    with _payload_cache_lock:
        _payload_cache[file_path] = payloads
    return payloads


def load_payloads_from_dir(directory_path, extensions=None):
    """Loads payloads from all files in a directory (cached)."""
    cache_key = (directory_path, tuple(extensions or []))
    with _payload_cache_lock:
        if cache_key in _payload_cache:
            return list(_payload_cache[cache_key])

    all_payloads = []
    if not os.path.exists(directory_path):
        return all_payloads

    for root, _, files in os.walk(directory_path):
        for file in files:
            if extensions and not file.endswith(tuple(extensions)):
                continue
            all_payloads.extend(load_payloads_from_file(os.path.join(root, file)))

    with _payload_cache_lock:
        _payload_cache[cache_key] = all_payloads
    return list(all_payloads)


# ── Target Validation & Protocol Fallback ────────────────────────────────────
def validate_and_normalize_target(url, timeout=10, logger_func=None):
    """
    Validates and normalizes target URL with automatic HTTP/HTTPS fallback,
    redirect handling, and clear logging.
    Returns (final_url, response) on success, or (None, None) on failure.
    """
    url = url.strip()
    if not url:
        return None, None

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/html, */*',
    }

    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def log_warn(msg):
        if logger_func:
            logger_func("warning", msg)
        else:
            try:
                from config import Colors
                Colors.warning(msg)
            except Exception:
                print(f"[WARN] {msg}")

    def log_info(msg):
        if logger_func:
            logger_func("info", msg)
        else:
            try:
                from config import Colors
                Colors.info(msg)
            except Exception:
                print(f"[INFO] {msg}")

    # Build candidate URLs in preference order
    candidates = []
    if url.startswith("https://"):
        candidates.append(url)
        candidates.append("http://" + url[8:])
    elif url.startswith("http://"):
        candidates.append(url)
        candidates.append("https://" + url[7:])
    else:
        # No scheme specified — try HTTPS first then HTTP
        candidates.append("https://" + url)
        candidates.append("http://" + url)

    last_error = None
    for cand in candidates:
        try:
            log_info(f"Connecting to target: {cand}...")
            resp = requests.get(cand, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
            final_url = resp.url if resp.url else cand
            if cand != url and (url.startswith("http://") or url.startswith("https://")):
                log_warn(f"Initial scheme connection failed. Successfully fell back to: {final_url}")
            elif not url.startswith("http://") and not url.startswith("https://"):
                log_info(f"Resolved target URL to: {final_url}")
            return final_url, resp
        except requests.exceptions.RequestException as e:
            last_error = e
            if cand != candidates[-1]:
                log_warn(f"Could not connect to {cand} ({type(e).__name__}). Retrying with alternate protocol...")


    log_warn(f"All connection attempts to target '{url}' failed. Last error: {last_error}")
    return None, None


# ── Endpoint Liveness ─────────────────────────────────────────────────────────

# Use HEAD (no body download) first — falls back to GET only if HEAD fails.
# This can be 5-10x faster for large pages since we skip downloading HTML.
_alive_cache = {}
_alive_lock = threading.Lock()

def check_endpoint_alive(url):
    """Fast liveness check using HEAD request + result cache."""
    with _alive_lock:
        if url in _alive_cache:
            return _alive_cache[url]

    result = False
    try:
        import requests, urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # HEAD is much faster — no body transfer
        r = requests.head(url, timeout=3, verify=False, allow_redirects=True)
        result = r.status_code < 500
    except Exception:
        try:
            import requests
            r = requests.get(url, timeout=3, verify=False, stream=True)
            result = True
        except Exception:
            result = False

    with _alive_lock:
        _alive_cache[url] = result
    return result


def generate_fuzzed_urls(url, payload):
    """
    Generates a list of dicts with URLs where payload is injected into each query param.
    Returns: [{'url': '...', 'param': '...'}, ...]
    """
    fuzzed_entries = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    if query_params:
        for target_param in query_params:
            current_params_list = []
            for k, v_list in query_params.items():
                if k != target_param:
                    for v in v_list:
                        current_params_list.append((k, v))
            current_params_list.append((target_param, payload))
            new_query = urlencode(current_params_list)
            new_url = urlunparse(parsed._replace(query=new_query))
            fuzzed_entries.append({"url": new_url, "param": target_param})
    else:
        common_inputs = ['id', 'q', 'search', 'query', 'page', 'cmd', 'file']
        for param in common_inputs:
            new_query = urlencode({param: payload})
            new_url = urlunparse(parsed._replace(query=new_query))
            fuzzed_entries.append({"url": new_url, "param": param})

    return fuzzed_entries


def get_vuln_details(vuln_type, context=None):
    """Returns dynamic Impact and Remediation details based on vulnerability type."""
    details = {
        "impact": "Security impact varies based on specific exploitation.",
        "recommendation": "Investigate and apply security best practices."
    }

    if vuln_type == "SQL Injection":
        db_type = "Generic SQL"
        if context:
            ctx = context.lower()
            if "mysql" in ctx: db_type = "MySQL"
            elif "sqlserver" in ctx or "microsoft" in ctx: db_type = "Microsoft SQL Server"
            elif "postgresql" in ctx: db_type = "PostgreSQL"
            elif "ora-" in ctx or "oracle" in ctx: db_type = "Oracle"

        details["impact"] = (
            f"Likely {db_type} database vulnerability. An attacker could bypass authentication, "
            "access, modify, or delete data within the entire database structure, and potentially "
            "gain administrative rights over the database server."
        )
        details["recommendation"] = (
            f"Ensure all inputs interacting with the {db_type} database are sanitized. "
            "Use prepared statements (Parameterized Queries) heavily. "
            "Enforce Least Privilege principles on the database user account."
        )

    elif vuln_type == "Sensitive Data Exposure":
        if context:
            ctx = context.lower()
            if "api" in ctx or "key" in ctx:
                details["impact"] = "Leaked API keys can allow attackers to access third-party services, cloud resources, or internal APIs."
                details["recommendation"] = "Revoke the exposed key immediately. Rotate credentials and implement secret scanning in CI/CD. Use environment variables."
            elif "password" in ctx or "credential" in ctx:
                details["impact"] = "Exposed credentials allow direct unauthorized access to user accounts or administrative panels."
                details["recommendation"] = "Force password resets. Ensure passwords are hashed (Argon2/bcrypt) and never logged."
            elif ".env" in ctx or "config" in ctx:
                details["impact"] = "Configuration files often contain database strings, secret keys, and debug settings."
                details["recommendation"] = "Configure server to deny access to dotfiles. Move configs outside the web root."
            elif "backup" in ctx or ".sql" in ctx or ".bak" in ctx:
                details["impact"] = "Backup files can expose full database snapshots or source code."
                details["recommendation"] = "Delete old backup files from production. Store backups in secure, access-controlled offsite storage."
            elif "id_rsa" in ctx or "ssh" in ctx:
                details["impact"] = "Compromised SSH private keys grant immediate remote access to the server."
                details["recommendation"] = "Regenerate SSH keys immediately. Disable password authentication for SSH."

    elif vuln_type == "Cross-Site Scripting (XSS)":
        details["impact"] = (
            "Reflected XSS allows an attacker to inject malicious scripts into a victim's browser session. "
            "This leads to Session Hijacking, Phishing, or unauthorized actions on behalf of the user."
        )
        details["recommendation"] = (
            "Implement a strong Content Security Policy (CSP). "
            "Apply context-aware encoding to all user input before rendering in HTML/JS/CSS contexts. "
            "Use frameworks that auto-escape data (React, Vue, Angular)."
        )

    return details
