
import os
import utils
import time
from core.network import requester
from config import Colors

def scan_directory_traversal(url):
    Colors.info("Testing for Directory Traversal...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    payload_dir = os.path.join(base_dir, "Payloads", "Directory_Traversal")
    
    dir_payloads = []
    if os.path.exists(payload_dir):
        dir_payloads = utils.load_payloads_from_dir(payload_dir)
        
    if not dir_payloads:
        dir_payloads = [
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "../etc/shadow", "../../etc/shadow",
            "../windows/system32/cmd.exe", "../../windows/system32/cmd.exe"
        ]

    vulnerabilities = []

    from concurrent.futures import ThreadPoolExecutor, as_completed
    from config import PAYLOAD_THREADS

    vulnerabilities = []
    
    # Generate tasks
    scan_tasks = []
    for payload in dir_payloads:
        fuzzed_targets = utils.generate_fuzzed_urls(url, payload)
        for target in fuzzed_targets:
            target['payload'] = payload
            scan_tasks.append(target)
            
    def test_target(target_data):
        test_url = target_data['url']
        payload = target_data['payload']
        param = target_data['param']
        
        try:
            response = requester.get(test_url)
            if response and ("root:" in response.text or "NT AUTHORITY" in response.text):
                Colors.vuln("Directory Traversal Vulnerability Found!")
                return {
                    "type": "Directory Traversal",
                    "payload": payload,
                    "location": f"Parameter: {param} (in URL: {test_url})",
                    "impact": "Attacker can read arbitrary sensitive files from the server.",
                    "severity": "High",
                    "recommendation": "Restrict file access and validate user input."
                }
        except:
            pass
        return None

    # Threaded Scan
    Colors.info(f"Scanning with {PAYLOAD_THREADS} threads...")
    with ThreadPoolExecutor(max_workers=PAYLOAD_THREADS) as executor:
        futures = {executor.submit(test_target, t): t for t in scan_tasks}
        for future in as_completed(futures):
            res = future.result()
            if res:
                vulnerabilities.append(res)
                # Exhaustive: continue

    return vulnerabilities

def scan_insecure_file_upload(upload_url, check_url):
    vulnerabilities = []
    # Simplified for new core - manual header handling needed if we use requester wrapper tailored for GET/POST
    # We used direct requests with verify=False before. Requester handles basics.
    
    dangerous_files = {
        "PHP Shell": ("shell.php", "<?php echo 'Hacked'; ?>"),
        "JSP Shell": ("shell.jsp", "<% out.println('Hacked'); %>"),
        "HTAccess File": (".htaccess", "RewriteEngine On"),
        "Double Extension": ("shell.php.png", "<?php echo 'Hacked'; ?>")
    }
    
    Colors.info("Testing for Insecure File Upload...")

    for file_type, (filename, content) in dangerous_files.items():
        files = {"file": (filename, content)} # Requester wrapper needs to support files? Or we bypass it for this specific test
        
        # Using pure requests here if wrapper is simple
        try:
            import requests
            time.sleep(2)
            # Todo: update requester to support files upload
            response = requests.post(upload_url, files=files, timeout=10) # ignoring requester for multipart

            if response.status_code == 200:
                Colors.vuln(f"{file_type} uploaded successfully! Checking execution...")
                time.sleep(1)
                
                execution_check = requests.get(f"{check_url}/{filename}", timeout=10)
                if "Hacked" in execution_check.text:
                    vulnerabilities.append({
                        "type": "Insecure File Upload",
                        "payload": filename,
                        "location": f"Upload Endpoint: {upload_url}",
                        "impact": "Attacker can upload and execute malicious scripts (RCE).",
                        "severity": "Critical",
                        "recommendation": "Restrict file types, validate uploads, and store files outside the web root."
                    })
        except Exception as e:
            pass # Colors.warning(f"Error testing {file_type}: {e}")

    return vulnerabilities
