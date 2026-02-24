
import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import Colors, MAX_THREADS, ENDPOINT_THREADS
from scanners import sql_injection, xss, auth, sensitive_data, injection, file_attacks, misconfig, ssrf, integrity, csrf
from reporting import html_generator, json_generator, csv_generator
from core.crawler import Crawler
from analysis.risk import RiskAnalyzer

class ScannerEngine:
    def __init__(self, output_callback=None):
        """
        output_callback: function(message_type, message_content)
        message_type: 'info', 'warning', 'error', 'success', 'progress'
        """
        self.output_callback = output_callback
        self.should_stop = False

    def log(self, type, message):
        if self.output_callback:
            self.output_callback(type, message)
        else:
            # Fallback for when running standalone (if needed)
            pass

    def stop(self):
        self.should_stop = True

    def run_scan(self, url, user_name="Admin"):
        if not url.startswith("http"):
            url = "http://" + url
        
        self.log("info", f"Validating target: {url}...")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            self.log("success", f"Target is online! [{response.status_code}]")
            
            if response.url != url:
                self.log("warning", f"Redirected to: {response.url}")
                # For automated engine, we usually follow redirects or stick to original.
                # Here we will follow specific logic or just notify.
                # For now, let's update url if redirected? 
                # In main.py it asks user. Here we'll stick to provided URL unless we decide otherwise.
                # Let's just create a notify.
                url = response.url # Auto-follow for web scanner simplicity
                self.log("info", f"Following redirect to: {url}")

        except requests.exceptions.RequestException as e:
            self.log("error", f"Could not connect to target: {e}")
            return None

        # --- Step 1: Discover Endpoints (Crawler) ---
        self.log("info", "Crawling target for endpoints...")
        crawler = Crawler(url)
        # Note: Crawler might print to console internally if not modified. 
        # Ideally Crawler should also use a logger, but we can't change deep code easily without risk.
        # We assume Crawler is mostly silent or we accept stdout.
        discovered_urls = crawler.crawl(depth=2)
        
        if not discovered_urls:
            self.log("error", "Crawler failed to reach target.")
            return None
        
        self.log("info", f"Discovered {len(discovered_urls)} endpoints.")

        # --- Scan Registry ---
        scan_results = {
            "SQL Injection": [],
            "Cross-Site Scripting (XSS)": [],
            "Broken Authentication": [],
            "Sensitive Data Exposure": [],
            "Command Injection": [],
            "Directory Traversal": [],
            "Insecure File Upload": [],
            "CSRF": [],
            "IDOR": [],
            "Security Misconfiguration": [],
            "Rate Limiting": [],
            "Vulnerable and Outdated Components": [],
            "Integrity Failure": [],
            "Logging Failure": []
        }

        self.log("info", f"Starting Exhaustive Scan on {len(discovered_urls)} endpoints...")

        # Filter targets
        scanned_bases = set()
        targets_to_scan = []
        STATIC_EXTENSIONS = (
            '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', 
            '.css', '.js', '.ico', '.woff', '.woff2', '.ttf', '.eot', 
            '.mp3', '.mp4', '.avi', '.zip', '.rar', '.tar', '.gz', 
            '.7z', '.exe', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.xml', '.json'
        )

        for target_url in discovered_urls:
            base_path = target_url.split("?")[0]
            if base_path.lower().endswith(STATIC_EXTENSIONS):
                continue
            if base_path in scanned_bases:
                continue
            scanned_bases.add(base_path)
            targets_to_scan.append(target_url)
            if len(scanned_bases) >= 500:
                self.log("warning", "Hit limit of 500 unique endpoints for deep scan.")
                break

        if targets_to_scan:
            self.log("info", f"Selected {len(targets_to_scan)} unique endpoints for parallel scanning.")
            
            def scan_endpoint_worker(target_url):
                if self.should_stop: return {}
                
                endpoint_results = {
                    "Command Injection": [],
                    "Directory Traversal": [],
                    "IDOR": [],
                    "SQL Injection": [],
                    "Cross-Site Scripting (XSS)": [],
                    "SSRF": []
                }
                
                # Parallelize internal scanners
                scan_tasks = {
                    "Command Injection": lambda: injection.scan_command_injection(target_url),
                    "Directory Traversal": lambda: file_attacks.scan_directory_traversal(target_url),
                    "IDOR": lambda: misconfig.scan_idor(target_url),
                    "SQL Injection": lambda: sql_injection.scan(target_url),
                    "Cross-Site Scripting (XSS)": lambda: xss.scan(target_url),
                    "SSRF": lambda: ssrf.scan_ssrf(target_url)
                }

                with ThreadPoolExecutor(max_workers=len(scan_tasks)) as internal_executor:
                    future_to_cat = {internal_executor.submit(func): cat for cat, func in scan_tasks.items()}
                    for future in as_completed(future_to_cat):
                         if self.should_stop: break
                         category = future_to_cat[future]
                         try:
                             findings = future.result()
                             if findings:
                                 endpoint_results[category].extend(findings)
                         except Exception:
                             pass
                
                return endpoint_results

            total_targets = len(targets_to_scan)
            completed_targets = 0
            start_time = time.time()

            executor = ThreadPoolExecutor(max_workers=ENDPOINT_THREADS)
            try:
                future_to_url = {executor.submit(scan_endpoint_worker, url): url for url in targets_to_scan}
                
                for future in as_completed(future_to_url):
                    if self.should_stop: 
                        self.log("warning", "Stopping scan immediately...")
                        break
                    
                    try:
                        data = future.result()
                        for category, findings in data.items():
                            if category in scan_results:
                                scan_results[category].extend(findings)
                    except Exception as exc:
                        self.log("error", f"Scanner generated an exception: {exc}")
                    
                    completed_targets += 1
                    
                    # Calculate ETA
                    elapsed = time.time() - start_time
                    if completed_targets > 0:
                        avg_time = elapsed / completed_targets
                        remaining_targets = total_targets - completed_targets
                        eta_seconds = int(remaining_targets * avg_time)
                        
                        # Send ETA update
                        if self.output_callback:
                            self.output_callback("eta", str(eta_seconds))

                    percent = int((completed_targets / total_targets) * 100)
                    self.log("progress", str(percent))
            finally:
                # If stopped, kill everything immediately
                if self.should_stop:
                    executor.shutdown(wait=False, cancel_futures=True)
                else:
                    executor.shutdown(wait=True)

        # --- step 3: Global Scanners ---
        if not self.should_stop:
            self.log("info", "Running Global Configuration Scans (Parallel)...")
            
            upload_endpoint = url + "/upload.php"
            check_endpoint = url + "/uploads"

            global_tasks = {
                "Sensitive Data Exposure": lambda: sensitive_data.scan(url),
                "Broken Authentication": lambda: auth.scan(url),
                "Insecure File Upload": lambda: file_attacks.scan_insecure_file_upload(upload_endpoint, check_endpoint),
                "Security Misconfiguration": lambda: misconfig.scan_security_misconfiguration(url),
                "Rate Limiting": lambda: misconfig.scan_multiple_login_attempts(url),
                "Integrity Failure": lambda: integrity.scan(url),
                "CSRF": lambda: csrf.scan(url)
            }

            with ThreadPoolExecutor(max_workers=len(global_tasks)) as global_executor:
                future_to_task = {global_executor.submit(func): name for name, func in global_tasks.items()}
                
                for future in as_completed(future_to_task):
                    if self.should_stop: break
                    name = future_to_task[future]
                    try:
                        results = future.result()
                        if results:
                            scan_results[name] = results
                    except Exception as e:
                        self.log("error", f"Global scan {name} error: {e}")

        # Flatten
        all_vulnerabilities = []
        for findings in scan_results.values():
            all_vulnerabilities.extend(findings)

        # Analysis
        self.log("info", "Analyzing vulnerabilities for Risk Score & Impact...")
        if all_vulnerabilities:
            analyzer = RiskAnalyzer()
            enriched_vulnerabilities = analyzer.analyze(all_vulnerabilities)
            self.log("success", f"Analysis Complete. Found {len(enriched_vulnerabilities)} vulnerabilities.")
        else:
            enriched_vulnerabilities = []
            self.log("success", "Scan completed. No vulnerabilities found.")

        # Reporting
        self.log("info", "Generating reports...")
        gen_start_time = time.time()
        
        # Calculate total scan duration
        total_scan_duration = time.time() - start_time
        
        # Pass duration to report generator (assuming it can handle it or we update it)
        # For now, just logging it as requested "estimated time [calculation]"
        report_path = html_generator.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
        
        gen_duration = time.time() - gen_start_time
        self.log("info", f"Report generated in {gen_duration:.2f} seconds. (Total Scan Time: {total_scan_duration:.2f}s)")
        
        json_gen = json_generator.JsonGenerator()
        json_path = json_gen.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
        
        csv_gen = csv_generator.CsvGenerator()
        csv_path = csv_gen.generate_report(user_name, url, enriched_vulnerabilities)

        return {
            "html_report": report_path,
            "json_report": json_path,
            "csv_report": csv_path,
            "vulnerability_count": len(enriched_vulnerabilities)
        }
