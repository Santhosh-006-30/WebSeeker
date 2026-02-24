
import sys
import argparse
import time
from config import Colors, console, MAX_THREADS, ENDPOINT_THREADS
from scanners import sql_injection, xss, auth, sensitive_data, injection, file_attacks, misconfig, ssrf, integrity, csrf
from reporting import html_generator, popup
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table

LOGO = r"""
    _    _      _      ______                      
   | |  | |    | |     |  ___|                     
   | |  | | ___| |__   | |_ _   _ ___________ _ __ 
   | |/\| |/ _ \ '_ \  |  _| | | |_  /_  / _ \ '__|
   \  /\  /  __/ |_) | | | | |_| |/ / / /  __/ |   
    \/  \/ \___|_.__/  \_|  \__,_/___/___\___|_|   
                                                   
    Professional Web Vulnerability Scanner
"""

from core.crawler import Crawler
from core.api_discovery import APIDiscovery
from analysis.risk import RiskAnalyzer

def main():
    console.print(Panel.fit(f"[bold blue]{LOGO}[/bold blue]", border_style="blue"))
    
    # Argument Parsing
    if len(sys.argv) < 2:
        # Launch Web UI mode by default if no arguments provided
        console.print("\n[bold green]🚀 Launching WebSeeker Dashboard...[/bold green]")
        console.print("[dim]Starting local web server and opening browser...[/dim]\n")
        
        import subprocess
        import os
        
        # Get the directory of the current script
        current_dir = os.path.dirname(os.path.abspath(__file__))
        web_app_path = os.path.join(current_dir, "web_app.py")
        
        try:
            # Run web_app.py in a subprocess
            subprocess.run([sys.executable, web_app_path])
        except KeyboardInterrupt:
            console.print("\n[bold red]Web UI stopped.[/bold red]")
        sys.exit(0)
    else:
        url = sys.argv[1]

    if not url.startswith("http"):
        url = "http://" + url
    
    # --- Step 0: Validate Target URL ---
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Headers for API requests
    api_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/html, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
    }
    
    Colors.info(f"Validating target: {url}...")
    
    # Retry logic for cold-start servers (like Render free tier)
    max_retries = 3
    response = None
    
    for attempt in range(max_retries):
        try:
            # Check connectivity with proper headers
            response = requests.get(url, timeout=30, verify=False, headers=api_headers)
            Colors.success(f"Target is online! [{response.status_code}]")
            break
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                Colors.warning(f"Connection attempt {attempt + 1} failed. Retrying in 1 second...")
                time.sleep(1)
            else:
                Colors.error(f"Could not connect to target after {max_retries} attempts: {e}")
                Colors.error("Please check the URL is correct and reachable.")
                sys.exit(1)
    
    if response:
        # Handle Redirects
        if response.url != url:
            Colors.warning(f"Redirected to: {response.url}")
            choice = console.input(f"[warning]Do you want to scan this redirected URL? (y/n): [/warning]").strip().lower()
            if choice == 'y' or choice == '':
                url = response.url
            else:
                Colors.info("Keeping original URL (Warning: Scan might be less effective).")

    user_name = "Admin"
    
    # --- Check if this looks like a frontend URL ---
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    is_likely_frontend = not any(kw in parsed_url.path.lower() or kw in parsed_url.netloc.lower() 
                                  for kw in ['api', 'rest', 'graphql', 'v1', 'v2', 'backend'])
    
    if is_likely_frontend:
        console.print("\n[bold yellow]⚠️  This looks like a frontend URL.[/bold yellow]")
        console.print("[dim]Frontend URLs (like React/Angular apps) often don't have testable vulnerabilities.[/dim]")
        console.print("[dim]For better results, provide the API backend URL if you know it.[/dim]\n")
        
        api_url_input = console.input("[bold green]Enter API Base URL (or press Enter to auto-discover): [/bold green]").strip()
        
        if api_url_input:
            if not api_url_input.startswith("http"):
                api_url_input = "https://" + api_url_input
            # Validate the API URL
            try:
                api_response = requests.get(api_url_input, timeout=10, verify=False, headers=api_headers)
                if api_response.status_code < 500:
                    Colors.success(f"API URL is reachable! [{api_response.status_code}]")
                    url = api_url_input  # Use the provided API URL
                else:
                    Colors.warning("API URL returned an error. Will try to auto-discover endpoints.")
            except:
                Colors.warning("Could not reach API URL. Will try to auto-discover endpoints.")
    
    # --- Step 1: API Endpoint Discovery ---
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]                   API ENDPOINT DISCOVERY                      [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    console.print("[dim]Analyzing JavaScript files, crawling common paths, and fuzzing for endpoints...[/dim]\n")
    
    api_discovery = APIDiscovery(url)
    discovered_urls = api_discovery.discover()
    
    # Filter discovered URLs to prioritize API endpoints
    def filter_api_endpoints(urls):
        api_keywords = ['api', 'rest', 'v1', 'v2', 'v3', 'graphql', 'json', 'data', 'auth', 'login', 'users', 'admin', 'webhook', 'callback']
        filtered = []
        for u in urls:
            p = urlparse(u)
            if p.fragment and not p.path.strip('/'):
                continue # Skip hash routing
            if p.path.lower().endswith(('.css', '.js', '.png', '.jpg', '.ico', '.svg', '.woff', '.ttf')):
                continue # Skip static
            
            # Prioritize API-looking paths or if explicitly discovered via fuzzing
            if any(k in u.lower() for k in api_keywords) or '?' in u:
                if u not in filtered:
                    filtered.append(u)
            elif u not in filtered:
                 # Add others but maybe later prioritize? For now add all valid looking
                 filtered.append(u)
        return filtered

    discovered_urls = filter_api_endpoints(discovered_urls)
    discovered_urls = list(set(discovered_urls)) # Dedup

    if not discovered_urls:
        Colors.warning("No specific API endpoints found. Falling back to crawling the main site.")
        with console.status("[bold green]Crawling target for endpoints...[/bold green]") as status:
            crawler = Crawler(url)
            discovered_urls = crawler.crawl(depth=2)
    
    if not discovered_urls:
        Colors.error("No endpoints discovered. Exiting.")
        sys.exit(1)

    Colors.success(f"Targeting {len(discovered_urls)} potential API endpoints.")

    # --- Scan Registry (Track all module results) ---
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
        "Vulnerable and Outdated Components": [], # A06
        "Integrity Failure": [], # A08
        "Logging Failure": [] # A09
    }

    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]           🛡️ DEEP VULNERABILITY SCANNING (ACCURATE) 🛡️           [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    Colors.info(f"Deep-scanning {len(discovered_urls)} API endpoints for maximum accuracy...")
    
    # Track scanned base URLs to avoid duplicate scans
    scanned_bases = set()
    
    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        # Pre-filter targets
        targets_to_scan = []
        
        # Extensions to skip
        STATIC_EXTENSIONS = (
            '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg', 
            '.css', '.js', '.ico', '.woff', '.woff2', '.ttf'
        )

        for target_url in discovered_urls:
            base_path = target_url.split("?")[0]
            if base_path.lower().endswith(STATIC_EXTENSIONS):
                continue
            if base_path in scanned_bases:
                continue
            scanned_bases.add(base_path)
            targets_to_scan.append(target_url)
            
            if len(scanned_bases) >= 500:  # Higher limit for accuracy
                break
        
        if targets_to_scan:
            Colors.info(f"🛡️  Testing {len(targets_to_scan)} endpoints with full payload sets...")
            console.print("[dim]This may take longer, but ensures high accuracy.[/dim]\n")

            def scan_endpoint_worker(target_url):
                endpoint_results = {
                    "Command Injection": [],
                    "Directory Traversal": [],
                    "IDOR": [],
                    "SQL Injection": [],
                    "Cross-Site Scripting (XSS)": [],
                    "SSRF": []
                }
                
                try:
                    # Parallelize internal scanners
                    scan_tasks = {
                        "Command Injection": lambda: injection.scan_command_injection(target_url),
                        "Directory Traversal": lambda: file_attacks.scan_directory_traversal(target_url),
                        "IDOR": lambda: misconfig.scan_idor(target_url),
                        "SQL Injection": lambda: sql_injection.scan(target_url),
                        "Cross-Site Scripting (XSS)": lambda: xss.scan(target_url),
                        "SSRF": lambda: ssrf.scan_ssrf(target_url)
                    }

                    # Use a new executor for internal parallelization
                    with ThreadPoolExecutor(max_workers=len(scan_tasks)) as internal_executor:
                        future_to_cat = {internal_executor.submit(func): cat for cat, func in scan_tasks.items()}
                        for future in as_completed(future_to_cat):
                             category = future_to_cat[future]
                             try:
                                 findings = future.result()
                                 if findings:
                                     endpoint_results[category].extend(findings)
                             except Exception:
                                 pass
                except Exception:
                    pass
                
                return endpoint_results

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
                transient=False
            ) as progress:
                # Progress bar reflects deep scan nature (slower but thorough)
                task = progress.add_task(f"[cyan]🛡️ Deep scanning...", total=len(targets_to_scan))
                
                # Maximized Parallelism
                # Maximized Parallelism
                executor = ThreadPoolExecutor(max_workers=ENDPOINT_THREADS)
                try:
                    future_to_url = {executor.submit(scan_endpoint_worker, url): url for url in targets_to_scan}
                    
                    for future in as_completed(future_to_url):
                        try:
                            # Use timeout to allow checking for interrupts if needed, though keyboardinterrupt breaks handle loop
                            data = future.result(timeout=180) 
                            for category, findings in data.items():
                                if category in scan_results and findings:
                                    scan_results[category].extend(findings)
                        except Exception:
                            pass
                        progress.advance(task)
                except KeyboardInterrupt:
                    raise # Re-raise to be caught by outer handler
                finally:
                    # Quick shutdown on exit
                    executor.shutdown(wait=False)
                        
        # --- Step 3: Global/Generic Scanners ---
        with console.status("[bold green]Running Global Configuration Scans...[/bold green]"):
            global_tasks = {
                "Sensitive Data Exposure": lambda: sensitive_data.scan(url),
                "Broken Authentication": lambda: auth.scan(url),
                "Insecure File Upload": lambda: file_attacks.scan_insecure_file_upload(url + "/upload.php", url + "/uploads"),
                "Security Misconfiguration": lambda: misconfig.scan_security_misconfiguration(url),
                "Rate Limiting": lambda: misconfig.scan_multiple_login_attempts(url),
                "Integrity Failure": lambda: integrity.scan(url),
                "CSRF": lambda: csrf.scan(url)
            }

            with ThreadPoolExecutor(max_workers=len(global_tasks)) as global_executor:
                future_to_task = {global_executor.submit(func): name for name, func in global_tasks.items()}
                
                for future in as_completed(future_to_task):
                    name = future_to_task[future]
                    try:
                        results = future.result()
                        if results:
                            scan_results[name] = results
                    except Exception:
                        pass

    except KeyboardInterrupt:
        Colors.warning("[!] Scan interrupted by user. Generating report with available findings...")

    # Flatten for Analysis
    all_vulnerabilities = []
    for findings in scan_results.values():
        all_vulnerabilities.extend(findings)

    # --- Intelligence Layer ---
    if all_vulnerabilities:
        Colors.info("Analyzing vulnerabilities for Risk Score & Impact...")
        analyzer = RiskAnalyzer()
        enriched_vulnerabilities = analyzer.analyze(all_vulnerabilities)
        Colors.success(f"Analysis Complete. Processed {len(enriched_vulnerabilities)} findings.")
    else:
        enriched_vulnerabilities = []
        Colors.success("Scan completed. No vulnerabilities found.")
        
    # Reporting
    report_path = html_generator.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
    
    from reporting.json_generator import JsonGenerator
    from reporting.csv_generator import CsvGenerator
    
    json_gen = JsonGenerator()
    json_path = json_gen.generate_report(user_name, url, enriched_vulnerabilities, scan_summary=scan_results)
    
    csv_gen = CsvGenerator()
    csv_path = csv_gen.generate_report(user_name, url, enriched_vulnerabilities)
    
    # Final Summary Table
    table = Table(title="Scan Summary")
    table.add_column("Report Type", style="cyan")
    table.add_column("Path", style="magenta")
    
    table.add_row("HTML Report", report_path)
    table.add_row("JSON Report", json_path)
    table.add_row("CSV Report", csv_path)
    
    console.print(table)

    # Popup
    popup.show_results_popup(report_path)

if __name__ == "__main__":
    main()
