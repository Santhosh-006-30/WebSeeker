
import sys
import argparse
import time
from config import Colors, console
from scanners import sql_injection, xss, auth, sensitive_data, injection, file_attacks, misconfig, ssrf, integrity, csrf
from reporting import html_generator, popup
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table
from urllib.parse import urlparse

LOGO = r"""
    _    _      _      ______                      
   | |  | |    | |     |  ___|                     
   | |  | | ___| |__   | |_ _   _ ___________ _ __ 
   | |/\| |/ _ \ '_ \  |  _| | | |_  /_  / _ \ '__|
   \  /\  /  __/ |_) | | | | |_| |/ / / /  __/ |   
    \/  \/ \___|_.__/  \_|  \__,_/___/___\___|_|   
                                                   
    Professional Web Vulnerability Scanner
    [API-Focused Security Testing]
"""

from core.crawler import Crawler
from core.api_discovery import APIDiscovery
from analysis.risk import RiskAnalyzer

def filter_api_endpoints(urls):
    """
    Filter URLs to only include actual API endpoints.
    Removes frontend routes (with #), static files, and non-API paths.
    """
    api_keywords = ['api', 'rest', 'v1', 'v2', 'v3', 'graphql', 'json', 'data', 
                    'auth', 'login', 'users', 'admin', 'webhook', 'callback']
    
    filtered = []
    for url in urls:
        parsed = urlparse(url)
        
        # Skip URLs with hash fragments (frontend routes like #about, #tracks)
        if parsed.fragment and not parsed.path.strip('/'):
            continue
        
        # Skip obvious frontend routes
        if parsed.fragment in ['about', 'tracks', 'sponsors-list', 'contact', 'community', 
                                'home', 'features', 'pricing', 'team', 'blog', 'careers']:
            continue
            
        # Remove hash fragment from URL for cleaner endpoints
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url += f"?{parsed.query}"
        
        # Skip static files
        static_ext = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', 
                     '.ico', '.woff', '.woff2', '.ttf', '.pdf', '.zip')
        if parsed.path.lower().endswith(static_ext):
            continue
        
        # Skip empty paths (just the root)
        if not parsed.path or parsed.path == '/':
            # Include root only if it looks like an API
            if any(kw in parsed.netloc.lower() for kw in ['api', 'backend', 'server']):
                filtered.append(clean_url)
            continue
        
        # Check if path looks like an API endpoint
        path_lower = parsed.path.lower()
        is_api_like = any(kw in path_lower for kw in api_keywords)
        
        # Include if it looks like API or has query parameters (potential for injection)
        if is_api_like or parsed.query or '/' in parsed.path[1:]:
            if clean_url not in filtered:
                filtered.append(clean_url)
    
    return filtered

def main():
    console.print(Panel.fit(f"[bold blue]{LOGO}[/bold blue]", border_style="blue"))
    
    # Argument Parsing
    if len(sys.argv) < 2:
        console.print(f"[warning]Usage: python main.py <url>[/warning]")
        console.print("\n[bold cyan]╭─────────────────────────────────────────────────────────────╮[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan] [bold yellow]TIP:[/bold yellow] For accurate vulnerability testing, provide an API URL  [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]│[/bold cyan] Examples: https://api.example.com or https://example.com/api [bold cyan]│[/bold cyan]")
        console.print("[bold cyan]╰─────────────────────────────────────────────────────────────╯[/bold cyan]\n")
        url = console.input("[bold green]Enter Target URL: [/bold green]").strip()
        if not url:
            sys.exit(1)
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
                Colors.warning(f"Connection attempt {attempt + 1} failed. Retrying in 3 seconds... (Server might be warming up)")
                time.sleep(3)
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
    console.print("[bold cyan]                   API ENDPOINT DISCOVERY                        [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    Colors.info("Starting API Endpoint Discovery...")
    console.print("[dim]Analyzing JavaScript files, fuzzing common API paths, checking for OpenAPI specs...[/dim]\n")
    
    api_discovery = APIDiscovery(url)
    discovered_urls = api_discovery.discover()
    
    # Filter to only API endpoints
    if discovered_urls:
        original_count = len(discovered_urls)
        discovered_urls = filter_api_endpoints(discovered_urls)
        filtered_count = len(discovered_urls)
        
        if original_count != filtered_count:
            Colors.info(f"Filtered {original_count} URLs down to {filtered_count} testable API endpoints.")
    
    if not discovered_urls:
        Colors.warning("No API endpoints auto-discovered.")
        console.print("\n[bold yellow]Would you like to:[/bold yellow]")
        console.print("  [1] Enter API endpoints manually")
        console.print("  [2] Try frontend crawling (may find some endpoints)")
        console.print("  [3] Exit")
        
        fallback_choice = console.input("\n[bold green]Enter choice (1/2/3): [/bold green]").strip()
        
        if fallback_choice == "1":
            console.print("\n[dim]Enter each API endpoint URL, one per line. Type 'done' when finished.[/dim]")
            manual_endpoints = []
            while True:
                endpoint = console.input("[green]> [/green]").strip()
                if endpoint.lower() == 'done':
                    break
                if endpoint:
                    if not endpoint.startswith("http"):
                        endpoint = url.rstrip('/') + '/' + endpoint.lstrip('/')
                    manual_endpoints.append(endpoint)
                    Colors.success(f"Added: {endpoint}")
            discovered_urls = manual_endpoints
            
        elif fallback_choice == "2":
            Colors.info("Falling back to frontend crawling...")
            with console.status("[bold green]Crawling target for endpoints...[/bold green]") as status:
                crawler = Crawler(url)
                discovered_urls = crawler.crawl(depth=2)
            # Filter crawler results too
            discovered_urls = filter_api_endpoints(discovered_urls)
        else:
            Colors.info("Exiting.")
            sys.exit(0)
    
    if not discovered_urls:
        Colors.error("No testable endpoints found. Exiting.")
        sys.exit(1)
    
    # Display discovered endpoints
    console.print("\n[bold green]✓ Discovered API Endpoints:[/bold green]")
    for i, endpoint in enumerate(discovered_urls[:20], 1):
        console.print(f"  [cyan]{i:2}.[/cyan] {endpoint}")
    if len(discovered_urls) > 20:
        console.print(f"  [dim]... and {len(discovered_urls) - 20} more endpoints[/dim]")
    
    console.print(f"\n[bold]Total: {len(discovered_urls)} API endpoints ready for testing[/bold]\n")

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

    Colors.info(f"Starting Exhaustive Scan on {len(discovered_urls)} endpoints...")
    
    # Track scanned base URLs to avoid duplicate scans
    scanned_bases = set()
    
    try:
        # --- Step 2: Parallel Scanners on Discovered URLs ---
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Pre-filter targets (Optimization)
        targets_to_scan = []
        
        # Extensions to skip for heavy scanning
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
            
            if len(scanned_bases) >= 100: 
                Colors.warning("Hit limit of 100 unique endpoints. Stopping crawl selection.")
                break
        
        if targets_to_scan:
            Colors.info(f"Selected {len(targets_to_scan)} unique endpoints for parallel scanning.")

            def scan_endpoint_worker(target_url):
                endpoint_results = {
                    "Command Injection": [],
                    "Directory Traversal": [],
                    "IDOR": [],
                    "SQL Injection": [],
                    "Cross-Site Scripting (XSS)": [],
                    "SSRF": []
                }
                
                # Fast Checks
                endpoint_results["Command Injection"].extend(injection.scan_command_injection(target_url))
                endpoint_results["Directory Traversal"].extend(file_attacks.scan_directory_traversal(target_url))
                endpoint_results["IDOR"].extend(misconfig.scan_idor(target_url))
                
                # Heavy Checks
                endpoint_results["SQL Injection"].extend(sql_injection.scan(target_url))
                endpoint_results["Cross-Site Scripting (XSS)"].extend(xss.scan(target_url))
                endpoint_results["SSRF"].extend(ssrf.scan_ssrf(target_url))
                
                return endpoint_results

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                transient=True
            ) as progress:
                task = progress.add_task(f"[cyan]Scanning {len(targets_to_scan)} endpoints...", total=len(targets_to_scan))
                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_url = {executor.submit(scan_endpoint_worker, url): url for url in targets_to_scan}
                    
                    for future in as_completed(future_to_url):
                        data = future.result()
                        for category, findings in data.items():
                            if category in scan_results:
                                scan_results[category].extend(findings)
                        progress.advance(task)
        
        # --- Step 3: Global/Generic Scanners ---
        with console.status("[bold green]Running Global Configuration Scans...[/bold green]"):
            scan_results["Sensitive Data Exposure"] = sensitive_data.scan(url)
            scan_results["Broken Authentication"] = auth.scan(url)
            
            upload_endpoint = url + "/upload.php"
            check_endpoint = url + "/uploads"
            scan_results["Insecure File Upload"] = file_attacks.scan_insecure_file_upload(upload_endpoint, check_endpoint)
            
            scan_results["Security Misconfiguration"] = misconfig.scan_security_misconfiguration(url)
            scan_results["Rate Limiting"] = misconfig.scan_multiple_login_attempts(url)
            scan_results["Integrity Failure"] = integrity.scan(url)
            scan_results["CSRF"] = csrf.scan(url)

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
