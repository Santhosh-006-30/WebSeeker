"""
Advanced API Endpoint Discovery Module
Discovers API endpoints from a given target URL through multiple techniques:
1. JavaScript file analysis
2. Common API endpoint fuzzing
3. robots.txt and sitemap.xml parsing
4. HTML/JSON response analysis
5. Common framework-specific endpoints
"""

import requests
import re
import json
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import Colors, TIMEOUT, MAX_THREADS

class APIDiscovery:
    def __init__(self, target_url, timeout=TIMEOUT):  # Use global fast timeout
        # Parse the URL to extract base components
        parsed = urlparse(target_url)
        
        # Extract the base URL (scheme + host) - this is where we fuzz from
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Keep the original target for reference
        self.original_target = target_url.rstrip('/')
        
        # For fuzzing, we use the base URL
        self.target_url = self.base_url
        
        self.base_domain = parsed.netloc
        self.timeout = timeout
        self.discovered_endpoints = set()
        self.api_base_paths = []
        
        # If the user provided a specific path, add it as a discovered endpoint
        if parsed.path and parsed.path != '/':
            self.discovered_endpoints.add(target_url.rstrip('/'))
        
        # Common API prefixes to check
        self.api_prefixes = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/graphql', '/gql',
            '/v1', '/v2', '/v3',
            '/backend', '/server',
            '/ajax', '/json', '/data',
            '/services', '/service',
            '/ws', '/websocket',
            '/rpc', '/jsonrpc',
            '/public/api', '/private/api'
        ]
        
        # Common API endpoint patterns
        self.common_endpoints = [
            # Authentication
            'login', 'logout', 'register', 'signup', 'signin', 'signout',
            'auth', 'authenticate', 'oauth', 'token', 'refresh',
            'forgot-password', 'reset-password', 'change-password',
            'verify', 'confirm', 'activate', 'session',
            
            # User Management
            'users', 'user', 'profile', 'account', 'me', 'self',
            'settings', 'preferences', 'permissions', 'roles',
            
            # Common CRUD Resources
            'items', 'products', 'orders', 'posts', 'comments',
            'articles', 'blogs', 'news', 'events', 'notifications',
            'messages', 'chats', 'conversations', 'files', 'uploads',
            'images', 'media', 'documents', 'attachments',
            
            # JSONPlaceholder / Common REST Resources
            'todos', 'albums', 'photos', 'users', 'posts', 'comments',
            
            # Admin/Management
            'admin', 'dashboard', 'stats', 'analytics', 'reports',
            'logs', 'audit', 'monitoring', 'health', 'status',
            'config', 'configuration', 'settings', 'system',
            
            # Data Operations
            'search', 'filter', 'sort', 'export', 'import',
            'download', 'upload', 'sync', 'backup', 'restore',
            
            # API Info
            'info', 'version', 'docs', 'swagger', 'openapi',
            'schema', 'metadata', 'endpoints', 'routes',
            
            # Common Actions
            'create', 'read', 'update', 'delete', 'list', 'get',
            'add', 'remove', 'submit', 'process', 'validate'
        ]
        
        # Patterns to identify API URLs in JavaScript
        self.js_api_patterns = [
            r'["\'](?:https?://[^"\']*?)?(/(?:api|rest|v\d|graphql)[^"\']*)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\.(?:get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'(?:baseURL|apiUrl|endpoint|url)\s*[:=]\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest[^;]*\.open\s*\([^,]+,\s*["\']([^"\']+)["\']',
            r'["\'](?:GET|POST|PUT|PATCH|DELETE)["\']\s*,\s*["\']([^"\']+)["\']',
            r'/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*(?:\?[^"\']*)?'
        ]
        
        # Headers for requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        }

    def discover(self):
        """Main discovery method - runs ALL discovery techniques in PARALLEL for speed."""
        Colors.info("Starting Fast Parallel API Discovery...")
        
        # Run all discovery techniques simultaneously for maximum speed
        with ThreadPoolExecutor(max_workers=6) as executor:
            # Submit all discovery tasks in parallel
            futures = {
                executor.submit(self._discover_api_bases): "API Bases",
                executor.submit(self._parse_robots_sitemap): "Robots/Sitemap",
                executor.submit(self._analyze_main_page): "JS Analysis",
                executor.submit(self._fuzz_common_endpoints_fast): "Endpoint Fuzzing",
                executor.submit(self._check_framework_endpoints): "Framework Endpoints"
            }
            
            # Wait for all to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    pass  # Continue even if one method fails
        
        # Quick validation (skip deep analysis for speed)
        valid_endpoints = self._validate_endpoints()
        
        Colors.success(f"Fast Discovery Complete. Found {len(valid_endpoints)} API endpoints.")
        return list(valid_endpoints)
    
    def _fuzz_common_endpoints_fast(self):
        """Fast parallel fuzzing of common API endpoints with reduced set."""
        # Use a smaller, high-value endpoint list for speed
        priority_endpoints = [
            'login', 'logout', 'register', 'auth', 'token', 'users', 'user', 
            'profile', 'account', 'admin', 'dashboard', 'search', 'upload',
            'api', 'data', 'config', 'settings', 'health', 'status', 'info',
            'docs', 'swagger', 'graphql', 'posts', 'items', 'orders'
        ]
        
        endpoints_to_check = []
        base_paths = self.api_base_paths if self.api_base_paths else ['/api', '/api/v1', '']
        
        for base in base_paths[:3]:  # Limit base paths for speed
            for endpoint in priority_endpoints:
                endpoints_to_check.append(f"{base}/{endpoint}")
        
        def check_endpoint_fast(path):
            try:
                url = f"{self.target_url}{path}"
                response = requests.get(url, headers=self.headers, timeout=3, verify=False, allow_redirects=False)
                if response.status_code not in [404, 301, 302, 0]:
                    return url
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(check_endpoint_fast, path): path for path in endpoints_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.discovered_endpoints.add(result)

    def _discover_api_bases(self):
        """Discover which API base paths exist."""
        Colors.info("Discovering API base paths...")
        
        def check_api_base(prefix):
            try:
                url = f"{self.target_url}{prefix}"
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                
                # Check if it returns something useful (not 404, not redirect to main page)
                if response.status_code in [200, 201, 400, 401, 403, 405, 500]:
                    content_type = response.headers.get('Content-Type', '')
                    if 'json' in content_type or 'xml' in content_type:
                        return prefix
                    # Also check if body looks like JSON
                    try:
                        json.loads(response.text)
                        return prefix
                    except:
                        pass
                # 301/302 to a different path might still be valid
                if response.status_code in [301, 302]:
                    location = response.headers.get('Location', '')
                    if '/api' in location.lower() or '/v1' in location.lower():
                        return prefix
                return None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(check_api_base, prefix): prefix for prefix in self.api_prefixes}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.api_base_paths.append(result)
                    Colors.success(f"  [+] Found API base: {result}")
        
        if not self.api_base_paths:
            # Default to trying /api if nothing found
            self.api_base_paths = ['/api', '/api/v1', '']

    def _parse_robots_sitemap(self):
        """Parse robots.txt and sitemap.xml for API endpoints."""
        Colors.info("Checking robots.txt and sitemap.xml...")
        
        # Check robots.txt
        try:
            response = requests.get(f"{self.target_url}/robots.txt", headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                # Look for API paths
                for line in response.text.split('\n'):
                    if ':' in line:
                        path = line.split(':', 1)[1].strip()
                        if any(api_prefix in path.lower() for api_prefix in ['api', 'rest', '/v1', '/v2']):
                            full_url = urljoin(self.target_url, path)
                            self.discovered_endpoints.add(full_url)
                            print(f"  [+] From robots.txt: {full_url}")
        except:
            pass
        
        # Check sitemap.xml
        sitemap_urls = [
            f"{self.target_url}/sitemap.xml",
            f"{self.target_url}/sitemap_index.xml",
            f"{self.target_url}/api/sitemap.xml"
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                response = requests.get(sitemap_url, headers=self.headers, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    # Extract URLs from sitemap
                    urls = re.findall(r'<loc>([^<]+)</loc>', response.text)
                    for url in urls:
                        if any(kw in url.lower() for kw in ['api', 'rest', 'graphql', '/v1', '/v2']):
                            self.discovered_endpoints.add(url)
                            print(f"  [+] From sitemap: {url}")
            except:
                pass

    def _analyze_main_page(self):
        """Analyze main page HTML and linked JS files for API endpoints."""
        Colors.info("Analyzing frontend for API calls...")
        
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code != 200:
                return
            
            html_content = response.text
            
            # Extract API calls from inline scripts
            self._extract_api_from_content(html_content)
            
            # Find and analyze JS files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html_content)
            js_urls += re.findall(r'<script[^>]+src=["\']([^"\']+chunk[^"\']*)["\']', html_content)
            
            Colors.info(f"Found {len(js_urls)} JavaScript files to analyze...")
            
            for js_url in js_urls:
                full_js_url = urljoin(self.target_url, js_url)
                try:
                    js_response = requests.get(full_js_url, headers=self.headers, timeout=self.timeout, verify=False)
                    if js_response.status_code == 200:
                        self._extract_api_from_content(js_response.text)
                except:
                    pass
                    
        except Exception as e:
            Colors.warning(f"Error analyzing main page: {e}")

    def _extract_api_from_content(self, content):
        """Extract API endpoints from JavaScript or HTML content."""
        for pattern in self.js_api_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    
                    # Clean and validate the path
                    if match and len(match) > 1:
                        # Skip if it's a full external URL
                        if match.startswith('http') and self.base_domain not in match:
                            continue
                        
                        # Build full URL
                        if match.startswith('/'):
                            full_url = urljoin(self.target_url, match)
                        elif match.startswith('http'):
                            full_url = match
                        else:
                            full_url = urljoin(self.target_url, '/' + match)
                        
                        # Filter out obvious non-API paths
                        if any(ext in full_url.lower() for ext in ['.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff']):
                            continue
                            
                        self.discovered_endpoints.add(full_url)
                        print(f"  [+] From JS analysis: {full_url}")
            except:
                pass

    def _fuzz_common_endpoints(self):
        """Fuzz common API endpoints."""
        Colors.info("Fuzzing common API endpoints...")
        
        endpoints_to_check = []
        
        # Build list of endpoints to check
        for base in self.api_base_paths:
            for endpoint in self.common_endpoints:
                endpoints_to_check.append(f"{base}/{endpoint}")
                # Also try with common CRUD patterns
                endpoints_to_check.append(f"{base}/{endpoint}/1")
                endpoints_to_check.append(f"{base}/{endpoint}/list")
                endpoints_to_check.append(f"{base}/{endpoint}/all")
        
        def check_endpoint(path):
            try:
                url = f"{self.target_url}{path}"
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                
                # Consider it valid if not 404
                if response.status_code != 404:
                    content_type = response.headers.get('Content-Type', '')
                    # Prefer JSON responses but accept others
                    if response.status_code in [200, 201, 400, 401, 403, 405, 500]:
                        return url
                    if 'json' in content_type or 'xml' in content_type:
                        return url
                return None
            except:
                return None
        
        Colors.info(f"Checking {len(endpoints_to_check)} potential endpoints...")
        
        found_count = 0
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(check_endpoint, path): path for path in endpoints_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.discovered_endpoints.add(result)
                    print(f"  [+] Found endpoint: {result}")
                    found_count += 1
        
        Colors.success(f"Fuzzing found {found_count} endpoints")

    def _check_framework_endpoints(self):
        """Check for common framework-specific endpoints."""
        Colors.info("Checking framework-specific endpoints...")
        
        framework_endpoints = [
            # Express/Node.js
            '/__express_routes',
            
            # Django
            '/admin/', '/api/schema/', '/api/docs/',
            
            # Flask
            '/static/', '/api/',
            
            # Laravel
            '/telescope', '/horizon', '/_debugbar',
            
            # Spring Boot
            '/actuator', '/actuator/health', '/actuator/info',
            '/actuator/metrics', '/actuator/env', '/actuator/mappings',
            '/swagger-ui.html', '/swagger-ui/', '/v2/api-docs', '/v3/api-docs',
            
            # ASP.NET
            '/swagger', '/api/values', '/_blazor',
            
            # Ruby on Rails
            '/rails/info/routes', '/rails/info/properties',
            
            # GraphQL
            '/graphql', '/graphiql', '/playground', '/graphql/playground',
            '/graphql/schema', '/graphql-explorer',
            
            # API Documentation
            '/docs', '/api/docs', '/api/documentation',
            '/redoc', '/api/redoc', '/openapi.json', '/openapi.yaml',
            '/swagger.json', '/swagger.yaml', '/spec', '/api/spec',
            
            # Health/Status
            '/health', '/healthz', '/healthcheck', '/ping', '/ready',
            '/status', '/api/status', '/api/health',
            
            # Debug
            '/debug', '/trace', '/phpinfo.php', '/info.php',
            '/server-status', '/server-info',
            
            # Common API Versioning
            '/api/v1/docs', '/api/v1/info', '/api/v1/status',
            '/api/v2/docs', '/api/v2/info', '/api/v2/status',
        ]
        
        def check_framework_endpoint(path):
            try:
                url = f"{self.target_url}{path}"
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                if response.status_code not in [404, 301, 302]:
                    return url
                return None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(check_framework_endpoint, path): path for path in framework_endpoints}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.discovered_endpoints.add(result)
                    print(f"  [+] Framework endpoint: {result}")

    def _deep_analyze_endpoints(self):
        """Analyze discovered endpoints for more paths."""
        Colors.info("Deep analyzing discovered endpoints...")
        
        new_endpoints = set()
        
        for endpoint in list(self.discovered_endpoints):
            try:
                response = requests.get(endpoint, headers=self.headers, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    # If JSON, look for nested URLs or endpoints
                    if 'json' in content_type:
                        try:
                            data = response.json()
                            self._extract_urls_from_json(data, new_endpoints)
                        except:
                            pass
                    
                    # Look for API paths in HTML/text responses
                    self._extract_api_from_content(response.text)
                    
            except:
                pass
        
        self.discovered_endpoints.update(new_endpoints)

    def _extract_urls_from_json(self, data, url_set, depth=0):
        """Recursively extract URLs from JSON data."""
        if depth > 5:
            return
            
        if isinstance(data, dict):
            for key, value in data.items():
                # Check if value looks like a URL or path
                if isinstance(value, str):
                    if value.startswith('/') or value.startswith('http'):
                        clean_url = urljoin(self.target_url, value)
                        if self.base_domain in clean_url:
                            url_set.add(clean_url)
                elif isinstance(value, (dict, list)):
                    self._extract_urls_from_json(value, url_set, depth + 1)
        elif isinstance(data, list):
            for item in data:
                self._extract_urls_from_json(item, url_set, depth + 1)

    def _validate_endpoints(self):
        """Validate and filter discovered endpoints."""
        Colors.info("Validating discovered endpoints...")
        
        valid_endpoints = set()
        
        # Filter endpoints
        for endpoint in self.discovered_endpoints:
            parsed = urlparse(endpoint)
            
            # Only include endpoints from target domain
            if parsed.netloc and parsed.netloc != self.base_domain:
                continue
            
            # Skip fragment-only URLs (like #about)
            if parsed.fragment and not parsed.path.strip('/'):
                continue
            
            # Skip obvious static files
            static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', 
                               '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip']
            if any(parsed.path.lower().endswith(ext) for ext in static_extensions):
                continue
            
            # Normalize URL (remove fragments)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"
            
            valid_endpoints.add(clean_url)
        
        # Remove duplicates that only differ by trailing slash
        final_endpoints = set()
        for endpoint in valid_endpoints:
            normalized = endpoint.rstrip('/')
            if normalized not in final_endpoints and (normalized + '/') not in final_endpoints:
                final_endpoints.add(endpoint)
        
        return final_endpoints


def discover_api_endpoints(target_url, timeout=10):
    """Convenience function to discover API endpoints."""
    discovery = APIDiscovery(target_url, timeout)
    return discovery.discover()
