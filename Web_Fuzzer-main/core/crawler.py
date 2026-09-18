import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import Colors, CRAWLER_THREADS, TIMEOUT

class Crawler:
    def __init__(self, target_url):
        self.target_url = target_url
        self.base_url = target_url
        self.visited_urls = set()
        self.discovered_urls = []
        self.domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.verify = False

    def crawl(self, depth=2):
        """
        Crawls the target URL to discover endpoints using Threaded BFS.
        """
        Colors.info(f"Starting Threaded Crawler on {self.target_url} (Depth: {depth})...")
        
        # Level 0
        current_level_urls = {self.target_url}
        self.discovered_urls.append(self.target_url)
        self.visited_urls.add(self.target_url)

        for d in range(depth):
            Colors.info(f"Crawling Level {d+1} with {len(current_level_urls)} URLs...")
            
            next_level_urls = set()
            
            # Parallel Fetch
            with ThreadPoolExecutor(max_workers=CRAWLER_THREADS) as executor:
                future_to_url = {executor.submit(self.fetch_links, url): url for url in current_level_urls}
                
                for future in as_completed(future_to_url):
                    links = future.result()
                    for link in links:
                        if link not in self.visited_urls:
                            self.visited_urls.add(link)
                            self.discovered_urls.append(link)
                            next_level_urls.add(link)
                            # print(f"  [+] Discovered: {link}") # Too noisy for high speed
            
            current_level_urls = next_level_urls
            if not current_level_urls:
                break
             
        Colors.success(f"Crawler finished. Found {len(self.discovered_urls)} unique endpoints.")
        return self.discovered_urls

    def fetch_links(self, url):
        found_links = []
        try:
            response = self.session.get(url, timeout=TIMEOUT)
            if response.status_code != 200:
                return []

            try:
                soup = BeautifulSoup(response.text, 'lxml')
            except Exception:
                soup = BeautifulSoup(response.text, 'html.parser')

            
            # Helper to validate and add
            def add_if_valid(raw_url):
                full_url = urljoin(url, raw_url)
                parsed = urlparse(full_url)
                if parsed.netloc == self.domain:
                    # Filter static
                    if not any(full_url.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg']):
                        found_links.append(full_url)

            # Href
            for link in soup.find_all('a', href=True):
                add_if_valid(link['href'])
            
            # Form Action
            for form in soup.find_all('form', action=True):
                add_if_valid(form['action'])

        except:
            pass
        
        return found_links
