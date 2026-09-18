
import os

try:
    from rich.console import Console
    from rich.theme import Theme
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# Scan Settings - HYPER SPEED EXTREME
TIMEOUT = 3              # Reduced: fast fail on dead endpoints
MAX_THREADS = 50
CRAWLER_THREADS = 60     # More crawler parallelism
ENDPOINT_THREADS = 30    # 2x: more simultaneous endpoints
PAYLOAD_THREADS = 60     # 1.5x: more payload parallelism
# Total Concurrency = ENDPOINT_THREADS * PAYLOAD_THREADS ~= 1800 reqs/sec peak
DELAY = 0

# User-Agent Rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
]

# Reporting
REPORT_FILE = "report.html"

# Rich Console Configuration
if HAS_RICH:
    custom_theme = Theme({
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "vuln": "bold magenta",
        "header": "bold blue"
    })
    console = Console(theme=custom_theme)
else:
    class MockConsole:
        def print(self, msg, style=None):
            # Strip simple tags for readability if needed, or just print
            print(msg)
        def input(self, msg):
            return input(msg)
        def status(self, msg):
            class Context:
                def __enter__(self): print(f"[*] {msg}")
                def __exit__(self, *args): pass
            return Context()
            
    console = MockConsole()

class Colors:
    if HAS_RICH:
        @staticmethod
        def info(msg):
            console.print(f"[info][INFO] {msg}[/info]")

        @staticmethod
        def success(msg):
            console.print(f"[success][SUCCESS] {msg}[/success]")

        @staticmethod
        def warning(msg):
            console.print(f"[warning][WARN] {msg}[/warning]")
            
        @staticmethod
        def error(msg):
            console.print(f"[error][ERROR] {msg}[/error]")
        
        @staticmethod
        def vuln(msg):
            console.print(f"[vuln][VULN] {msg}[/vuln]")
    else:
        @staticmethod
        def info(msg):
            print(f"[INFO] {msg}")

        @staticmethod
        def success(msg):
            print(f"[SUCCESS] {msg}")

        @staticmethod
        def warning(msg):
            print(f"[WARN] {msg}")
            
        @staticmethod
        def error(msg):
            print(f"[ERROR] {msg}")
        
        @staticmethod
        def vuln(msg):
            print(f"[VULN] {msg}")
    
    # ANSI codes for fallback if needed in raw strings elsewhere
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
