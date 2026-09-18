
import requests
import threading
import urllib3
import random
from config import USER_AGENTS, TIMEOUT, DELAY, Colors
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Thread-local sessions ─────────────────────────────────────────────────────
# Each thread gets its own Session — eliminates connection pool lock contention
# that happens when many threads share a single Session object.
_thread_local = threading.local()

def _get_session():
    """Return a thread-local requests.Session, creating it if needed."""
    if not hasattr(_thread_local, 'session'):
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=0
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.verify = False
        session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        _thread_local.session = session
    return _thread_local.session


class Network:
    """Thin wrapper that delegates to thread-local sessions for zero contention."""

    def get(self, url, params=None, **kwargs):
        if DELAY > 0:
            time.sleep(DELAY)
        try:
            timeout = kwargs.pop('timeout', TIMEOUT)
            verify = kwargs.pop('verify', False)
            return _get_session().get(url, params=params, timeout=timeout, verify=verify, **kwargs)
        except requests.RequestException:
            return None

    def post(self, url, data=None, json=None, **kwargs):
        if DELAY > 0:
            time.sleep(DELAY)
        try:
            timeout = kwargs.pop('timeout', TIMEOUT)
            verify = kwargs.pop('verify', False)
            return _get_session().post(url, data=data, json=json, timeout=timeout, verify=verify, **kwargs)
        except requests.RequestException:
            return None

    def head(self, url, **kwargs):
        """HEAD request — useful for fast liveness checks (no body download)."""
        try:
            timeout = kwargs.pop('timeout', TIMEOUT)
            verify = kwargs.pop('verify', False)
            return _get_session().head(url, timeout=timeout, verify=verify, **kwargs)
        except requests.RequestException:
            return None



# Global singleton — lightweight now since sessions are thread-local
requester = Network()
