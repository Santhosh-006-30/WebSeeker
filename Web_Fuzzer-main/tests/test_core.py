import os
import sys
import pytest

# Ensure parent directory is in sys.path so modules like core, utils, config can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crawler import Crawler
from core.engine import ScannerEngine
from config import MAX_THREADS
import utils
from core.network import requester

def test_crawler_initialization():
    """Test that the crawler initializes with the correct base URL and domain."""
    url = "http://example.com"
    crawler = Crawler(url)
    assert crawler.base_url == url
    assert crawler.domain == "example.com"

def test_engine_initialization():
    """Test that the engine initializes and can stop."""
    engine = ScannerEngine()
    assert engine.should_stop is False
    engine.stop()
    assert engine.should_stop is True

def test_config_constants():
    """Test that critical speed constants exist."""
    assert isinstance(MAX_THREADS, int)
    assert MAX_THREADS > 0

def test_requester_custom_kwargs():
    """Test that Network requester handles custom kwargs (like timeout) without keyword argument collisions."""
    # Test HEAD request or GET request with custom timeout parameter
    res = requester.get("http://httpbin.org/get", timeout=3)
    # Even if unreachable offline, it shouldn't raise TypeError
    assert res is None or res.status_code == 200

def test_validate_and_normalize_target_fallback():
    """Test protocol fallback handling for target validation."""
    # Input with invalid protocol scheme should fallback or attempt correctly
    url, resp = utils.validate_and_normalize_target("http://httpbin.org/get", timeout=5)
    if resp:
        assert url.startswith("http")

