"""
HTTP session factory with retry logic, rotating user-agents,
and optional SOCKS/HTTP proxy support.
"""

import random

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
]

DEFAULT_TIMEOUT = 10
MAX_RETRIES     = 2


def make_session(timeout: int = DEFAULT_TIMEOUT,
                 proxy_url: str = None) -> requests.Session:
    """
    Build a configured requests.Session with retry support.

    If *proxy_url* is provided it is used for both HTTP and HTTPS.
    Supported schemes: http, https, socks4, socks5, socks5h.
    Example: socks5://127.0.0.1:9050
    """
    sess = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers["User-Agent"] = random.choice(USER_AGENTS)
    sess.headers["Accept"] = (
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    )
    sess.headers["Accept-Language"] = "en-US,en;q=0.5"
    sess.timeout = timeout

    if proxy_url:
        sess.proxies = {
            "http":  proxy_url,
            "https": proxy_url,
        }
        # Force DNS resolution through proxy for SOCKS
        if proxy_url.startswith("socks5"):
            sess.proxies["http"]  = proxy_url
            sess.proxies["https"] = proxy_url

    return sess


def request_url(session: requests.Session, url: str,
                method: str = "GET", allow_redirects: bool = False,
                timeout: int = None):
    """Safe HTTP request that never raises on network errors."""
    try:
        return session.request(
            method, url,
            allow_redirects=allow_redirects,
            timeout=timeout or session.timeout,
        )
    except (
        requests.ConnectionError,
        requests.Timeout,
        requests.exceptions.InvalidURL,
        requests.exceptions.TooManyRedirects,
    ):
        return None
    except Exception:
        return None
