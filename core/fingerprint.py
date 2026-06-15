"""
Phase 1 — Laravel fingerprinting via cookies, headers, path probes,
and body-text signatures.
"""

from urllib.parse import urlparse

from core.session import request_url
from core.terminal import term, OK, INFO, FOUND, WARN, BRIGHT, Fore, Style
from data.signatures import PROBE_PATHS, BODY_PATTERNS

LARAVEL_THRESHOLD = 4  # minimum confidence score to declare "Laravel detected"


class FingerprintResult:
    """Stores the outcome of the fingerprinting phase."""

    def __init__(self):
        self.is_laravel         = False
        self.confidence         = 0
        self.indicators         = []  # list of (type, description)


def fingerprint(session, base_url: str) -> FingerprintResult:
    """
    Run all detection checks against base_url.
    Returns a FingerprintResult with confidence score and indicators.
    """
    result = FingerprintResult()
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    score  = 0
    indicators = []

    term.print(f"\n{Fore.CYAN}═══ PHASE 1 : LARAVEL FINGERPRINTING ═══{Style.RESET_ALL}\n")

    resp = request_url(session, base_url)

    # ── Cookie check ──
    if resp and resp.cookies:
        for cookie in resp.cookies:
            cname = cookie.name.lower()
            if "laravel_session" in cname:
                score += 3
                indicators.append(("cookie", "laravel_session cookie"))
            elif "laravel_token" in cname:
                score += 3
                indicators.append(("cookie", "laravel_token cookie"))
            elif "xf_session" in cname:
                score += 1
                indicators.append(("cookie", "xf_session cookie (possible Laravel)"))

    # ── Header check ──
    if resp and resp.headers:
        xpb = resp.headers.get("X-Powered-By", "")
        if "laravel" in xpb.lower():
            score += 3
            indicators.append(("header", f"X-Powered-By: {xpb.strip()}"))
        set_cookie = resp.headers.get("Set-Cookie", "")
        if "laravel_session" in set_cookie.lower():
            score += 3
            indicators.append(("header", "Set-Cookie contains laravel_session"))
        elif "laravel" in set_cookie.lower():
            score += 2
            indicators.append(("header", "Set-Cookie contains 'laravel'"))
        server = resp.headers.get("Server", "")
        if "laravel" in server.lower():
            score += 2
            indicators.append(("header", f"Server: {server.strip()}"))

    # ── Path probes ──
    for path, weight, desc in PROBE_PATHS:
        r = request_url(session, base + path)
        if r and r.status_code < 400:
            score += weight
            indicators.append(("path", f"{desc} [{r.status_code}]"))
            if path == "/api/user" and r.status_code == 200:
                ct = r.headers.get("Content-Type", "")
                if "json" in ct.lower():
                    score += 1
                    indicators.append(("body", "api/user returned JSON"))

    # ── Body text signatures (from homepage) ──
    if resp and resp.status_code == 200:
        body_lower = resp.text.lower()
        for pattern, weight in BODY_PATTERNS:
            if pattern in body_lower:
                score += weight
                indicators.append(("body", f"Pattern '{pattern}' found in response body"))

    # ── Populate result ──
    result.confidence = score
    result.indicators = indicators
    result.is_laravel = score >= LARAVEL_THRESHOLD

    # ── Report ──
    if result.is_laravel:
        term.print(f"  {FOUND}  Laravel DETECTED  (confidence: {score}/?)")
    elif score >= 2:
        term.print(f"  {WARN}  Possible Laravel  (confidence: {score}/?)")
    else:
        term.print(f"  {INFO}  No strong Laravel indicators (score: {score})")

    for typ, desc in indicators:
        icon = OK if typ in ("cookie", "header") else INFO
        term.print(f"    {icon} [{typ.upper()}] {desc}")

    term.print(f"\n  {INFO} Total Laravel confidence score: {BRIGHT}{score}{Style.RESET_ALL}\n")
    return result
