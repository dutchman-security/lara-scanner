"""
Phase 2 — Multi-threaded path discovery.
Strictly identifies real Laravel log files and valuable leaked artifacts.
"""

import concurrent.futures
import re
import time
from urllib.parse import urlparse

from core.session import request_url
from core.terminal import term, INFO, FOUND, BRIGHT, Fore, Style
from data.paths import build_path_list
from data.signatures import risk_of, RISK_COLORS


# ── Strict log-detection patterns ─────────────────────────
#
# A file is flagged as [LOG] only when its content genuinely
# looks like a Laravel log file — stack traces, SQL errors,
# exception dumps, environment leaks, etc.

_STRONG_LOG_PATTERNS = re.compile(
    r"#\d+\s+\/"                          # stack frame:  #0 /var/www/...
    r"|production\.\w+:"                   # monolog:      production.ERROR:
    r"|local\.\w+:"                        # monolog:      local.DEBUG:
    r"|stack trace\s*:"                    # stack trace header
    r"|SQLSTATE\["                         # SQL exception
    r"|vendor\\?/laravel\\?/framework"     # Laravel source path in trace
    r"|Next Illuminate\\"                  # chained exception
    r"|APP_KEY="                           # env dump
    r'|"exception":"'                      # JSON exception
    r"|\[(?:2\d{3})-\d{2}-\d{2}"           # log timestamp  [2026-06-15 ...
    r"|\.ERROR\s*:"                        # Monolog level
    r"|\.CRITICAL\s*:"                     # Monolog level
    r"|\.ALERT\s*:"                        # Monolog level
    r"|\.EMERGENCY\s*:"                    # Monolog level
    r"|array\s*\(\s*"                      # PHP var dump start
    r"|object\(Illuminate\\"               # PHP object dump
    r"|#\d+\s+\{main\}"                    # stack frame main
    r"|thrown in /"                        # thrown in /path
    r"|Next exception"                     # chained exception
    ,
    re.IGNORECASE,
)

_MEDIUM_LOG_PATTERNS = re.compile(
    r"exception"
    r"|\.\w+Exception"
    r"|QueryException"
    r"|PDOException"
    r"|ErrorException"
    r"|FatalError"
    r"|whoops"
    r"|debug_backtrace"
    r"|array\(\s*\)"
)


def _is_actual_log(path: str, raw_text: str, size: int) -> bool:
    """
    Multi-layer heuristic to decide if content is a real Laravel log.

    Returns True only when we're confident the content is a log file
    with stack traces, error dumps, SQL queries, or environment leaks.
    """
    text = raw_text.lower()

    # ── Layer 1: Strong patterns — single match is enough ──
    if _STRONG_LOG_PATTERNS.search(text):
        return True

    # ── Layer 2: Path-based for .log files with content ──
    is_log_path = (
        path.endswith(".log")
        or path.endswith(".txt")
        or "storage/logs" in path
    )
    if is_log_path and size > 100:
        # Check for medium-strength patterns
        medium_matches = len(_MEDIUM_LOG_PATTERNS.findall(text))
        if medium_matches >= 3:
            return True
        # Check line count — real logs have many lines
        lines = raw_text.count("\n")
        if lines >= 20 and medium_matches >= 1:
            return True

    # ── Layer 3: Very large files with error-like content ──
    if size > 50000 and ("error" in text or "exception" in text):
        return True

    return False


# ──────────────────────────────────────────────────────────

def _check_path(session, base: str, path: str, timeout: int):
    """
    Probe a single path.

    Returns (path, status, size_hr, snippet, is_log, content_type) or None.
    """
    url = base + path
    resp = request_url(session, url, timeout=timeout)
    if resp is None:
        return None

    status = resp.status_code
    size   = len(resp.content)
    content_type = resp.headers.get("Content-Type", "").lower()

    if status in (200, 301, 302, 307, 308) and size > 0:
        text = resp.text if size < 10000 else resp.text[:10000]
        snippet = text[:300].replace("\n", " ").strip()

        is_log = _is_actual_log(path, text, size)
        size_hr = _fmt_size(size)

        return (path, status, size_hr, snippet, is_log, content_type)

    return None


def _fmt_size(bytes_: int) -> str:
    if bytes_ < 1024:
        return f"{bytes_} B"
    elif bytes_ < 1024 ** 2:
        return f"{bytes_/1024:.1f} KB"
    return f"{bytes_/1024**2:.1f} MB"


def discover(session, base_url: str, threads: int, timeout: int,
             show_terminal: bool):
    """
    Enumerate all known paths concurrently.

    Returns (findings, total_scanned)
      findings      — list of (path, status, size_hr, snippet, is_log, content_type)
      total_scanned — int, how many paths were probed
    """
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    term.print(f"\n{Fore.CYAN}═══ PHASE 2 : PATH & LOG DISCOVERY ═══{Style.RESET_ALL}\n")

    paths = build_path_list()
    total = len(paths)
    term.print(f"  {INFO} Enumerating {BRIGHT}{total}{Style.RESET_ALL} known log / config paths ...\n")

    findings = []
    completed = 0
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        fut_map = {pool.submit(_check_path, session, base, p, timeout): p for p in paths}
        for future in concurrent.futures.as_completed(fut_map):
            completed += 1
            result = future.result()
            if result:
                findings.append(result)
                path_found, status, size_hr, snippet, is_log, ctype = result
                full_url = base + path_found
                risk = risk_of(path_found, is_log)

                log_tag = (
                    f"{Fore.RED}[LOG]{Style.RESET_ALL}" if is_log
                    else f"{Fore.YELLOW}[FILE]{Style.RESET_ALL}"
                )
                risk_tag = f"{RISK_COLORS.get(risk, Fore.WHITE)}[{risk}]{Style.RESET_ALL}"

                # Show a preview of the content in verbose mode
                extra = ""
                if is_log:
                    extra = f"\n         {Fore.LIGHTBLACK_EX}{snippet[:200]}{Style.RESET_ALL}"

                line = (
                    f"  {FOUND} {risk_tag} {log_tag} "
                    f"{BRIGHT}{full_url}{Style.RESET_ALL}  [{status}]  {size_hr}"
                    f"{extra}"
                )
                if show_terminal:
                    term.print(line)

            # Progress update every 25 paths
            if completed % 25 == 0 or completed == total:
                pct = int(completed / total * 100)
                elapsed = time.time() - start_time
                prog = (
                    f"  {INFO} Progress: {completed}/{total} ({pct}%)  "
                    f"|  Elapsed: {elapsed:.1f}s  |  Found: {len(findings)}"
                )
                term.progress(prog)

    term.done()
    term.print(
        f"\n  {INFO} Scan complete — {BRIGHT}{total}{Style.RESET_ALL} paths scanned, "
        f"{BRIGHT}{len(findings)}{Style.RESET_ALL} accessible.\n"
    )
    return findings, total
