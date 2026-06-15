"""
Phase 3 — Categorize findings by risk level and display a summary table.
Shows full URLs. Highlights real log files vs. other accessible artifacts.
"""

from urllib.parse import urlparse

from core.terminal import term, INFO, FOUND, BRIGHT, Fore, Style
from data.signatures import risk_of, RISK_COLORS


def analyze(findings: list, elapsed: float, scanned_paths: int,
            is_laravel: bool, laravel_confidence: int, target_url: str):
    """
    Categorize findings, print risk table, and show final summary.

    Each finding tuple: (path, status, size_hr, snippet, is_log, content_type)

    Returns categorized dict: { "CRITICAL": [...], "HIGH": [...], ... }
    """
    parsed = urlparse(target_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    term.print(f"\n{Fore.CYAN}═══ PHASE 3 : RISK ANALYSIS ═══{Style.RESET_ALL}\n")

    categorized = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}

    if not findings:
        term.print(f"  {INFO} No findings to analyze.\n")
    else:
        # Count real log files vs. other accessible files
        log_count = sum(1 for f in findings if f[4])  # is_log at index 4
        other_count = len(findings) - log_count

        if log_count:
            term.print(f"  {FOUND} {Fore.RED}{log_count} log file(s){Style.RESET_ALL} found — "
                       f"these may contain sensitive stack traces, SQL queries, and credentials.\n")

        for entry in findings:
            # Unpack: (path, status, size_hr, snippet, is_log, content_type)
            path, status, size_hr, snippet, is_log, ctype = entry
            risk = risk_of(path, is_log)
            categorized[risk].append(entry)

        # ── Print risk table with FULL URLs ──
        for risk_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = categorized[risk_level]
            if not items:
                continue
            color = RISK_COLORS[risk_level]
            term.print(f"  {color}[{risk_level}] {len(items)} finding(s):{Style.RESET_ALL}")
            for path, status, size_hr, snippet, is_log, ctype in items:
                full_url = base + path
                log_tag = f" {Fore.RED}[LOG]{Style.RESET_ALL}" if is_log else ""
                ctype_tag = f" [{ctype.split('/')[0]}]" if ctype else ""
                term.print(
                    f"    {FOUND}{log_tag} {BRIGHT}{full_url}{Style.RESET_ALL}  "
                    f"[{status}]  {size_hr}{ctype_tag}"
                )

    # ── Summary ──
    term.print(f"\n{Fore.CYAN}═══ SCAN SUMMARY ═══{Style.RESET_ALL}\n")
    term.print(f"  {INFO} Target       : {BRIGHT}{target_url}{Style.RESET_ALL}")
    laravel_status = "YES" if is_laravel else "NO / UNCERTAIN"
    term.print(f"  {INFO} Laravel      : {BRIGHT}{laravel_status}{Style.RESET_ALL}  (confidence: {laravel_confidence})")
    term.print(f"  {INFO} Paths scanned: {BRIGHT}{scanned_paths}{Style.RESET_ALL}")
    term.print(f"  {INFO} Findings     : {BRIGHT}{len(findings)}{Style.RESET_ALL}")
    log_count = sum(1 for f in findings if f[4])
    if log_count:
        term.print(f"  {INFO} Real log files: {Fore.RED}{log_count}{Style.RESET_ALL}")
    for rl in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len(categorized.get(rl, []))
        if count:
            term.print(f"    {RISK_COLORS[rl]}{rl}{Style.RESET_ALL}: {count}")
    term.print(f"  {INFO} Time elapsed : {BRIGHT}{elapsed:.1f}s{Style.RESET_ALL}")
    term.print()

    return categorized
