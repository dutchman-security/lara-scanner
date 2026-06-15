#!/usr/bin/env python3
"""
Laravel Exposed Log Hunter - Red Team Edition
Fingerprint, Locate, Exfiltrate exposed Laravel artifacts.
"""

__author__  = "Dutchman Security"
__credits__ = "Idea by overthrash1337"
__version__ = "2.2"
__license__ = "For Authorized Testing Only"

import argparse
import os
import sys
import time

from colorama import Fore, Style

from core.session import make_session
from core.terminal import term, INFO, WARN, OK, ERR, FOUND, BRIGHT
from core.fingerprint import fingerprint
from core.scanner import discover
from core.analysis import analyze
from core.export.exporter import build_report, export_to_file, store_auto


# ── Banner ──
BANNER = f"""{Fore.RED}
██╗      █████╗ ██████╗  █████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██║     ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║     ███████║██████╔╝███████║███████╗██║     ███████║██╔██╗ ██║
██║     ██╔══██║██╔══██╗██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║
███████╗██║  ██║██║  ██║██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

{Fore.YELLOW}              Laravel Logs Exposer
{Fore.YELLOW}              Red Team Edition  v{__version__}

{Style.BRIGHT}{Fore.CYAN}              by Dutchman Security{Style.RESET_ALL}
"""

# ──────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────

def read_urls_from_file(path: str) -> list:
    """Read a text file, return non-empty, non-comment lines as URLs."""
    if not os.path.isfile(path):
        term.print(f"{ERR} File not found: {BRIGHT}{path}{Style.RESET_ALL}")
        sys.exit(1)
    urls = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("#", ";", "//")):
                continue
            if not line.startswith(("http://", "https://")):
                term.print(f"{WARN} Skipping invalid URL (no scheme): {BRIGHT}{line}{Style.RESET_ALL}")
                continue
            urls.append(line.rstrip("/"))
    if not urls:
        term.print(f"{ERR} No valid URLs found in {BRIGHT}{path}{Style.RESET_ALL}")
        sys.exit(1)
    return urls


def scan_target(target: str, session, args, show_terminal: bool,
                batch_index: int = None, batch_total: int = None):
    """
    Run all 3 phases against a single target URL.
    Returns (report_dict, total_findings) or (None, 0) on failure.
    """
    prefix = ""
    if batch_index is not None:
        prefix = f"{Fore.CYAN}[{batch_index}/{batch_total}]{Style.RESET_ALL} "

    # ── Phase 1: Fingerprint ──
    term.print(f"\n{prefix}{Fore.CYAN}═══ TARGET: {BRIGHT}{target}{Style.RESET_ALL} ═══{Style.RESET_ALL}\n")
    fp = fingerprint(session, target)
    start_time = time.time()

    # ── Phase 2: Discover ──
    findings, total_scanned = discover(
        session, target, args.threads, args.timeout, show_terminal
    )
    end_time = time.time()
    elapsed = end_time - start_time

    # ── Phase 3: Analyze ──
    categorized = analyze(findings, elapsed, total_scanned,
                          fp.is_laravel, fp.confidence, target)

    # ── Build report ──
    report = build_report(
        target_url=target,
        is_laravel=fp.is_laravel,
        laravel_confidence=fp.confidence,
        laravel_indicators=fp.indicators,
        scanned_paths=total_scanned,
        findings=findings,
        categorized=categorized,
        start_time=start_time,
        end_time=end_time,
    )
    return report, len(findings)


# ──────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="logs-fucker.py",
        description="Laravel Exposed Log Hunter — Red Team Edition",
        epilog=(
            "Examples:\n"
            "  Single target:\n"
            "    python3 logs-fucker.py -host https://target.com\n"
            "    python3 logs-fucker.py -host https://target.com -store -o report.json\n"
            "    python3 logs-fucker.py -host https://target.com --proxy socks5://127.0.0.1:9050\n"
            "\n"
            "  Batch mode (targets in a .txt file, one per line):\n"
            "    python3 logs-fucker.py -batch targets.txt -store\n"
            "    python3 logs-fucker.py -batch targets.txt -store -terminal -t 20\n"
            "    python3 logs-fucker.py -batch targets.txt -store --proxy socks5://127.0.0.1:9050\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target group: either -host OR -batch
    target_group = p.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-host", "--host",
                              help="Single target URL (e.g. https://example.com)")
    target_group.add_argument("-batch", "--batch", metavar="FILE",
                              help="Path to .txt file with one target URL per line")

    # Output flags
    p.add_argument("-terminal", "--terminal", action="store_true",
                   help="Display discovered paths live in terminal")
    p.add_argument("-store", "--store", nargs="?", const="output", default=None,
                   metavar="DIR",
                   help="Auto-save reports to ./<DIR>/<domain>/<timestamp>/report.json")
    p.add_argument("-o", "--output", default=None, metavar="FILE",
                   help="Save single-target report to a specific JSON file (not used in -batch mode)")

    # Performance
    p.add_argument("-t", "--threads", type=int, default=15,
                   help="Concurrent threads per target (default: 15)")
    p.add_argument("--timeout", type=int, default=10,
                   help="Request timeout in seconds (default: 10)")

    # Proxy
    p.add_argument("--proxy", "--proxy", default=None, metavar="URL",
                   help="Proxy for all requests (http, socks4, socks5). "
                        "Example: socks5://127.0.0.1:9050")

    # Extra
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show response snippets")
    p.add_argument("--no-color", action="store_true",
                   help="Disable colored output")

    return p.parse_args()


# ──────────────────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # Handle --no-color
    if args.no_color:
        from colorama import init as cinit
        cinit(strip=True)

    # Determine display mode
    show_terminal = args.terminal
    if not args.terminal and not args.store and not args.output:
        show_terminal = True  # default to terminal display

    # Print banner
    term.print(BANNER)
    term.print(f"{INFO} Threads     : {BRIGHT}{args.threads}{Style.RESET_ALL}")
    term.print(f"{INFO} Timeout     : {BRIGHT}{args.timeout}s{Style.RESET_ALL}")
    if args.proxy:
        term.print(f"{INFO} Proxy       : {BRIGHT}{args.proxy}{Style.RESET_ALL}")

    modes = []
    if show_terminal:
        modes.append("terminal")
    if args.store:
        modes.append(f"store→{args.store}")
    if args.output:
        modes.append(f"output→{args.output}")
    term.print(f"{INFO} Output mode : {BRIGHT}{', '.join(modes) or 'terminal'}{Style.RESET_ALL}")
    term.print(f"{'─' * 60}{Style.RESET_ALL}\n")

    # ── Build one session (reused across targets in batch) ──
    session = make_session(timeout=args.timeout, proxy_url=args.proxy)

    # ──────────────────────────────────────────────────────
    #  SINGLE-TARGET MODE
    # ──────────────────────────────────────────────────────
    if args.host:
        target = args.host.rstrip("/")
        if not target.startswith(("http://", "https://")):
            term.print(f"{ERR} URL must start with http:// or https://")
            sys.exit(1)

        report, count = scan_target(target, session, args, show_terminal)

        # Export
        if args.output:
            export_to_file(args.output, report)
        if args.store:
            store_auto(report, base_dir=args.store)

    # ──────────────────────────────────────────────────────
    #  BATCH MODE
    # ──────────────────────────────────────────────────────
    else:
        urls = read_urls_from_file(args.batch)
        total = len(urls)
        term.print(f"{INFO} Batch mode — {BRIGHT}{total}{Style.RESET_ALL} targets loaded from "
                   f"{BRIGHT}{args.batch}{Style.RESET_ALL}\n")

        if args.output:
            term.print(f"{WARN} -output is ignored in batch mode. Use -store instead.\n")

        all_reports = []
        total_findings_all = 0
        batch_start = time.time()

        for idx, target in enumerate(urls, 1):
            report, count = scan_target(
                target, session, args, show_terminal,
                batch_index=idx, batch_total=total,
            )
            if report:
                all_reports.append(report)
                total_findings_all += count

                # Save immediately per target
                if args.store:
                    store_auto(report, base_dir=args.store)

                # Separate targets with a blank line
                if idx < total:
                    term.print(f"\n  {'─' * 60}\n")

        # ── Batch summary ──
        batch_elapsed = time.time() - batch_start
        term.print(f"\n{Fore.CYAN}═══ BATCH COMPLETE ═══{Style.RESET_ALL}\n")
        term.print(f"  {INFO} Targets scanned : {BRIGHT}{total}{Style.RESET_ALL}")
        term.print(f"  {INFO} Total findings  : {BRIGHT}{total_findings_all}{Style.RESET_ALL}")
        term.print(f"  {INFO} Time elapsed    : {BRIGHT}{batch_elapsed:.1f}s{Style.RESET_ALL}")
        term.print()

        # Print per-target quick recap
        if show_terminal:
            term.print(f"  {INFO} Per-target recap:")
            for r in all_reports:
                s = r["summary"]
                log_files = s.get("real_log_files", 0)
                line = f"    {BRIGHT}{r['target']}{Style.RESET_ALL}  →  {s['total_findings']} findings"
                if log_files:
                    line += f"  ({Fore.RED}{log_files} logs{Style.RESET_ALL})"
                term.print(line)
            term.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        term.done()
        term.print(f"\n{ERR} Interrupted by user. Exiting.")
        sys.exit(130)
