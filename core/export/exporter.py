"""
JSON report builder and file writer.
Produces a complete A-to-Z report from all scan phases.
"""

import datetime
import json
import os
from urllib.parse import urlparse

from core.terminal import term, OK, ERR, BRIGHT, Style
from data.signatures import risk_of


def build_report(target_url: str, is_laravel: bool, laravel_confidence: int,
                 laravel_indicators: list, scanned_paths: int,
                 findings: list, categorized: dict,
                 start_time: float, end_time: float) -> dict:
    """Assemble the full scan report as a dict ready for JSON export."""
    elapsed = round((end_time or datetime.datetime.now().timestamp()) -
                    (start_time or datetime.datetime.now().timestamp()), 1)

    report = {
        "tool":             "Laravel Logs Exposer",
        "version":          "2.2",
        "target":           target_url,
        "scan_timestamp":   datetime.datetime.utcnow().isoformat() + "Z",
        "is_laravel":       is_laravel,
        "laravel_confidence": laravel_confidence,
        "laravel_indicators": [
            {"type": t, "description": d} for t, d in laravel_indicators
        ],
        "paths_scanned":    scanned_paths,
        "elapsed_seconds":  elapsed,
        "summary": {
            "total_findings":  len(findings),
            "real_log_files":  sum(1 for f in findings if f[4]),
            "critical": len(categorized.get("CRITICAL", [])),
            "high":     len(categorized.get("HIGH", [])),
            "medium":   len(categorized.get("MEDIUM", [])),
            "low":      len(categorized.get("LOW", [])),
            "info":     len(categorized.get("INFO", [])),
        },
        "findings": [],
    }

    parsed_url = urlparse(target_url)
    base = f"{parsed_url.scheme}://{parsed_url.netloc}"

    for entry in findings:
        path, status, size_hr, snippet, is_log, ctype = entry[:6]
        risk = risk_of(path, is_log)
        report["findings"].append({
            "path":         path,
            "url":          base + path,
            "status":       status,
            "size_hr":      size_hr,
            "is_log":       is_log,
            "content_type": ctype,
            "risk":         risk,
            "snippet":      snippet[:500],
        })

    return report


def export_to_file(filepath: str, report: dict) -> bool:
    """Write the report dict to a JSON file (creates directories as needed)."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        term.print(f"  {OK} Saved -> {BRIGHT}{filepath}{Style.RESET_ALL}")
        return True
    except Exception as e:
        term.print(f"  {ERR} Failed to write {filepath}: {e}")
        return False


def store_auto(report: dict, base_dir: str = "output") -> str:
    """
    Auto-save report to  ./<base_dir>/<domain>/<timestamp>/report.json
    Returns the path written, or None on failure.
    """
    parsed_url = urlparse(report["target"])
    domain = parsed_url.netloc.replace(":", "_")
    ts     = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dir_path = os.path.join(base_dir, domain, ts)
    filepath = os.path.join(dir_path, "report.json")
    if export_to_file(filepath, report):
        return filepath
    return None
