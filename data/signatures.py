"""
Laravel fingerprinting signatures and risk-level logic.
"""

LARAVEL_SIGNATURES = [
    # (check_type, value/pattern, weight)
    ("cookie",   "laravel_session",          3),
    ("cookie",   "laravel_token",            3),
    ("cookie",   "xf_session",               1),
    ("header",   "x-powered-by",             2),
    ("header",   "set-cookie",               2),
    ("path",     "/api/user",                2),
    ("path",     "/csrf-cookie",             2),
    ("path",     "/sanctum/csrf-cookie",     3),
    ("path",     "/_debugbar/open",          3),
    ("path",     "/telescope/health-check",  3),
    ("path",     "/ignition/health-check",   3),
    ("body",     "Laravel v",                3),
    ("body",     "laravel",                  1),
    ("body",     "csrf-token",               1),
    ("body",     "csrf_token",               1),
    ("body",     "Stack trace",              2),
    ("body",     "laravel_session",          2),
    ("body",     "Whoops! There was an error", 2),
    ("body",     "UnexpectedValueException", 1),
    ("body",     "InvalidArgumentException", 1),
    ("body",     "NotFoundHttpException",    2),
    ("body",     "MethodNotAllowedHttpException", 2),
    ("body",     "QueryException",           2),
    ("body",     "SQLSTATE",                 1),
    ("body",     "Telescope",                2),
]

# Probe paths used during fingerprinting phase
PROBE_PATHS = [
    ("/api/user",                2, "API user endpoint exists"),
    ("/csrf-cookie",             2, "CSRF cookie endpoint exists"),
    ("/sanctum/csrf-cookie",     3, "Sanctum CSRF endpoint exists"),
    ("/_debugbar/open",          3, "Debugbar endpoint exposed"),
    ("/telescope/health-check",  3, "Telescope health endpoint exposed"),
    ("/ignition/health-check",   3, "Ignition health endpoint exposed"),
    ("/artisan",                 1, "Artisan file accessible"),
    ("/.env",                    1, ".env file accessible (misconfiguration)"),
]

# Body text patterns checked on the homepage
BODY_PATTERNS = [
    ("laravel v",                  3),
    ("csrf-token",                 1),
    ("csrf_token",                 1),
    ("laravel_session",            2),
    ("telescope",                  2),
    ("horizon",                    2),
    ("livewire",                   2),
    ("alpinejs",                   1),
    ("whoops! there was an error", 2),
    ("stack trace",                2),
    ("queryexception",             2),
    ("notfoundhttpexception",      2),
]


def risk_of(path: str, is_log: bool) -> str:
    """Determine risk level for a finding path."""
    pl = path.lower()

    # ── CRITICAL ──
    # .env leaks (except the example file)
    if pl == "/.env.example":
        pass
    elif ".env" in pl:
        return "CRITICAL"
    # Storage logs
    if is_log and "storage/logs" in pl:
        return "CRITICAL"
    # Git leak
    if "/.git/" in pl:
        return "CRITICAL"

    # ── HIGH ──
    if is_log and "logs" in pl:
        return "HIGH"
    if "bootstrap/cache" in pl:
        return "HIGH"
    if "telescope" in pl:
        return "HIGH"
    if "horizon" in pl:
        return "HIGH"
    if "_debugbar" in pl:
        return "HIGH"

    # ── MEDIUM ──
    if "vendor/" in pl or "routes/" in pl:
        return "MEDIUM"
    if "composer." in pl or "artisan" in pl:
        return "MEDIUM"
    if pl.startswith("/.git"):
        return "MEDIUM"

    # ── LOW / INFO ──
    if is_log:
        return "HIGH"
    return "LOW"


RISK_COLORS = {
    "CRITICAL": "\033[1;31m",     # bold red
    "HIGH":     "\033[0;31m",     # red
    "MEDIUM":   "\033[0;33m",     # yellow
    "LOW":      "\033[2;37m",     # dim white
    "INFO":     "\033[0;36m",     # cyan
}
