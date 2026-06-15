"""
Path database — focused exclusively on:
  1. Laravel log files  (storage/logs/*.log, *.json, *.gz)
  2. Environment/config leaks  (.env, bootstrap/cache/*)
  3. Debug endpoints that leak data  (Telescope, Horizon, Debugbar)
  4. Source-code leaks  (git, artisan, composer, routes)

No health checks, no phpinfo, no generic webserver logs.
"""

import datetime

STATIC_PATHS = [
    # ────────────────────────────────────────────────────────
    #  LARAVEL LOG FILES  (primary target)
    # ────────────────────────────────────────────────────────
    "/storage/logs/laravel.log",
    "/storage/logs/lumen.log",
    "/storage/logs/development.log",
    "/storage/logs/production.log",
    "/storage/logs/error.log",
    "/storage/logs/debug.log",
    "/storage/logs/info.log",
    "/storage/logs/application.log",
    "/storage/logs/system.log",
    "/storage/logs/queue.log",
    "/storage/logs/cron.log",
    "/storage/logs/slow.log",
    "/storage/logs/query.log",
    "/storage/logs/sql.log",
    "/storage/logs/request.log",
    "/storage/logs/response.log",
    "/storage/logs/api.log",
    "/storage/logs/web.log",
    "/storage/logs/schedule.log",
    "/storage/logs/worker.log",
    "/storage/logs/horizon.log",
    "/storage/logs/telescope.log",
    "/storage/logs/octane.log",
    "/storage/logs/reverb.log",

    # JSON / structured logs  (modern Laravel)
    "/storage/logs/laravel.json",
    "/storage/logs/laravel.ndjson",
    "/storage/logs/lumen.json",
    "/storage/logs/development.json",
    "/storage/logs/production.json",

    # Compressed / rotated
    "/storage/logs/laravel.log.gz",
    "/storage/logs/lumen.log.gz",

    # Logs at alternate project roots
    "/laravel/storage/logs/laravel.log",
    "/backend/storage/logs/laravel.log",
    "/api/storage/logs/laravel.log",
    "/app/storage/logs/laravel.log",
    "/src/storage/logs/laravel.log",
    "/public/storage/logs/laravel.log",
    "/current/storage/logs/laravel.log",

    # Standalone log files at web root
    "/laravel.log",
    "/lumen.log",

    # ────────────────────────────────────────────────────────
    #  ENVIRONMENT & CONFIG LEAKS
    # ────────────────────────────────────────────────────────
    "/.env",
    "/.env.backup",
    "/.env.old",
    "/.env.production",
    "/.env.development",
    "/.env.local",
    "/.env.staging",
    "/.env.prod",
    "/.env.dev",
    "/.env.example",
    "/env",
    "/env.txt",
    "/.env.txt",

    # Bootstrap cache (compiled config, routes, services)
    "/bootstrap/cache/config.php",
    "/bootstrap/cache/packages.php",
    "/bootstrap/cache/services.php",
    "/bootstrap/cache/routes-v7.php",
    "/bootstrap/cache/compiled.php",

    # ────────────────────────────────────────────────────────
    #  ARTISAN
    # ────────────────────────────────────────────────────────
    "/artisan",
    "/artisan.php",

    # ────────────────────────────────────────────────────────
    #  DEBUG / DEV TOOLS
    # ────────────────────────────────────────────────────────
    # Debugbar
    "/_debugbar/open",
    "/_debugbar/assets/stylesheets",

    # Telescope (Laravel debug dashboard)
    "/telescope/telescope-api/entries",
    "/telescope/requests",
    "/telescope/commands",
    "/telescope/schedule",
    "/telescope/exceptions",
    "/telescope/logs",
    "/telescope/dumps",
    "/telescope/entries",
    "/telescope/monitored-tags",
    "/telescope/api/entries",

    # Horizon (queue monitoring)
    "/horizon",
    "/horizon/status",
    "/horizon/jobs",
    "/horizon/queues",
    "/horizon/failed",
    "/horizon/supervisors",
    "/horizon/workload",

    # Ignition / Flare (error pages)
    "/ignition/health-check",
    "/ignition/execute-solution",
    "/flare",

    # ────────────────────────────────────────────────────────
    #  SOURCE CODE LEAKS
    # ────────────────────────────────────────────────────────
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/HEAD",
    "/vendor/.git/config",
    "/vendor/composer/installed.json",
    "/vendor/composer/installed.php",
    "/composer.json",
    "/composer.lock",

    # Routes source
    "/routes/web.php",
    "/routes/api.php",
    "/routes/channels.php",
    "/routes/console.php",
]


def generate_dated_logs(days_back: int = 30) -> list:
    """Generate dated log-file paths for the last N days."""
    paths = []
    today = datetime.date.today()
    for d in range(days_back):
        dt = today - datetime.timedelta(days=d)
        datestr    = dt.strftime("%Y-%m-%d")
        datestr_ns = dt.strftime("%Y%m%d")
        dshort     = dt.strftime("%y%m%d")

        paths.append(f"/storage/logs/laravel-{datestr}.log")
        paths.append(f"/storage/logs/laravel-{datestr}.txt")
        paths.append(f"/storage/logs/laravel-{datestr}.json")
        paths.append(f"/storage/logs/laravel-{datestr}.ndjson")
        paths.append(f"/storage/logs/lumen-{datestr}.log")
        paths.append(f"/storage/logs/laravel-{datestr}.log.gz")
        paths.append(f"/storage/logs/laravel-{datestr_ns}.log")
        paths.append(f"/storage/logs/laravel-{dshort}.log")
        paths.append(f"/storage/logs/daily-{datestr}.log")
        paths.append(f"/storage/logs/daily.{datestr}.log")
        paths.append(f"/storage/logs/error-{datestr}.log")

        # Also check alternate storage roots
        for prefix in ("/laravel", "/backend", "/api", "/app", "/src", "/public", "/current"):
            paths.append(f"{prefix}/storage/logs/laravel-{datestr}.log")

    return paths


def build_path_list() -> list:
    """Merge static + dated paths, deduplicate, preserve order."""
    all_paths = list(STATIC_PATHS)
    all_paths += generate_dated_logs(days_back=30)
    seen = set()
    unique = []
    for p in all_paths:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique
