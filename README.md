<div align="center">

# ╔═════════════════════════════════╗
# ║     LARAVEL LOGS EXPOSER        ║
# ║     Red Team Edition            ║
# ╚═════════════════════════════════╝

**Fingerprint · Locate · Exfiltrate exposed Laravel artifacts.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Authorized%20Testing%20Only-red)](LICENSE)
**Developed by [Dutchman Security](https://github.com/dutchman-security)**  
*Idea by overthrash1337*

---

</div>

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Command Reference](#-command-reference)
  - [Single Target](#single-target)
  - [Batch Mode](#batch-mode)
  - [Proxy Support](#proxy-support)
  - [Performance Tuning](#performance-tuning)
- [Output & Reports](#-output--reports)
- [Detection Methodology](#-detection-methodology)
- [Risk Classification](#-risk-classification)
- [Full Command Examples](#-full-command-examples)
- [PDF Documentation](#-pdf-documentation)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 🔍 Overview

**Laravel Logs Exposer** is a professional red-team tool that systematically identifies exposed log files, configuration dumps, and sensitive artifacts from Laravel-based web applications.

It uses a **three-phase approach**:

| Phase | Description |
|-------|-------------|
| **1. Fingerprinting** | Confirms the target runs Laravel via cookies, headers, endpoints, and body signatures |
| **2. Path Discovery** | Probes 635+ known Laravel artifact paths concurrently using multi-threading |
| **3. Risk Analysis** | Categorises findings by severity (CRITICAL → LOW) and exports detailed JSON reports |

---

## ✨ Features

- ✅ **Laravel Detection** — 25+ fingerprint indicators with weighted confidence scoring
- ✅ **635+ Probe Paths** — Storage logs, .env files, bootstrap cache, Telescope, Horizon, Debugbar, git leaks, artisan, composer, routes
- ✅ **Smart Log Detection** — Regex-based engine distinguishes real log files (stack traces, SQL errors, env dumps) from false positives
- ✅ **Multi-Threaded** — Concurrent path scanning with configurable thread count
- ✅ **Single & Batch Mode** — Scan one target or hundreds from a `.txt` file
- ✅ **SOCKS/HTTP Proxy Support** — Route all traffic through proxies for stealth
- ✅ **JSON Export** — Full A-to-Z reports with findings, snippets, risk levels, and metadata
- ✅ **Auto-Store** — Results saved to `./output/<domain>/<timestamp>/report.json`
- ✅ **Real-Time Terminal Output** — Watch findings appear as they're discovered
- ✅ **Dated Log Scanning** — Auto-generates paths for the last 30 days in multiple formats
- ✅ **Professional PDF Documentation** — 8-page guide included

---

## 💻 Installation

```bash
# 1. Clone the repository
git clone https://github.com/dutchman-security/lara-scanner.git
cd lara-scanner

# 2. Install dependencies
pip install -r requirements.txt
```

### Requirements

```
requests>=2.31.0
requests[socks]>=2.31.0
colorama>=0.4.6
urllib3>=2.0.0
fpdf2>=2.7.0
```

> **Note:** `fpdf2` is only needed if you regenerate the PDF documentation.  
> `requests[socks]` is only needed if you use the `--proxy` flag with SOCKS proxies.

---

## 🚀 Quick Start

```bash
# Basic scan (terminal output)
python3 logs-fucker.py -host https://target.com

# Scan and save results
python3 logs-fucker.py -host https://target.com -store

# Full control
python3 logs-fucker.py -host https://target.com -store -terminal -t 30 -v
```

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/dutchman-security/lara-scanner)

Click the button above to open this tool directly in **Google Cloud Shell** — no local setup required.

---

## 📖 Command Reference

### Single Target

```bash
# Basic scan — shows findings in terminal
python3 logs-fucker.py -host https://example.com

# Explicit terminal mode
python3 logs-fucker.py -host https://example.com -terminal

# Save to auto-structured directory
python3 logs-fucker.py -host https://example.com -store

# Save to custom directory
python3 logs-fucker.py -host https://example.com -store ./campaign_results

# Save report to a specific file
python3 logs-fucker.py -host https://example.com -o report.json

# Both store and file output
python3 logs-fucker.py -host https://example.com -store -o report.json

# Verbose mode (show content snippets)
python3 logs-fucker.py -host https://example.com -v
```

### Batch Mode

Create a text file with one URL per line:

```text
# targets.txt
https://target1.com
https://target2.com
# comments and blank lines are ignored
https://target3.com
```

Then run:

```bash
# Silent batch — saves results only
python3 logs-fucker.py -batch targets.txt -store

# Batch with live terminal output
python3 logs-fucker.py -batch targets.txt -store -terminal

# Batch with proxy
python3 logs-fucker.py -batch targets.txt -store --proxy socks5://127.0.0.1:9050

# Batch with performance tuning
python3 logs-fucker.py -batch targets.txt -store -t 30 --timeout 5
```

### Proxy Support

Route all traffic through HTTP or SOCKS proxies:

```bash
# SOCKS5 proxy (Tor, etc.)
python3 logs-fucker.py -host https://example.com --proxy socks5://127.0.0.1:9050

# HTTP proxy
python3 logs-fucker.py -host https://example.com --proxy http://proxy.corp:8080

# SOCKS4 proxy
python3 logs-fucker.py -host https://example.com --proxy socks4://localhost:1080

# Batch with proxy
python3 logs-fucker.py -batch targets.txt -store --proxy socks5://127.0.0.1:9050
```

Supported schemes: `http`, `https`, `socks4`, `socks5`, `socks5h`.

### Performance Tuning

```bash
# Faster scan — more threads, shorter timeout
python3 logs-fucker.py -host https://example.com -t 50 --timeout 3

# Stealthy scan — fewer threads, longer timeout
python3 logs-fucker.py -host https://example.com -t 5 --timeout 15

# Batch performance
python3 logs-fucker.py -batch targets.txt -store -t 30 --timeout 5
```

### Flag Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-host URL` | Single target URL | *required* |
| `-batch FILE` | Batch file with one URL per line | *required* |
| `-terminal` | Show findings in terminal in real-time | off |
| `-store [DIR]` | Auto-save to `./<DIR>/<domain>/<ts>/report.json` | off |
| `-o FILE` | Save single-target report to a specific JSON file | off |
| `-t N` | Concurrent threads per target | `15` |
| `--timeout N` | Request timeout in seconds | `10` |
| `--proxy URL` | Proxy for all requests | off |
| `-v` | Show response content snippets | off |
| `--no-color` | Disable coloured terminal output | off |
| `-h` | Show help message | — |

> **Note:** `-host` and `-batch` are **mutually exclusive** — use one or the other.  
> `-o` is ignored in batch mode (use `-store` instead).

---

## 📊 Output & Reports

When using `-store`, results are organised automatically:

```
./output/
├── example.com/
│   └── 20260615_143022/
│       └── report.json
├── target2.com/
│   └── 20260615_143105/
│       └── report.json
└── target3.com/
    └── 20260615_143148/
        └── report.json
```

### JSON Report Structure

```json
{
  "tool": "Laravel Logs Exposer",
  "version": "2.2",
  "target": "https://example.com",
  "scan_timestamp": "2026-06-15T14:30:22Z",
  "is_laravel": true,
  "laravel_confidence": 8,
  "laravel_indicators": [
    {"type": "header", "description": "Set-Cookie contains 'laravel'"},
    {"type": "path", "description": "Sanctum CSRF endpoint exists [204]"}
  ],
  "paths_scanned": 635,
  "elapsed_seconds": 37.8,
  "summary": {
    "total_findings": 5,
    "real_log_files": 2,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  },
  "findings": [
    {
      "path": "/storage/logs/laravel.log",
      "url": "https://example.com/storage/logs/laravel.log",
      "status": 200,
      "size_hr": "1.2 MB",
      "is_log": true,
      "content_type": "text/plain",
      "risk": "CRITICAL",
      "snippet": "[2026-06-15 10:30:00] production.ERROR: SQLSTATE[HY000]..."
    }
  ]
}
```

---

## 🧠 Detection Methodology

### Phase 1 — Fingerprinting

The tool probes for **25+ Laravel indicators**:

| Category | Indicators |
|----------|-----------|
| 🍪 Cookies | `laravel_session`, `laravel_token`, `xf_session` |
| 📋 Headers | `X-Powered-By`, `Set-Cookie`, `Server` |
| 🔗 Endpoints | `/sanctum/csrf-cookie`, `/_debugbar/open`, `/telescope/health-check`, `/api/user`, `/artisan` |
| 📝 Body Text | `csrf-token`, `livewire`, `Laravel v`, `Whoops!`, `Stack trace`, `Telescope` |

Each indicator scores points. A **score of 4+** confirms Laravel.

### Phase 2 — Path Discovery

**635 paths** are probed concurrently across these categories:

| Category | Examples |
|----------|----------|
| 📄 Storage Logs | `laravel.log`, `lumen.log`, `development.log`, `production.log`, `error.log`, `debug.log`, `query.log`, `sql.log`, `horizon.log`, `telescope.log`, `octane.log` |
| 📅 Dated Logs | `laravel-2026-06-15.log`, `daily-2026-06-15.log`, `error-2026-06-15.log` (30 days back) |
| 🔐 JSON Logs | `laravel.json`, `laravel.ndjson`, `development.json` |
| 📦 Compressed | `laravel.log.gz`, `lumen.log.gz` |
| ⚙️ Environment | `.env`, `.env.backup`, `.env.production`, `.env.local` |
| 🗃️ Bootstrap Cache | `config.php`, `packages.php`, `services.php`, `routes-v7.php` |
| 🔬 Debug Tools | Telescope, Horizon, Debugbar, Ignition endpoints |
| 🕵️ Source Leaks | `.git/config`, `composer.json`, `artisan`, `routes/web.php` |
| 📁 Alternate Roots | `/laravel/`, `/backend/`, `/api/`, `/app/`, `/src/`, `/public/`, `/current/` |

### Log Detection (Strict Mode)

Content is flagged as a **real log file** only when it contains:

- **Stack trace frames** — `#0 /var/www/...`, `#1 /vendor/laravel/...`
- **Monolog channels** — `production.ERROR:`, `local.DEBUG:`, `production.CRITICAL:`
- **SQL errors** — `SQLSTATE[HY000]`, `SQLSTATE[42S02]`
- **Environment leaks** — `APP_KEY=`, `DB_HOST=`, `DB_PASSWORD=`
- **PHP dumps** — `array(`, `object(Illuminate\)`
- **Exception chains** — `Next exception`, `thrown in /path`
- **Log timestamps** — `[2026-06-15 10:30:00]`

### Phase 3 — Risk Analysis

Each finding is tagged with a risk level:

| Risk | Criteria |
|------|----------|
| 🔴 **CRITICAL** | `.env` files, `storage/logs` with real log content, `.git` leaks |
| 🟠 **HIGH** | Log files outside storage, Telescope, Horizon, Debugbar, bootstrap cache |
| 🟡 **MEDIUM** | Composer files, artisan, routes, vendor exposures |
| ⚪ **LOW** | Other accessible files without sensitive content |

---

## 📚 Full Command Examples

```bash
# ── BASIC ──

# Default terminal output
python3 logs-fucker.py -host https://example.com

# ── OUTPUT ──

# Show findings in terminal
python3 logs-fucker.py -host https://example.com -terminal

# Save to structured directory
python3 logs-fucker.py -host https://example.com -store

# Save to custom directory
python3 logs-fucker.py -host https://example.com -store ./campaign

# Save to specific file
python3 logs-fucker.py -host https://example.com -o report.json

# Both store + file
python3 logs-fucker.py -host https://example.com -store -o report.json

# ── PROXY ──

# Via SOCKS5 (Tor)
python3 logs-fucker.py -host https://example.com --proxy socks5://127.0.0.1:9050

# Via HTTP proxy
python3 logs-fucker.py -host https://example.com --proxy http://gateway:8080

# Store + proxy
python3 logs-fucker.py -host https://example.com -store --proxy socks5://127.0.0.1:9050

# ── PERFORMANCE ──

# Fast scan (50 threads, 3s timeout)
python3 logs-fucker.py -host https://example.com -t 50 --timeout 3

# Stealth scan (5 threads, 15s timeout)
python3 logs-fucker.py -host https://example.com -t 5 --timeout 15

# Full power
python3 logs-fucker.py -host https://example.com -t 30 --timeout 5 -v

# ── VERBOSE ──

# Show content snippets
python3 logs-fucker.py -host https://example.com -v

# Verbose + store + all options
python3 logs-fucker.py -host https://example.com -store -o report.json -t 30 -v --proxy socks5://127.0.0.1:9050

# ── BATCH ──

# Silent batch
python3 logs-fucker.py -batch targets.txt -store

# Batch with terminal
python3 logs-fucker.py -batch targets.txt -store -terminal

# Batch with proxy
python3 logs-fucker.py -batch targets.txt -store --proxy socks5://127.0.0.1:9050

# Batch full
python3 logs-fucker.py -batch targets.txt -store -terminal -t 30 --timeout 5 --proxy socks5://127.0.0.1:9050

# ── HELP ──

python3 logs-fucker.py --help
```

---

## 📄 PDF Documentation

An **8-page professional PDF** is included in the repository:

```
Laravel_Logs_Exposer_Documentation.pdf
```

It covers installation, all flag references, 7+ usage examples, report format specifications, detection methodology, and legal guidance.

---

## ⚖️ Legal Disclaimer

```
This tool is provided for authorised security assessments only.
You must have explicit written permission from the target owner
before using this tool. Unauthorised use may violate computer
fraud and abuse laws in your jurisdiction.

The authors and contributors assume no liability for misuse.
```

**Developed by [Dutchman Security](https://github.com/dutchman-security)**  
*Idea by overthrash1337*

---

<div align="center">

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/dutchman-security/lara-scanner)

**For Authorized Testing Only**  
© 2026 Dutchman Security

</div>
