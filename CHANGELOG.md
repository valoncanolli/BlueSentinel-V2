# Changelog

All notable changes to BlueSentinel are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [2.1.0] — 2026-03-29

### Added
- **Dashboard scan controls** — Quick/File/Network/Full scan buttons with live progress
- **Scan progress bar** — Real-time updates: module name, file being scanned, overall %
- **Reports page** (`/reports-page`) — Table of all saved reports with metadata
- **Report metadata** — JSON sidecar file saved alongside each HTML report
- **Threat Notification System** — Real-time slide-in drawer with breach verdict
- **1-click Kill Process** — Terminate suspicious process by PID (psutil)
- **1-click Blacklist IP** — Add IP to local IOC database
- **1-click Block Firewall** — Windows Firewall inbound + outbound rules (netsh)
- **IP Intelligence modal** — Geolocation, ASN, abuse score, Google Maps link
- **Demo Mode** — Load/clear realistic threat dataset for dashboard testing
- **Clear Demo button** — Removes demo data and reloads dashboard
- `core/progress.py` — Windows-safe CLI progress bars (`\r` approach, no ANSI cursor-up)
- `core/file_cache.py` — SHA-256 hash cache (no TTL, hash-based validity only)
- `core/notifications.py` — ThreatNotification dataclass
- `core/logger.py` — Structured JSON daily logs with 7-day auto-retention
- `intelligence/news_client.py` — Parallel RSS cybersecurity news feed
- `demo/generate_demo_data.py` — Realistic threat dataset generator
- `config/ip_blacklist.json` — Persistent IP blacklist
- HTTPS support — auto-generated self-signed certificate (cryptography package)
- Rate limiting — flask-limiter on sensitive API endpoints
- Process whitelist — system-critical processes cannot be killed

### Fixed
- `/files` page Internal Server Error (500) after demo data load
- `load-demo-data` now stores result in `app.config` (not just Socket.IO)
- QuickScan now limited to 5 minutes with path restriction (no System32)
- FileOnly limited to 10 minutes
- Scan mode `continue` statement — non-applicable modules now truly skipped
- Progress bar no longer scrolls in PowerShell (`\r` in-place update)
- Progress starts at correct % (pre-skip counted before loop)
- Text collision (`"etaPHASE"`) fixed with pause/resume approach
- CPU/RAM dashboard gauges now animate correctly (was stuck at 0%)
- Export JSON now returns populated data after scan/demo load
- News ticker hover-pause (CSS `animation-play-state: paused`)
- Sparkline cards fixed to 120px height (was growing infinitely)

### Changed
- YARA scan uses `socketio.start_background_task()` (fixes eventlet compatibility)
- Parallel intelligence lookups with `ThreadPoolExecutor`
- Parallel RSS news fetch (all feeds simultaneously)
- News ticker renamed from "THREAT INTEL" to "NEWS"
- News ticker 20% faster scroll (72s animation)
- News instant load via `sessionStorage` between page navigations
- `requirements.txt` updated: added cryptography, flask-limiter, pyyaml
- `setup.py` version 2.1.0 with complete classifiers

---

## [2.0.0] — 2026-01-15

### Added
- Complete rewrite from BlueSentinel V1.0
- Flask + Socket.IO real-time dashboard
- MITRE ATT&CK v14 mapping
- Dual AI provider support (OpenAI / Anthropic)
- FFT-based beaconing detection
- VirusTotal multi-key rotation
- YARA rule engine with 20+ detection rules
- PowerShell collector modules
