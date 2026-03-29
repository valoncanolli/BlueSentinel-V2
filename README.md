<div align="center">

# 🔵 BlueSentinel V2.0

**AI-Augmented Threat Detection Platform**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows)](https://github.com/valoncanolli/BlueSentinel-V2)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org)
[![AI](https://img.shields.io/badge/AI-GPT--4o%20%7C%20Claude-blueviolet)](https://openai.com)
[![Version](https://img.shields.io/badge/Version-2.1.0-00d4ff)](https://github.com/valoncanolli/BlueSentinel-V2)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](https://github.com/valoncanolli/BlueSentinel-V2)

Built for SOC analysts, Blue Teams, and security engineers who need a fast,
powerful, open-source threat detection platform for Windows environments.

[Features](#features) • [Quick Start](#quick-start) • [Scan Modes](#scan-modes) • [Dashboard](#dashboard) • [Demo Mode](#demo-mode)

</div>

---

## Features

### 🔍 Detection Engine
- **YARA Scanning** — Custom rule sets for malware families, persistence, LOLBins, ransomware
- **FFT Beaconing Detection** — Frequency-domain analysis detects C2 heartbeat patterns
- **Memory Snapshot** — Live process analysis for injection, hollowing, suspicious execution
- **Prefetch Analysis** — Windows prefetch forensics for execution history
- **Registry Monitor** — Detects new persistence entries in Run keys and services
- **IOC Matching** — Real-time matching against configurable threat intelligence feeds

### 🌐 Threat Intelligence
- **VirusTotal** — Multi-key rotation (up to 7 API keys) for file hash lookups
- **AbuseIPDB** — IP reputation scoring with abuse confidence score
- **OTX AlienVault** — Open threat exchange feed integration
- **IP Intelligence** — Geolocation + ASN + ISP via ipinfo.io (no key required)

### 🤖 AI Triage
- **Dual AI Provider** — Switch between OpenAI GPT-4o and Anthropic Claude via `.env`
- **Threat Explainer** — Natural language analysis of each finding
- **Anomaly Detection** — IsolationForest for behavioral baseline deviation
- **Executive Summary** — Auto-generated report narrative for management

### 🖥️ Real-Time Dashboard
- Live hardware monitoring (CPU/RAM/Disk with color-coded gauges)
- Socket.IO real-time scan progress with module-level and file-level updates
- MITRE ATT&CK heatmap showing technique coverage
- Threat notification drawer with 1-click response actions
- Windows Firewall integration (block/unblock IP from notification)
- IP Intelligence modal (geolocation, abuse score, Google Maps link)
- Cybersecurity news ticker (RSS: The Hacker News, BleepingComputer, CISA, Krebs)
- Reports page with full scan history table

### ⚡ One-Click Threat Response
| Action | Effect | Requires |
|---|---|---|
| **Kill Process** | Terminates suspicious process by PID | Admin (system processes) |
| **Blacklist IP** | Adds IP to local IOC database | — |
| **Block Firewall** | Windows Firewall inbound + outbound rule | **Administrator** |
| **IP Intelligence** | Full geolocation + abuse score modal | Internet |

---

## Quick Start

### Prerequisites
- Windows 10/11 (Administrator recommended)
- Python 3.11+ ([download](https://python.org/downloads))
- TShark (optional, for packet capture): included with Wireshark

### Installation

```powershell
# Clone the repository
git clone https://github.com/valoncanolli/BlueSentinel-V2.git
cd "BlueSentinel-V2"

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Copy `config/.env.example` to `.env` and fill in your API keys:

```env
# Required
AI_PROVIDER=openai          # or: anthropic
OPENAI_API_KEY=sk-proj-...
DASHBOARD_PASSWORD=YourSecurePassword

# Optional — add for enriched threat intelligence
VIRUSTOTAL_API_KEYS=key1,key2,key3
ABUSEIPDB_API_KEY=...
OTX_API_KEY=...
ANTHROPIC_API_KEY=sk-ant-...

# Optional — for broader cybersecurity news coverage
NEWS_API_KEY=...            # https://newsapi.org/register (free tier)
```

---

## Scan Modes

| Mode | Command | Max Duration | Paths Scanned | Modules Run |
|---|---|---|---|---|
| **Full Scan** | `-FullScan` | No limit | All configured paths | All 20 |
| **Quick Scan** | `-QuickScan` | **5 minutes** | Temp, AppData, Downloads, Desktop | 7 |
| **File Only** | `-FileOnly` | **10 minutes** | Configurable | 7 |
| **Network Only** | `-NetworkOnly` | **2 minutes** | Network interfaces | 9 |

```powershell
# Run from Administrator PowerShell:
.\main_launcher.ps1 -QuickScan      # Fast scan of high-risk locations
.\main_launcher.ps1 -FileOnly       # Deep file scan only
.\main_launcher.ps1 -NetworkOnly    # Network connections only
.\main_launcher.ps1 -FullScan       # Complete scan

# Start dashboard only
.\main_launcher.ps1 -Dashboard
```

---

## Dashboard

Start the web dashboard:

```powershell
.\main_launcher.ps1 -Dashboard
# Open: http://localhost:5000
```

Or with HTTPS (auto-generates self-signed certificate):

```powershell
python dashboard/app.py
# Open: https://localhost:5000
```

### Dashboard Pages

| Page | Path | Description |
|---|---|---|
| Overview | `/` | Risk gauge, scan controls, MITRE heatmap, hardware summary |
| Alerts | `/alerts` | All threat findings with MITRE mapping and severity |
| Network | `/network` | Live connections, beaconing chart, suspicious IPs |
| Hardware | `/hardware` | CPU/RAM gauges, disk I/O, network interfaces |
| Files & YARA | `/files` | File scan results, YARA matches, prefetch anomalies |
| MITRE ATT&CK | `/mitre` | Technique coverage heatmap |
| Intelligence | `/intelligence` | VT/AbuseIPDB results, IOC matches |
| Reports | `/reports-page` | All saved reports with metadata |
| Settings | `/settings` | Configuration and preferences |

---

## Demo Mode

Test all dashboard features without running a real scan:

```powershell
# Step 1: Start dashboard
.\main_launcher.ps1 -Dashboard

# Step 2: Click "Load Demo Data" on the Overview page
# OR via API:
python -c "
import requests
r = requests.post('http://localhost:5000/api/load-demo-data',
                  auth=('admin', 'YOUR_PASSWORD'))
print(r.json())
"
```

**Demo includes:**
- 10 malicious + 5 suspicious connections (Metasploit, Cobalt Strike, Tor, DNS tunneling)
- 8 YARA matches (ransomware, RATs, PowerShell cradles, credential dumping)
- 5 registry persistence entries
- 6 event log anomalies (brute force, new admin account, scheduled task)
- Live threat notifications with 1-click kill/blacklist/firewall actions

---

## Smart File Cache

BlueSentinel uses SHA-256 hash-based caching — files are only re-scanned when
their content changes:

```
First scan:   compute hash → scan file → store result + hash
Next scan:    compute hash → compare → SKIP if unchanged
File changed: hash differs → rescan automatically
New version:  YARA rules changed → rescan all files once
```

**Typical speedup on second run: 90–99% fewer files actually scanned.**

Cache location: `cache/file_scan_cache.json`
No time-based expiry (TTL) — only hash change or version update invalidates entries.

---

## Structured Logging

All scan activity is logged to daily JSON files:

```
logs/bluesentinel_YYYY-MM-DD.log    (one file per day)
Retention: 7 days (auto-purged on startup)
Format: NDJSON — one JSON object per line
```

Query via API:
```bash
GET /api/logs/2026-03-27                              # specific date
GET /api/logs/range?start=2026-03-21&end=2026-03-27  # date range
GET /api/logs/2026-03-27?level=CRITICAL               # filter by level
GET /api/logs/dates                                   # list available dates
```

---

## Project Structure

```
BlueSentinel V2.0/
├── core/
│   ├── orchestrator.py         # Main scan pipeline coordinator
│   ├── config_manager.py       # Environment configuration
│   ├── logger.py               # Structured JSON logging (7-day retention)
│   ├── progress.py             # CLI progress bars (Windows-safe)
│   ├── file_cache.py           # SHA-256 hash-based file cache
│   ├── notifications.py        # ThreatNotification dataclass
│   └── integrity_check.py      # File integrity verification
│
├── analyzers/
│   ├── yara_engine.py          # YARA rule scanning with cache integration
│   ├── beaconing_detector.py   # FFT-based C2 beacon detection
│   ├── threat_scorer.py        # Risk score calculation (0–100)
│   ├── mitre_mapper.py         # ATT&CK technique mapping
│   ├── ioc_matcher.py          # IOC database matching
│   └── behavior_analyzer.py    # Process behavior analysis
│
├── collectors/
│   ├── py/
│   │   ├── memory_snapshot.py  # Process memory analysis
│   │   ├── prefetch_parser.py  # Windows prefetch forensics
│   │   └── hardware_monitor.py # CPU/RAM/Disk real-time stats
│   └── ps/
│       ├── network_check.ps1   # Network connections
│       ├── registry_monitor.ps1# Registry persistence
│       └── eventlog_collector.ps1
│
├── intelligence/
│   ├── virustotal_client.py    # VT API (multi-key rotation)
│   ├── abuseipdb_client.py     # AbuseIPDB IP reputation
│   ├── otx_client.py           # AlienVault OTX
│   ├── feed_aggregator.py      # Parallel threat feed aggregation
│   └── news_client.py          # Cybersecurity RSS news feed
│
├── ai_engine/
│   ├── ai_provider.py          # OpenAI/Anthropic abstraction
│   ├── threat_explainer.py     # Finding natural language explanation
│   ├── anomaly_detector.py     # IsolationForest anomaly detection
│   └── triage_assistant.py     # Automated SOC triage
│
├── reporting/
│   ├── html_report_generator.py
│   ├── pdf_exporter.py
│   ├── siem_exporter.py        # CEF format export
│   └── executive_summary.py
│
├── dashboard/
│   ├── app.py                  # Flask application + all routes
│   ├── websocket_feed.py       # Socket.IO event handlers
│   ├── templates/              # Jinja2 HTML templates
│   └── static/                 # CSS, JavaScript, fonts
│
├── demo/
│   └── generate_demo_data.py   # Realistic threat dataset generator
│
├── rules/
│   ├── yara/                   # YARA rules (malware, persistence, C2, LOLBins)
│   └── sigma/                  # Sigma detection rules
│
├── config/
│   ├── thresholds.json         # Scan configuration and limits
│   ├── mitre_mappings.json     # ATT&CK technique mappings
│   ├── ip_blacklist.json       # Persistent IP blacklist
│   └── .env.example            # Configuration template
│
├── logs/                       # Daily scan logs (7-day retention)
├── reports/                    # Generated HTML/PDF scan reports
├── cache/                      # File hash cache and temp data
│
├── main_launcher.ps1           # Windows PowerShell launcher
├── requirements.txt
├── setup.py
└── README.md
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/start-scan` | POST | Start a scan: `{"mode": "quick-scan"}` |
| `/api/scan-status` | GET | Current scan status and progress |
| `/api/scan-results` | GET | Latest scan results (JSON) |
| `/api/load-demo-data` | POST | Load demo threat dataset |
| `/api/clear-demo-data` | POST | Remove demo data |
| `/api/export/json` | GET | Export scan results as JSON |
| `/api/export/cef` | GET | Export in CEF/SIEM format |
| `/api/kill-process/<pid>` | POST | Terminate process by PID |
| `/api/blacklist-ip` | POST | Add IP to local IOC database |
| `/api/firewall-block` | POST | Block IP in Windows Firewall |
| `/api/firewall-unblock` | POST | Remove firewall block |
| `/api/ip-intel/<ip>` | GET | IP intelligence (geo + abuse score) |
| `/api/news` | GET | Cybersecurity headlines (cached 30 min) |
| `/api/reports` | GET | List all saved reports |
| `/api/reports/delete/<file>` | DELETE | Delete a report |
| `/api/logs/<date>` | GET | Query logs for date (YYYY-MM-DD) |
| `/api/logs/range` | GET | Query logs for date range |
| `/api/logs/dates` | GET | List available log dates |
| `/api/notifications` | GET | All threat notifications |

---

## Security Notes

- **Administrator required** for process termination and Windows Firewall rules
- Dashboard supports HTTPS with auto-generated self-signed certificate
- API endpoints are rate-limited (flask-limiter)
- Process kill has a whitelist — system-critical processes (lsass, csrss, etc.) are protected
- IP blocking validates against private/loopback ranges before applying rules
- All API keys stored in `.env` (never committed to git)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with 🔵 by <a href="https://github.com/valoncanolli">Valon Canolli</a>
— Cyber Security Engineer, Prishtinë, Kosovë
</div>
