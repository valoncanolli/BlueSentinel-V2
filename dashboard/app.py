"""
dashboard/app.py
Flask web dashboard for BlueSentinel v2.0.
Provides real-time SOC interface with all API endpoints.
"""
import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Ensure project root is on sys.path when running dashboard/app.py directly
_project_root = str(Path(__file__).parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import psutil
from flask import Flask, render_template, jsonify, request, Response, abort, send_file
from flask_socketio import SocketIO

log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent
CACHE_DIR = BASE_DIR / "cache"
REPORTS_DIR = BASE_DIR / "reports"

# Shared state (in production use Redis)
_scan_results: Optional[Dict] = None
_alerts: list = []
_timeline: list = []

# ── Notification store (in-memory, lost on restart) ──────────────────────────
notification_store: list = []
MAX_NOTIFICATIONS = 200

# ── Explicit scan-result store for export API ─────────────────────────────────
# Set by run_scan_bg(), api_load_demo_data(), and /api/internal/store-result.
# Unlike _scan_results (which falls back to empty defaults), this is None until
# a real scan or demo load occurs — allowing api_export() to return a proper 404.
_scan_result_store: Dict = {"last_result": None, "last_updated": None}

BLACKLIST_FILE = BASE_DIR / "config" / "ip_blacklist.json"

PROTECTED_PROCESSES = {
    # Windows critical processes — NEVER kill these
    'lsass.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'smss.exe', 'svchost.exe', 'system',
    'registry', 'memory compression', 'secure system',
    'ntoskrnl.exe', 'hal.dll', 'spoolsv.exe',
    # Security tools — do not auto-kill
    'msseces.exe', 'msmpeng.exe', 'antimalware service executable',
    # BlueSentinel itself
    'python.exe', 'pythonw.exe',
}


def _load_blacklist() -> set:
    if BLACKLIST_FILE.exists():
        try:
            return set(json.loads(BLACKLIST_FILE.read_text()))
        except Exception:
            return set()
    return set()


def _save_blacklist(ips: set) -> None:
    BLACKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    BLACKLIST_FILE.write_text(json.dumps(sorted(ips), indent=2))


def _validate_ip_for_blocking(ip: str) -> Tuple[bool, str]:
    """Return (True, 'OK') if ip is safe to block; (False, reason) otherwise."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f'Invalid IP address: {ip}'
    if addr.is_private:
        return False, f'{ip} is a private IP — cannot block (would break local network)'
    if addr.is_loopback:
        return False, f'{ip} is loopback — cannot block'
    if addr.is_link_local:
        return False, f'{ip} is link-local — cannot block'
    if addr.is_multicast:
        return False, f'{ip} is multicast — cannot block'
    if addr.is_reserved:
        return False, f'{ip} is a reserved address — cannot block'
    for env_key in ['SIEM_HOST']:
        configured = os.getenv(env_key, '').strip()
        if configured and ip == configured:
            return False, f'{ip} is configured as {env_key} — cannot block'
    return True, 'OK'


def _run_module_for_dashboard(module_name: str, scan_mode: str,
                               result: dict, scan_id: str,
                               progress_emit=None) -> dict:
    """Run a single scan module and return its partial results."""
    from pathlib import Path as _Path

    try:
        thresholds = json.loads((_Path(__file__).parent.parent / "config" / "thresholds.json").read_text())
    except Exception:
        thresholds = {}
    scan_cfg = thresholds.get("scan", {})

    # ── YARA engine ──────────────────────────────────────────────────────────
    if module_name == "yara_engine":
        try:
            from analyzers.yara_engine import YaraEngine
            from core.file_cache import FileCache

            if scan_mode == "quick-scan":
                raw_paths = scan_cfg.get("quick_scan_paths",
                    ["C:\\Windows\\Temp", "C:\\Users\\%USERNAME%\\Downloads"])
                max_files = scan_cfg.get("quick_max_files", 5000)
                max_size = scan_cfg.get("quick_max_file_size_mb", 10)
            else:
                raw_paths = scan_cfg.get("file_scan_paths",
                    ["C:\\Windows\\Temp", "C:\\Users"])
                max_files = 20000
                max_size = scan_cfg.get("max_file_size_mb", 50)

            paths = [os.path.expandvars(p) for p in raw_paths]
            paths = [p for p in paths if os.path.exists(p)]

            engine = YaraEngine(rules_dir=_Path("rules/yara") if _Path("rules/yara").exists() else None)
            matches = []
            hits = misses = 0

            # Collect files
            all_files = []
            for path in paths:
                try:
                    for f in _Path(path).rglob("*"):
                        if f.is_file():
                            try:
                                if f.stat().st_size <= max_size * 1024 * 1024:
                                    all_files.append(f)
                            except Exception:
                                pass
                        if max_files and len(all_files) >= max_files:
                            break
                except Exception:
                    pass
                if max_files and len(all_files) >= max_files:
                    break

            total_files = len(all_files)

            for i, fp in enumerate(all_files):
                # Emit file progress
                if progress_emit and i % 50 == 0:
                    pct = round((i / total_files * 100)) if total_files > 0 else 100
                    progress_emit(pct, "yara_engine", f"Scanning files... {i}/{total_files}",
                                  current_file=str(fp.name))

                try:
                    file_matches = engine.scan_file(fp)
                    if file_matches:
                        matches.extend(file_matches)
                        misses += 1
                    else:
                        hits += 1
                except Exception:
                    pass

            yara_results = [{
                "rule": getattr(m, "rule_name", getattr(m, "rule", str(m))),
                "file": str(getattr(m, "file_path", getattr(m, "path", ""))),
                "severity": getattr(m, "severity", "High"),
                "matched_strings": [str(s) for s in (getattr(m, "strings", []) or [])[:3]],
                "mitre_technique": getattr(m, "mitre_technique", "T1059"),
                "mitre_tactic": getattr(m, "mitre_tactic", "Execution"),
            } for m in matches]

            result["yara_matches"] = yara_results
            result["total_files_scanned"] = total_files
            result["cache_hits"] = hits
            result["cache_misses"] = misses

            return {"summary": f"Scanned {total_files} files, {len(matches)} matches"}
        except Exception as e:
            log.warning(f"yara_engine error: {e}")
            return {"summary": f"YARA error: {str(e)[:40]}"}

    # ── Network check ────────────────────────────────────────────────────────
    elif module_name == "network_check":
        try:
            connections = []
            for conn in psutil.net_connections(kind="inet"):
                try:
                    if conn.raddr:
                        connections.append({
                            "local_addr": str(conn.laddr.ip) if conn.laddr else "",
                            "local_port": conn.laddr.port if conn.laddr else 0,
                            "remote_addr": str(conn.raddr.ip) if conn.raddr else "",
                            "remote_port": conn.raddr.port if conn.raddr else 0,
                            "status": conn.status,
                            "pid": conn.pid or 0,
                            "process_name": "",
                            "classification": "legitimate",
                            "color": "#00ff88",
                        })
                except Exception:
                    pass
            result["connections"] = connections[:100]
            return {"summary": f"Found {len(connections)} connections"}
        except Exception as e:
            return {"summary": f"Network error: {str(e)[:40]}"}

    # ── Memory snapshot ──────────────────────────────────────────────────────
    elif module_name == "memory_snapshot":
        try:
            # Use safe iteration — skip net_connections() which can segfault on some systems
            suspicious = []
            suspicious_paths = ["\\temp\\", "\\appdata\\roaming\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    info = proc.info
                    exe = (info.get('exe') or '').lower().replace('/', '\\')
                    name = (info.get('name') or '').lower()
                    if any(p in exe for p in suspicious_paths) and name not in {'python.exe', 'python3.exe'}:
                        suspicious.append({
                            'pid': info['pid'], 'name': info['name'],
                            'exe': info['exe'], 'reason': 'Runs from suspicious path',
                        })
                except Exception:
                    pass
            return {"summary": f"Found {len(suspicious)} suspicious processes"}
        except Exception as e:
            return {"summary": f"Memory snapshot: {str(e)[:40]}"}

    # ── Beaconing detector ───────────────────────────────────────────────────
    elif module_name == "beaconing_detector":
        try:
            from analyzers.beaconing_detector import BeaconingDetector
            detector = BeaconingDetector()
            beacons = detector.detect(result.get("connections", []))
            result["beaconing_alerts"] = beacons
            return {"summary": f"Found {len(beacons)} beaconing flows"}
        except Exception as e:
            return {"summary": f"Beaconing: {str(e)[:40]}"}

    # ── Threat scorer ────────────────────────────────────────────────────────
    elif module_name == "threat_scorer":
        try:
            from analyzers.threat_scorer import ThreatScorer
            from types import SimpleNamespace
            result_obj = SimpleNamespace(**result)
            score = ThreatScorer().calculate_score(result_obj)
            result["risk_score"] = score
            result["threat_score"] = score
            return {"summary": f"Risk score: {score}/100"}
        except Exception as e:
            return {"summary": f"Scorer error: {str(e)[:40]}"}

    # ── MITRE mapper ─────────────────────────────────────────────────────────
    elif module_name == "mitre_mapper":
        try:
            from analyzers.mitre_mapper import MitreMapper
            mapper = MitreMapper()
            coverage = mapper.generate_navigator_layer(result.get("alerts", []))
            result["mitre_coverage"] = coverage
            techniques = coverage.get("techniques", []) if isinstance(coverage, dict) else []
            return {"summary": f"Mapped {len(techniques)} techniques"}
        except Exception as e:
            return {"summary": f"MITRE mapper: {str(e)[:40]}"}

    # ── HTML report ──────────────────────────────────────────────────────────
    elif module_name == "html_report_generator":
        try:
            from reporting.html_report_generator import generate_html_report_from_dict
            # Ensure threat_score key is present (alias of risk_score)
            if "threat_score" not in result:
                result["threat_score"] = result.get("risk_score", 0)
            rpath = generate_html_report_from_dict(result)
            result["report_path"] = rpath
            return {"summary": f"Report saved: {_Path(rpath).name}"}
        except Exception as e:
            return {"summary": f"Report error: {str(e)[:40]}"}

    # ── IOC matcher ─────────────────────────────────────────────────────────
    elif module_name == "ioc_matcher":
        try:
            from analyzers.ioc_matcher import IOCMatcher
            matcher = IOCMatcher()
            iocs = []
            for conn in result.get("connections", []):
                ip = conn.get("remote_addr", "")
                if ip:
                    match = matcher.match(ip)
                    if match:
                        iocs.append({
                            "indicator": ip,
                            "indicator_type": "ip",
                            "threat_type": getattr(match, "threat_type", "unknown"),
                            "source": getattr(match, "source", "ioc_db"),
                            "severity": "High",
                        })
            result["ioc_matches"] = iocs
            return {"summary": f"Found {len(iocs)} IOC matches"}
        except Exception as e:
            return {"summary": f"IOC matcher: {str(e)[:40]}"}

    # ── All other modules — stub gracefully ──────────────────────────────────
    else:
        import time as _t
        _t.sleep(0.3)  # simulate brief work
        return {"summary": f"{module_name} completed"}


def _merge_module_result(main: dict, mod: dict):
    """Merge partial module result into main scan result."""
    for key, val in mod.items():
        if key == "summary":
            continue
        if isinstance(val, list) and isinstance(main.get(key), list):
            main[key].extend(val)
        elif isinstance(val, dict) and isinstance(main.get(key), dict):
            main[key].update(val)
        else:
            main[key] = val


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    try:
        from core.config_manager import get_config
        cfg = get_config()
        app.config["SECRET_KEY"] = os.urandom(32).hex()
        app.config["DASHBOARD_USERNAME"] = cfg.dashboard_username
        app.config["DASHBOARD_PASSWORD"] = cfg.dashboard_password
        app.config["DASHBOARD_PORT"] = cfg.dashboard_port
    except Exception:
        app.config["SECRET_KEY"] = "bluesentinel-dev-key"
        app.config["DASHBOARD_USERNAME"] = os.getenv("DASHBOARD_USERNAME", "admin")
        app.config["DASHBOARD_PASSWORD"] = os.getenv("DASHBOARD_PASSWORD", "changeme")
        app.config["DASHBOARD_PORT"] = int(os.getenv("DASHBOARD_PORT", "5000"))

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
    app.extensions["socketio"] = socketio

    # Start hardware monitor background thread
    try:
        from collectors.py.hardware_monitor import HardwareMonitor
        _hw_monitor = HardwareMonitor()
        _hw_monitor.start_background_thread(socketio, interval=2)
        log.info("Hardware monitor background thread started")
    except Exception as _hw_exc:
        log.warning("Hardware monitor unavailable: %s", _hw_exc)
        _hw_monitor = None
    app.extensions["hw_monitor"] = _hw_monitor

    def check_auth(username: str, password: str) -> bool:
        return (username == app.config["DASHBOARD_USERNAME"] and
                password == app.config["DASHBOARD_PASSWORD"])

    def requires_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            if not auth or not check_auth(auth.username, auth.password):
                return Response(
                    "BlueSentinel — Authentication Required",
                    401,
                    {"WWW-Authenticate": 'Basic realm="BlueSentinel v2.0"'},
                )
            return f(*args, **kwargs)
        return decorated

    def _load_latest_scan() -> Optional[Dict]:
        scan_files = sorted(CACHE_DIR.glob("scan_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if scan_files:
            try:
                with open(scan_files[0]) as fh:
                    return json.load(fh)
            except Exception:
                pass
        return None

    def store_scan_result(data: dict) -> None:
        """Persist a completed scan result for use by api_export and /api/internal/store-result."""
        _scan_result_store["last_result"] = data
        _scan_result_store["last_updated"] = datetime.now(timezone.utc).isoformat()

    def _get_scan_result() -> Dict:
        global _scan_results
        if _scan_results is None:
            _scan_results = _load_latest_scan()
        return _scan_results or {
            "scan_id": "DEMO",
            "hostname": socket.gethostname(),
            "threat_score": 0,
            "alerts": [],
            "yara_matches": [],
            "beaconing_alerts": [],
            "ioc_matches": [],
            "mitre_coverage": {},
            "ai_summary": "No scan data available. Run a scan to populate this dashboard.",
            "ai_provider_used": os.getenv("AI_PROVIDER", "openai"),
        }

    # Page routes
    @app.route("/")
    @requires_auth
    def index():
        data = _get_scan_result()
        return render_template("index.html", data=data, hostname=socket.gethostname(),
                               ai_provider=data.get("ai_provider_used", "openai").upper())

    @app.route("/alerts")
    @requires_auth
    def alerts():
        data = _get_scan_result()
        return render_template("alerts.html", data=data)

    @app.route("/network")
    @requires_auth
    def network():
        data = _get_scan_result()
        return render_template("network.html", data=data)

    @app.route("/files")
    @requires_auth
    def files():
        """Files & YARA scan results page. Safe defaults — never raises 500."""
        try:
            raw = app.config.get('LAST_SCAN_RESULT') or _get_scan_result() or {}
            if not isinstance(raw, dict):
                raw = {}

            yara_matches = (
                raw.get('yara_matches')
                or raw.get('yara_results')
                or raw.get('yara')
                or []
            )
            if not isinstance(yara_matches, list):
                yara_matches = []

            prefetch_anomalies = (
                raw.get('prefetch_findings')
                or raw.get('prefetch_anomalies')
                or raw.get('prefetch_results')
                or []
            )
            if not isinstance(prefetch_anomalies, list):
                prefetch_anomalies = []

            vt_results = (
                raw.get('vt_results')
                or raw.get('virustotal_results')
                or raw.get('threat_intel_results')
                or []
            )
            if not isinstance(vt_results, list):
                vt_results = []

            return render_template(
                'files.html',
                yara_matches=yara_matches,
                prefetch_anomalies=prefetch_anomalies,
                vt_results=vt_results,
                total_files_scanned=int(raw.get('total_files_scanned', 0)),
                cache_hits=int(raw.get('cache_hits', 0)),
                cache_misses=int(raw.get('cache_misses', 0)),
                scan_id=str(raw.get('scan_id', '')),
                hostname=str(raw.get('hostname', '')),
                risk_score=int(raw.get('risk_score', raw.get('threat_score', 0))),
                has_data=bool(yara_matches or prefetch_anomalies or vt_results),
            )
        except Exception as e:
            import traceback as _tb
            app.logger.error(f"/files route error: {_tb.format_exc()}")
            return render_template(
                'files.html',
                yara_matches=[],
                prefetch_anomalies=[],
                vt_results=[],
                total_files_scanned=0,
                cache_hits=0,
                cache_misses=0,
                scan_id='',
                hostname='',
                risk_score=0,
                has_data=False,
                error_message=f"Error loading file scan results: {str(e)}",
            )

    @app.route("/mitre")
    @requires_auth
    def mitre():
        data = _get_scan_result()
        return render_template("mitre.html", data=data)

    @app.route("/intelligence")
    @requires_auth
    def intelligence():
        return render_template("intelligence.html", data=_get_scan_result())

    @app.route("/hardware")
    @requires_auth
    def hardware():
        return render_template("hardware.html",
                               hostname=socket.gethostname(),
                               ai_provider=os.getenv("AI_PROVIDER", "openai").upper())

    @app.route("/settings")
    @requires_auth
    def settings():
        return render_template("settings.html",
                               ai_provider=os.getenv("AI_PROVIDER", "openai"),
                               openai_model=os.getenv("OPENAI_MODEL", "gpt-4o"),
                               anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5"))

    @app.route("/reports-page")
    @requires_auth
    def reports_page():
        """List all generated scan reports."""
        from pathlib import Path as _P
        reports = []
        reports_dir = _P("reports")
        if reports_dir.exists():
            for html_file in sorted(reports_dir.glob("BlueSentinel_*.html"), reverse=True):
                meta_file = html_file.with_suffix(".json")
                meta = {}
                if meta_file.exists():
                    try:
                        meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    except Exception:
                        pass

                parts = html_file.stem.split("_")
                hostname = parts[2] if len(parts) > 2 else "Unknown"
                ts_raw = parts[3] if len(parts) > 3 else ""
                try:
                    ts = datetime.strptime(ts_raw, "%Y%m%d%H%M%S")
                    ts_display = ts.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    ts_display = ts_raw or "Unknown"

                size_kb = round(html_file.stat().st_size / 1024, 1)
                yara_val = meta.get("yara_matches", 0)
                alerts_val = meta.get("total_alerts", 0)
                reports.append({
                    "filename": html_file.name,
                    "path": str(html_file),
                    "hostname": meta.get("hostname", hostname),
                    "scan_id": meta.get("scan_id", ""),
                    "scan_mode": meta.get("scan_mode", meta.get("mode", "unknown")),
                    "timestamp": meta.get("completed_at", ts_display),
                    "risk_score": meta.get("risk_score", 0),
                    "critical_count": meta.get("critical_count", 0),
                    "high_count": meta.get("high_count", 0),
                    "total_alerts": alerts_val if isinstance(alerts_val, int) else len(alerts_val),
                    "yara_matches": yara_val if isinstance(yara_val, int) else len(yara_val),
                    "size_kb": size_kb,
                    "url": f"/reports-view/{html_file.name}",
                })

        return render_template("reports.html", reports=reports, total=len(reports))

    @app.route("/reports-view/<filename>")
    @requires_auth
    def view_report(filename):
        """Serve a specific report HTML file."""
        from flask import send_from_directory
        safe_name = os.path.basename(filename)
        if not safe_name.startswith("BlueSentinel_") or not safe_name.endswith(".html"):
            return "Invalid report name", 400
        return send_from_directory(str(REPORTS_DIR), safe_name)

    @app.route("/api/reports", methods=["GET"])
    @requires_auth
    def api_reports():
        """JSON list of all reports."""
        reports = []
        if REPORTS_DIR.exists():
            for f in sorted(REPORTS_DIR.glob("BlueSentinel_*.html"), reverse=True):
                meta_f = f.with_suffix(".json")
                meta = {}
                if meta_f.exists():
                    try:
                        meta = json.loads(meta_f.read_text())
                    except Exception:
                        pass
                reports.append({
                    "filename": f.name,
                    "size_kb": round(f.stat().st_size / 1024, 1),
                    "risk_score": meta.get("risk_score", 0),
                    "scan_mode": meta.get("scan_mode", ""),
                    "timestamp": meta.get("completed_at", ""),
                    "hostname": meta.get("hostname", ""),
                    "scan_id": meta.get("scan_id", ""),
                    "url": f"/reports-view/{f.name}",
                })
        return jsonify({"reports": reports, "total": len(reports)})

    @app.route("/api/reports/delete/<filename>", methods=["DELETE"])
    @requires_auth
    def delete_report(filename):
        """Delete a specific report."""
        safe_name = os.path.basename(filename)
        if not safe_name.startswith("BlueSentinel_"):
            return jsonify({"success": False, "error": "Invalid filename"}), 400
        for suffix in [".html", ".json", ".pdf"]:
            target = REPORTS_DIR / (safe_name.replace(".html", suffix))
            if target.exists():
                target.unlink()
        return jsonify({"success": True, "message": f"Deleted {safe_name}"})

    @app.route("/api/hardware")
    @requires_auth
    def api_hardware():
        hw = app.extensions.get("hw_monitor")
        if hw is None:
            return jsonify({"error": "Hardware monitor not available"}), 503
        try:
            snapshot = hw.collect_snapshot()
            return jsonify(snapshot)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # API routes
    @app.route("/api/scan-results")
    @requires_auth
    def api_scan_results():
        return jsonify(_get_scan_result())

    @app.route("/api/alerts")
    @requires_auth
    def api_alerts():
        data = _get_scan_result()
        alerts_list = data.get("alerts", [])
        severity_filter = request.args.get("severity")
        if severity_filter:
            alerts_list = [a for a in alerts_list if a.get("severity") == severity_filter]
        return jsonify(alerts_list)

    @app.route("/api/metrics")
    @requires_auth
    def api_metrics():
        data = _get_scan_result()
        alerts = data.get("alerts", [])
        return jsonify({
            "risk_score": data.get("threat_score", 0),
            "critical": sum(1 for a in alerts if a.get("severity") == "Critical"),
            "high": sum(1 for a in alerts if a.get("severity") == "High"),
            "medium": sum(1 for a in alerts if a.get("severity") == "Medium"),
            "low": sum(1 for a in alerts if a.get("severity") == "Low"),
            "total_alerts": len(alerts),
            "yara_matches": len(data.get("yara_matches", [])),
            "beaconing": len(data.get("beaconing_alerts", [])),
            "ioc_matches": len(data.get("ioc_matches", [])),
            "ai_provider": data.get("ai_provider_used", "N/A"),
            "hostname": data.get("hostname", socket.gethostname()),
            "scan_id": data.get("scan_id", "N/A"),
            "last_scan": data.get("started_at", "Never"),
        })

    @app.route("/api/timeline")
    @requires_auth
    def api_timeline():
        if not _timeline:
            # Generate synthetic timeline from scan result
            data = _get_scan_result()
            now = time.time()
            points = []
            base_score = data.get("threat_score", 0)
            import random
            random.seed(42)
            for i in range(120):
                ts = now - (120 - i) * 60
                dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M")
                variation = random.randint(-5, 5)
                score = max(0, min(100, base_score + variation if i > 90 else variation))
                points.append({"time": dt, "risk_score": score, "alert_count": max(0, i - 90) if score > 30 else 0})
            return jsonify(points)
        return jsonify(_timeline[-120:])

    @app.route("/api/beaconing")
    @requires_auth
    def api_beaconing():
        data = _get_scan_result()
        beacons = data.get("beaconing_alerts", [])
        return jsonify(sorted(beacons, key=lambda b: b.get("confidence", 0), reverse=True)[:8])

    @app.route("/api/mitre-coverage")
    @requires_auth
    def api_mitre_coverage():
        data = _get_scan_result()
        return jsonify(data.get("mitre_coverage", {}))

    @app.route("/api/start-scan", methods=["POST"])
    @requires_auth
    def api_start_scan():
        data = request.get_json() or {}
        scan_mode = data.get("mode", "quick-scan")

        VALID = {"quick-scan", "file-only", "network-only", "full-scan"}
        if scan_mode not in VALID:
            return jsonify({"success": False, "error": f"Unknown mode: {scan_mode}"}), 400

        if app.config.get("SCAN_RUNNING"):
            return jsonify({"success": False, "error": "Scan already in progress"}), 409

        import uuid as _uuid
        scan_id = _uuid.uuid4().hex[:8].upper()
        app.config["SCAN_RUNNING"] = True
        app.config["SCAN_ID"] = scan_id
        app.config["SCAN_MODE"] = scan_mode

        socketio.emit("scan_started", {
            "scan_id": scan_id,
            "mode": scan_mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        def _background_scan():
            """Run scan in background, emit progress via socketio."""
            global _scan_results
            app.logger.info(f"[SCAN:{scan_id}] Background task started — mode={scan_mode}")
            try:
                from core.orchestrator import (
                    SCAN_PHASES, SCAN_MODE_MODULES, SCAN_TIMEOUTS,
                    ScanTimer, ScanTimeoutError,
                )
                import time as _t

                # Determine applicable modules
                applicable = SCAN_MODE_MODULES.get(scan_mode)
                all_mods = [m for ph in SCAN_PHASES for m in ph.modules]
                total = len(all_mods)

                # Count skips upfront so % starts correctly
                done = 0
                if applicable is not None:
                    done = sum(1 for m in all_mods if m not in applicable)

                result = {
                    "scan_id": scan_id,
                    "hostname": os.environ.get("COMPUTERNAME", "Windows11"),
                    "scan_mode": scan_mode,
                    "risk_score": 0, "threat_score": 0,
                    "critical_count": 0, "high_count": 0,
                    "alerts": [], "yara_matches": [], "beaconing_alerts": [],
                    "prefetch_anomalies": [], "vt_results": [],
                    "connections": [], "notifications": [],
                    "mitre_coverage": {}, "ioc_matches": [],
                    "total_files_scanned": 0, "cache_hits": 0, "cache_misses": 0,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "ai_provider_used": os.getenv("AI_PROVIDER", "openai"),
                }

                timeout_s = SCAN_TIMEOUTS.get(scan_mode)
                scan_start = _t.time()

                try:
                    with ScanTimer(timeout_s, scan_mode) as timer:
                        for phase_idx, phase in enumerate(SCAN_PHASES):
                            for module_name in phase.modules:
                                timer.check()

                                # Skip non-applicable modules
                                if applicable is not None and module_name not in applicable:
                                    done += 1
                                    continue

                                pct = round(done / total * 100) if total > 0 else 0

                                # Emit progress — this is what updates the bar
                                socketio.emit("scan_progress", {
                                    "scan_id": scan_id,
                                    "percent": pct,
                                    "module": module_name,
                                    "phase": phase.name,
                                    "status": "running...",
                                    "done": done,
                                    "total": total,
                                    "current_file": "",
                                })

                                # Run the module
                                try:
                                    mod_result = _run_module_for_dashboard(
                                        module_name, scan_mode, result,
                                        scan_id=scan_id,
                                        progress_emit=lambda pct2, mod, status, current_file="":
                                            socketio.emit("scan_progress", {
                                                "scan_id": scan_id,
                                                "percent": pct2,
                                                "module": mod,
                                                "phase": phase.name,
                                                "status": status,
                                                "done": done,
                                                "total": total,
                                                "current_file": current_file,
                                            })
                                    )
                                    if mod_result:
                                        _merge_module_result(result, mod_result)
                                    summary = mod_result.get('summary','ok') if mod_result else 'ok'
                                    app.logger.info(f"[SCAN:{scan_id}] {module_name}: {summary}")
                                except ScanTimeoutError:
                                    raise
                                except Exception as e:
                                    import traceback as _tb2
                                    app.logger.warning(f"[SCAN:{scan_id}] {module_name} error: {_tb2.format_exc()}")

                                done += 1
                                # Emit completion of this module
                                socketio.emit("scan_progress", {
                                    "scan_id": scan_id,
                                    "percent": round(done / total * 100),
                                    "module": module_name,
                                    "phase": phase.name,
                                    "status": "done",
                                    "done": done,
                                    "total": total,
                                    "current_file": "",
                                })

                except ScanTimeoutError as e:
                    app.logger.warning(str(e))
                    socketio.emit("scan_warning", {
                        "message": str(e), "scan_id": scan_id,
                    })

                result["duration_seconds"] = round(_t.time() - scan_start, 1)
                result["completed_at"] = datetime.now(timezone.utc).isoformat()

                # Compute risk score
                try:
                    from analyzers.threat_scorer import ThreatScorer
                    from types import SimpleNamespace as _NS
                    result_obj = _NS(**result)
                    score = ThreatScorer().calculate_score(result_obj)
                    result["risk_score"] = score
                    result["threat_score"] = score
                except Exception:
                    pass

                # Store result
                _scan_results = result
                store_scan_result(result)
                app.config["LAST_SCAN_RESULT"] = result

                # Save HTML report
                try:
                    from reporting.html_report_generator import generate_html_report_from_dict
                    if "threat_score" not in result:
                        result["threat_score"] = result.get("risk_score", 0)
                    rpath = generate_html_report_from_dict(result)
                    result["report_path"] = rpath
                    # Save JSON metadata alongside report
                    import json as _json
                    from pathlib import Path as _P
                    meta_path = rpath.replace(".html", ".json")
                    _P(meta_path).write_text(_json.dumps({
                        "scan_id":       result.get("scan_id", ""),
                        "hostname":      result.get("hostname", ""),
                        "scan_mode":     result.get("scan_mode", ""),
                        "completed_at":  result.get("completed_at", ""),
                        "risk_score":    result.get("risk_score", 0),
                        "critical_count":result.get("critical_count", 0),
                        "high_count":    result.get("high_count", 0),
                        "total_alerts":  len(result.get("alerts", [])),
                        "yara_matches":  len(result.get("yara_matches", [])),
                    }, indent=2), encoding="utf-8")
                    app.logger.info(f"[SCAN:{scan_id}] Report saved: {_P(rpath).name}")
                except Exception as e:
                    app.logger.warning(f"Report generation failed: {e}")
                    result["report_path"] = ""

                socketio.emit("scan_complete", {
                    "scan_id": scan_id,
                    "total_alerts": len(result.get("alerts", [])),
                    "critical": result.get("critical_count", 0),
                    "high": result.get("high_count", 0),
                    "risk_score": result.get("risk_score", 0),
                    "duration_seconds": result.get("duration_seconds", 0),
                    "report_path": result.get("report_path", ""),
                })

            except Exception as e:
                import traceback
                app.logger.error(f"Scan failed: {traceback.format_exc()}")
                socketio.emit("scan_error", {"error": str(e), "scan_id": scan_id})
            finally:
                app.config["SCAN_RUNNING"] = False

        # Use socketio.start_background_task for threading async mode compat
        socketio.start_background_task(_background_scan)

        return jsonify({"success": True, "scan_id": scan_id, "mode": scan_mode})

    @app.route("/api/scan-status", methods=["GET"])
    @requires_auth
    def api_scan_status():
        return jsonify({
            "running": bool(app.config.get("SCAN_RUNNING", False)),
            "mode": app.config.get("SCAN_MODE", ""),
            "has_results": app.config.get("LAST_SCAN_RESULT") is not None,
        })

    @app.route("/api/acknowledge-alert/<alert_id>", methods=["POST"])
    @requires_auth
    def api_acknowledge_alert(alert_id: str):
        data = _get_scan_result()
        for alert in data.get("alerts", []):
            if alert.get("alert_id") == alert_id:
                alert["acknowledged"] = True
                return jsonify({"status": "acknowledged", "alert_id": alert_id})
        abort(404)

    @app.route("/api/test-provider", methods=["POST"])
    @requires_auth
    def api_test_provider():
        start = time.time()
        try:
            from ai_engine.ai_provider import get_ai_provider
            provider = get_ai_provider()
            response = provider.complete(
                system_prompt="You are a test assistant.",
                user_prompt="Reply with: OK",
                max_tokens=10,
            )
            latency_ms = int((time.time() - start) * 1000)
            return jsonify({
                "status": "success" if response.success else "error",
                "provider": response.provider,
                "model": response.model,
                "latency_ms": latency_ms,
                "error": response.error,
            })
        except Exception as exc:
            return jsonify({"status": "error", "error": str(exc), "latency_ms": int((time.time() - start) * 1000)})

    @app.route("/api/save-settings", methods=["POST"])
    @requires_auth
    def api_save_settings():
        data = request.json or {}
        env_file = BASE_DIR / "config" / ".env"
        if not env_file.exists():
            env_file = BASE_DIR / ".env"
        lines = []
        if env_file.exists():
            with open(env_file) as fh:
                lines = fh.readlines()

        updates = {
            "AI_PROVIDER": data.get("ai_provider", ""),
            "OPENAI_API_KEY": data.get("openai_api_key", ""),
            "ANTHROPIC_API_KEY": data.get("anthropic_api_key", ""),
        }

        new_lines = []
        updated_keys = set()
        for line in lines:
            key = line.split("=")[0].strip()
            if key in updates and updates[key]:
                new_lines.append(f"{key}={updates[key]}\n")
                updated_keys.add(key)
            else:
                new_lines.append(line)

        for key, val in updates.items():
            if key not in updated_keys and val:
                new_lines.append(f"{key}={val}\n")

        try:
            with open(env_file, "w") as fh:
                fh.writelines(new_lines)
            return jsonify({"status": "saved"})
        except IOError as exc:
            return jsonify({"status": "error", "error": str(exc)}), 500

    @app.route("/api/export/<fmt>")
    @requires_auth
    def api_export(fmt: str):
        data = _scan_result_store.get("last_result")
        if data is None:
            return jsonify({
                "error": "No scan result available. Run a scan or load demo data first.",
                "hint": "POST /api/load-demo-data or run: python -m core.orchestrator --quick-scan",
            }), 404
        if fmt == "json":
            return jsonify(data)
        elif fmt == "html":
            from reporting.html_report_generator import generate_html_report_from_dict
            path = generate_html_report_from_dict(data)
            return send_file(path, as_attachment=True, mimetype="text/html")
        elif fmt in ("cef", "siem"):
            from reporting.siem_exporter import SiemExporter
            exp = SiemExporter()
            path = exp.export_cef(data)
            return send_file(path, as_attachment=True, mimetype="text/plain")
        else:
            abort(400)

    @app.route("/api/internal/store-result", methods=["POST"])
    def api_internal_store_result():
        """Called by CLI orchestrator to push scan results into a running dashboard."""
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "No JSON body"}), 400
        store_scan_result(data)
        global _scan_results
        _scan_results = data
        return jsonify({"status": "stored", "scan_id": data.get("scan_id", "unknown")})

    # ── Notification endpoints ─────────────────────────────────────────────

    @app.route("/api/notifications", methods=["GET"])
    @requires_auth
    def api_notifications():
        return jsonify(notification_store)

    @app.route("/api/notifications/acknowledge/<notif_id>", methods=["POST"])
    @requires_auth
    def api_acknowledge_notification(notif_id: str):
        for n in notification_store:
            if n.get("id") == notif_id:
                n["is_acknowledged"] = True
                return jsonify({"success": True})
        return jsonify({"success": False, "error": "Notification not found"}), 404

    @app.route("/api/kill-process/<int:pid>", methods=["POST"])
    @requires_auth
    def api_kill_process(pid: int):
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()

            # Safety check — never kill protected processes
            if proc_name.lower() in PROTECTED_PROCESSES:
                return jsonify({
                    'success': False,
                    'error': f'Process {proc_name} (PID {pid}) is protected and cannot be terminated by BlueSentinel.',
                    'protected': True,
                }), 403

            # Reject kernel/system PIDs
            if proc.pid <= 4:
                return jsonify({
                    'success': False,
                    'error': f'PID {pid} is a system process — cannot terminate.',
                    'protected': True,
                }), 403

            proc.kill()
            socketio.emit("notification_update", {
                "action": "process_killed",
                "pid": pid,
                "process_name": proc_name,
                "message": f"Process {proc_name} (PID {pid}) terminated successfully.",
            })
            return jsonify({"success": True, "message": f"Process {proc_name} (PID {pid}) killed.",
                            "pid": pid, "process_name": proc_name})
        except psutil.NoSuchProcess:
            return jsonify({"success": False, "error": f"Process {pid} no longer exists."}), 404
        except psutil.AccessDenied:
            return jsonify({"success": False,
                            "error": "Access denied. Run BlueSentinel as Administrator to kill system processes."}), 403
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 500

    @app.route("/api/blacklist-ip", methods=["POST"])
    @requires_auth
    def api_blacklist_ip():
        data = request.get_json() or {}
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({"success": False, "error": "No IP provided"}), 400

        blacklist = _load_blacklist()
        blacklist.add(ip)
        _save_blacklist(blacklist)

        try:
            from analyzers.ioc_matcher import IOCMatcher
            matcher = IOCMatcher()
            matcher.add_ioc("ip", ip, "manual_blacklist", "C2", 100)
        except Exception:
            pass

        socketio.emit("notification_update", {
            "action": "ip_blacklisted",
            "ip": ip,
            "message": f"IP {ip} added to blacklist and IOC database.",
        })
        return jsonify({"success": True, "message": f"IP {ip} blacklisted.", "ip": ip})

    @app.route("/api/firewall-block", methods=["POST"])
    @requires_auth
    def firewall_block_ip():
        data   = request.get_json() or {}
        ip     = (data.get('ip') or '').strip()
        reason = data.get('reason', 'Blocked by BlueSentinel V2.0')
        if not ip:
            return jsonify({'success': False, 'error': 'IP required'}), 400
        safe, msg = _validate_ip_for_blocking(ip)
        if not safe:
            return jsonify({'success': False, 'error': msg}), 400
        rule = f"BlueSentinel_Block_{ip.replace('.','_').replace(':','_')}"
        try:
            chk = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule}_OUT'],
                capture_output=True, text=True, timeout=8
            )
            if chk.returncode == 0 and 'No rules match' not in chk.stdout:
                return jsonify({'success': True, 'already_blocked': True,
                                'message': f'{ip} already blocked in firewall'})
            errors = []
            for direction, dir_flag in [('OUT', 'out'), ('IN', 'in')]:
                res = subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule}_{direction}', f'dir={dir_flag}',
                    'action=block', f'remoteip={ip}', 'enable=yes',
                    f'description={reason} [{dir_flag}]',
                ], capture_output=True, text=True, timeout=15)
                if res.returncode != 0:
                    errors.append(res.stderr.strip() or res.stdout.strip())
            if errors:
                err_text = ' | '.join(errors)
                if 'access is denied' in err_text.lower() or 'elevation' in err_text.lower():
                    return jsonify({'success': False,
                                    'error': 'Access denied — run BlueSentinel as Administrator'}), 403
                return jsonify({'success': False, 'error': err_text}), 500
            bl = _load_blacklist()
            bl.add(ip)
            _save_blacklist(bl)
            log.info(f'Firewall blocked: {ip}')
            socketio.emit('notification_update', {
                'action': 'firewall_blocked', 'ip': ip,
                'message': f'{ip} blocked in Windows Firewall (inbound + outbound)',
            })
            return jsonify({'success': True,
                            'message': f'{ip} blocked in Windows Firewall',
                            'rule': rule, 'ip': ip})
        except FileNotFoundError:
            return jsonify({'success': False, 'error': 'netsh not found — Windows only'}), 501
        except subprocess.TimeoutExpired:
            return jsonify({'success': False, 'error': 'Firewall command timed out'}), 500
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route("/api/firewall-unblock", methods=["POST"])
    @requires_auth
    def firewall_unblock_ip():
        data = request.get_json() or {}
        ip   = (data.get('ip') or '').strip()
        if not ip:
            return jsonify({'success': False, 'error': 'IP required'}), 400
        rule = f"BlueSentinel_Block_{ip.replace('.','_').replace(':','_')}"
        for direction in ['_OUT', '_IN']:
            try:
                subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                     f'name={rule}{direction}'],
                    capture_output=True, text=True, timeout=10
                )
            except Exception:
                pass
        return jsonify({'success': True,
                        'message': f'Firewall rules removed for {ip}', 'ip': ip})

    @app.route("/api/news", methods=["GET"])
    @requires_auth
    def get_news():
        """Return top 10 cybersecurity headlines. Cached 30 minutes."""
        try:
            from intelligence.news_client import get_news_client
            client = get_news_client()
            headlines = client.get_headlines(limit=10)
            return jsonify({
                "success": True,
                "headlines": headlines,
                "count": len(headlines),
            })
        except Exception as e:
            return jsonify({
                "success": False,
                "headlines": [],
                "error": str(e),
            })

    @app.route("/api/logs/dates", methods=["GET"])
    @requires_auth
    def get_log_dates():
        """Return list of dates that have log files."""
        from core.logger import list_available_log_dates
        dates = list_available_log_dates()
        return jsonify({"dates": dates, "retention_days": 7})

    @app.route("/api/logs/<date>", methods=["GET"])
    @requires_auth
    def get_logs_for_date(date):
        """Return log entries for a specific date (YYYY-MM-DD)."""
        from core.logger import get_logs_by_date
        level  = request.args.get("level", "").upper()
        module = request.args.get("module", "")
        limit  = int(request.args.get("limit", 500))

        entries = get_logs_by_date(date)
        if level:
            entries = [e for e in entries if e.get("level") == level]
        if module:
            entries = [e for e in entries if module.lower() in e.get("module", "").lower()]

        return jsonify({
            "date": date,
            "count": len(entries),
            "entries": entries[-limit:],
        })

    @app.route("/api/logs/range", methods=["GET"])
    @requires_auth
    def get_logs_for_range():
        """Return log entries for a date range."""
        from core.logger import get_logs_range
        start = request.args.get("start", "")
        end   = request.args.get("end", "")
        if not start or not end:
            return jsonify({"error": "start and end date required (YYYY-MM-DD)"}), 400

        entries = get_logs_range(start, end)
        level   = request.args.get("level", "").upper()
        if level:
            entries = [e for e in entries if e.get("level") == level]

        return jsonify({
            "start": start,
            "end": end,
            "count": len(entries),
            "entries": entries,
        })

    @app.route("/api/load-demo-data", methods=["POST"])
    @requires_auth
    def api_load_demo_data():
        import threading as _threading
        demo_path = CACHE_DIR / "demo_scan_result.json"
        demo_data = None

        if demo_path.exists():
            try:
                demo_data = json.loads(demo_path.read_text(encoding='utf-8'))
            except Exception:
                demo_data = None

        if not demo_data:
            try:
                from demo.generate_demo_data import build_scan_result
                demo_data = build_scan_result()
                demo_path.parent.mkdir(parents=True, exist_ok=True)
                demo_path.write_text(
                    json.dumps(demo_data, indent=2, ensure_ascii=False),
                    encoding='utf-8'
                )
            except Exception as exc:
                log.error(f"Demo generation failed: {exc}")
                return jsonify({"success": False, "error": f"Demo failed: {exc}"}), 500

        global _scan_results
        _scan_results = demo_data
        store_scan_result(demo_data)
        app.config['LAST_SCAN_RESULT'] = demo_data
        app.config["DEMO_MODE"] = True

        socketio.emit("scan_complete", {
            "total_alerts": demo_data.get("total_alerts", 0),
            "critical": demo_data.get("critical_count", 0),
            "high": demo_data.get("high_count", 0),
            "risk_score": demo_data.get("risk_score", 0),
            "duration_seconds": 12.4,
            "demo_mode": True,
        })

        def _send_demo_notifs():
            import time as _time
            for notif in demo_data.get("notifications", []):
                _time.sleep(0.5)
                notification_store.insert(0, notif)
                if len(notification_store) > MAX_NOTIFICATIONS:
                    notification_store.pop()
                socketio.emit("threat_notification", notif)

        _threading.Thread(target=_send_demo_notifs, daemon=True).start()
        return jsonify({"success": True, "message": "Demo data loaded",
                        "alerts": demo_data.get("total_alerts", 0)})

    @app.route("/api/ip-intel/<ip>", methods=["GET"])
    @requires_auth
    def ip_intelligence(ip):
        """Comprehensive IP intelligence: geolocation + abuse score + IOC status."""
        import ipaddress as _ipaddr
        try:
            _ipaddr.ip_address(ip)
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid IP'}), 400

        result = {'ip': ip, 'success': True, 'sources': {}}

        # ipinfo.io — free, no key needed
        try:
            import requests as _req
            r = _req.get(f'https://ipinfo.io/{ip}/json',
                         headers={'Accept': 'application/json'}, timeout=6)
            if r.status_code == 200:
                d = r.json()
                loc = d.get('loc', '')
                result['geolocation'] = {
                    'city':     d.get('city', ''),
                    'region':   d.get('region', ''),
                    'country':  d.get('country', ''),
                    'org':      d.get('org', ''),
                    'timezone': d.get('timezone', ''),
                    'loc':      loc,
                    'hostname': d.get('hostname', ''),
                    'map_url':  f'https://www.google.com/maps?q={loc}' if loc and ',' in loc else '',
                }
                result['sources']['ipinfo'] = 'OK'
        except Exception as e:
            result['sources']['ipinfo'] = f'Error: {e}'

        # AbuseIPDB
        abuse_key = os.getenv('ABUSEIPDB_API_KEY', '')
        if abuse_key and abuse_key != 'test':
            try:
                import requests as _req
                r = _req.get('https://api.abuseipdb.com/api/v2/check',
                    params={'ipAddress': ip, 'maxAgeInDays': 90},
                    headers={'Key': abuse_key, 'Accept': 'application/json'},
                    timeout=6)
                if r.status_code == 200:
                    d = r.json().get('data', {})
                    result['abuse'] = {
                        'score':       d.get('abuseConfidenceScore', 0),
                        'reports':     d.get('totalReports', 0),
                        'last_seen':   d.get('lastReportedAt', ''),
                        'isp':         d.get('isp', ''),
                        'usage_type':  d.get('usageType', ''),
                        'domain':      d.get('domain', ''),
                        'whitelisted': d.get('isWhitelisted', False),
                    }
                    result['sources']['abuseipdb'] = 'OK'
            except Exception as e:
                result['sources']['abuseipdb'] = f'Error: {e}'

        # Local IOC check
        try:
            from analyzers.ioc_matcher import IOCMatcher
            matcher = IOCMatcher()
            ioc = matcher.check_ip(ip)
            result['ioc'] = {
                'found':      ioc is not None,
                'source':     getattr(ioc, 'source', ''),
                'confidence': getattr(ioc, 'confidence', 0),
                'category':   getattr(ioc, 'category', ''),
            }
            result['sources']['ioc_db'] = 'OK'
        except Exception as e:
            result['ioc'] = {'found': False}
            result['sources']['ioc_db'] = f'Error: {e}'

        # Blacklist + firewall status
        result['in_blacklist'] = ip in _load_blacklist()
        try:
            rule = f"BlueSentinel_Block_{ip.replace('.','_').replace(':','_')}_OUT"
            chk = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule}'],
                capture_output=True, text=True, timeout=5)
            result['firewall_blocked'] = 'No rules match' not in chk.stdout
        except Exception:
            result['firewall_blocked'] = False

        return jsonify(result)

    @app.route("/api/clear-demo-data", methods=["POST"])
    @requires_auth
    def api_clear_demo_data():
        global _scan_results
        _scan_results = None
        app.config['LAST_SCAN_RESULT'] = None
        app.config['DEMO_MODE'] = False
        app.config['SCAN_RUNNING'] = False
        _scan_result_store["last_result"] = None
        _scan_result_store["last_updated"] = None
        notification_store.clear()
        socketio.emit('demo_cleared', {
            'message': 'Demo data cleared',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })
        return jsonify({'success': True, 'message': 'Demo data cleared. Page will refresh.'})

    # Socket.IO events
    @socketio.on("connect")
    def handle_connect():
        data = _get_scan_result()
        socketio.emit("risk_score_update", {
            "score": data.get("threat_score", 0),
            "delta": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    @socketio.on("request_metrics")
    def handle_request_metrics():
        data = _get_scan_result()
        alerts = data.get("alerts", [])
        socketio.emit("metrics_update", {
            "risk_score": data.get("threat_score", 0),
            "total_alerts": len(alerts),
            "critical": sum(1 for a in alerts if a.get("severity") == "Critical"),
        })

    return app


# Module-level app instance — allows `from dashboard.app import app` in tests/scripts.
# create_app() is idempotent and safe to call at import time.
app = create_app()


def ensure_ssl_cert():
    """Generate self-signed SSL cert for dashboard HTTPS. Returns (cert_path, key_path) or (None, None)."""
    cert_path = BASE_DIR / "config" / "dashboard.crt"
    key_path  = BASE_DIR / "config" / "dashboard.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)
    try:
        result = subprocess.run([
            'python', '-c',
            '''
import sys
from pathlib import Path
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime, ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "BlueSentinel Dashboard"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BlueSentinel V2.0"),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256(), default_backend()))
    Path("config/dashboard.key").write_bytes(
        key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    Path("config/dashboard.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print("SSL cert generated")
except ImportError:
    print("cryptography not installed — using HTTP")
'''
        ], capture_output=True, timeout=30, cwd=str(BASE_DIR))
    except Exception:
        pass
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)
    return None, None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    _socketio = app.extensions["socketio"]
    _port = app.config.get("DASHBOARD_PORT", 5000)
    _cert, _key = ensure_ssl_cert()
    if _cert and _key:
        print(f"[*] BlueSentinel Dashboard starting on https://0.0.0.0:{_port}")
        print(f"[*] Username: {app.config['DASHBOARD_USERNAME']}")
        _socketio.run(app, host="0.0.0.0", port=_port,
                      ssl_context=(_cert, _key), debug=False, allow_unsafe_werkzeug=True)
    else:
        print(f"[*] BlueSentinel Dashboard starting on http://0.0.0.0:{_port}")
        print(f"[*] Username: {app.config['DASHBOARD_USERNAME']}")
        print("[!] Install 'cryptography' package for HTTPS support.")
        _socketio.run(app, host="0.0.0.0", port=_port, debug=False, allow_unsafe_werkzeug=True)
