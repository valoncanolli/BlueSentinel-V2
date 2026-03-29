"""
core/orchestrator.py
Central orchestrator for BlueSentinel v2.0 scan pipeline.
Manages all modules, aggregates results, provides CLI interface.
"""
import argparse
import asyncio
import json
import math
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

import sys
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

# Ensure UTF-8 output on Windows (prevents UnicodeEncodeError with box-drawing chars)
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, Exception):
    pass

from core.logger import get_logger
from core.config_manager import get_config
from core.integrity_check import verify_integrity
from core.progress import ScanProgress, ScanPhase, LiveRenderer, C

log = get_logger(__name__)


@dataclass
class Alert:
    alert_id: str
    severity: str  # Critical, High, Medium, Low
    alert_type: str
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    mitre_technique: str = ""
    mitre_tactic: str = ""
    source_module: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    ai_analysis: Optional[Dict[str, Any]] = None
    acknowledged: bool = False


@dataclass
class ScanResult:
    scan_id: str
    hostname: str
    scan_mode: str
    started_at: str
    completed_at: str = ""
    duration_seconds: float = 0.0
    alerts: List[Alert] = field(default_factory=list)
    threat_score: int = 0
    yara_matches: List[Dict] = field(default_factory=list)
    beaconing_alerts: List[Dict] = field(default_factory=list)
    network_findings: List[Dict] = field(default_factory=list)
    memory_findings: List[Dict] = field(default_factory=list)
    registry_findings: List[Dict] = field(default_factory=list)
    prefetch_findings: List[Dict] = field(default_factory=list)
    ioc_matches: List[Dict] = field(default_factory=list)
    mitre_coverage: Dict[str, Any] = field(default_factory=dict)
    ai_summary: str = ""
    ai_provider_used: str = ""
    errors: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == "Critical")

    @property
    def high_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == "High")

    @property
    def total_alerts(self) -> int:
        return len(self.alerts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "hostname": self.hostname,
            "scan_mode": self.scan_mode,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "threat_score": self.threat_score,
            "total_alerts": self.total_alerts,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "severity": a.severity,
                    "type": a.alert_type,
                    "message": a.message,
                    "timestamp": a.timestamp,
                    "mitre_technique": a.mitre_technique,
                    "mitre_tactic": a.mitre_tactic,
                    "source_module": a.source_module,
                    "acknowledged": a.acknowledged,
                    "ai_analysis": a.ai_analysis,
                }
                for a in self.alerts
            ],
            "yara_matches": self.yara_matches,
            "beaconing_alerts": self.beaconing_alerts,
            "ioc_matches": self.ioc_matches,
            "mitre_coverage": self.mitre_coverage,
            "ai_summary": self.ai_summary,
            "ai_provider_used": self.ai_provider_used,
            "errors": self.errors,
        }


SCAN_PHASES = [
    ScanPhase("DATA COLLECTION", ["network_check", "memory_snapshot", "prefetch_parser"], weight=2.0),
    ScanPhase("ANALYSIS",        ["yara_engine", "beaconing_detector", "ioc_matcher"],    weight=3.0),
    ScanPhase("THREAT SCORING",  ["threat_scorer", "mitre_mapper"],                        weight=1.0),
    ScanPhase("AI ANALYSIS",     ["threat_explainer", "report_narrator"],                  weight=1.5),
    ScanPhase("REPORTING",       ["html_report_generator", "siem_exporter"],               weight=0.5),
]

# Modules applicable per scan mode (None = all modules run)
SCAN_MODE_MODULES = {
    'full-scan': None,
    'file-only': {
        'yara_engine', 'ioc_matcher', 'threat_scorer',
        'mitre_mapper', 'virustotal_lookup', 'html_report_generator',
        'siem_exporter',
    },
    'network-only': {
        'network_check', 'tshark_capture', 'beaconing_detector',
        'ioc_matcher', 'abuseipdb_lookup', 'otx_lookup',
        'feed_aggregator', 'threat_scorer', 'mitre_mapper',
        'html_report_generator',
    },
    'quick-scan': {
        'network_check', 'memory_snapshot', 'yara_engine',
        'ioc_matcher', 'threat_scorer', 'mitre_mapper',
        'html_report_generator',
    },
}

# Hard timeout per scan mode in seconds (None = no timeout)
SCAN_TIMEOUTS: dict = {
    'quick-scan':   300,
    'file-only':    600,
    'network-only': 120,
    'full-scan':    None,
}


class ScanTimeoutError(Exception):
    pass


class ScanTimer:
    """Hard timeout enforcer for scan modes."""

    def __init__(self, seconds, mode: str):
        self.seconds  = seconds
        self.mode     = mode
        self._expired = threading.Event()
        self._timer   = None

    def __enter__(self):
        if self.seconds:
            self._timer = threading.Timer(self.seconds, self._expired.set)
            self._timer.daemon = True
            self._timer.start()
        return self

    def __exit__(self, *args):
        if self._timer:
            self._timer.cancel()

    def check(self):
        if self._expired.is_set():
            raise ScanTimeoutError(
                f'{self.mode} exceeded {self.seconds}s limit. '
                f'Generating partial report.'
            )

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
██████╗ ██╗     ██╗   ██╗███████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔══██╗██║     ██║   ██║██╔════╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
██████╔╝██║     ██║   ██║█████╗  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██╔══██╗██║     ██║   ██║██╔══╝  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
██████╔╝███████╗╚██████╔╝███████╗███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}                 v2.0 — AI-Augmented Threat Detection Platform{Style.RESET_ALL}
{Fore.BLUE}                 Author: Valon Canolli | Cyber Security Engineer{Style.RESET_ALL}
"""


def collect_files_parallel(scan_paths: list, max_size_mb: int = 50) -> list:
    """Collect all file paths from multiple directories in parallel."""
    all_files = []
    lock = threading.Lock()

    def collect_one(path):
        found = []
        try:
            for f in Path(path).rglob('*'):
                if f.is_file() and f.stat().st_size <= max_size_mb * 1024 * 1024:
                    found.append(f)
        except (PermissionError, OSError):
            pass
        return found

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(collect_one, p) for p in scan_paths if Path(p).exists()]
        for fut in futures:
            try:
                with lock:
                    all_files.extend(fut.result())
            except Exception:
                pass

    return all_files


def scan_files_parallel(files: list, rules, cache, progress=None,
                        workers: int = 4) -> tuple:
    """
    Scan files in parallel using ThreadPoolExecutor.
    workers=4 is safe — yara-python's match() is GIL-safe for reads.
    """
    if not files:
        return [], 0, 0

    chunk_size = max(1, math.ceil(len(files) / workers))
    chunks = [files[i:i+chunk_size] for i in range(0, len(files), chunk_size)]

    all_matches = []
    total_hits  = 0
    total_miss  = 0
    lock = threading.Lock()

    def scan_chunk(chunk):
        matches = []
        hits = misses = 0
        for f in chunk:
            if cache:
                cached = cache.get_if_unchanged(str(f))
                if cached is not None:
                    hits += 1
                    continue
            misses += 1
            try:
                m = rules.match(str(f))
                if m:
                    matches.extend(m)
                    if progress:
                        progress.add_finding('high')
            except Exception:
                pass
            if cache:
                cache.store(str(f), 'malicious' if matches else 'clean',
                            [x.rule for x in matches])
        return matches, hits, misses

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_chunk, chunk) for chunk in chunks]
        for fut in as_completed(futures):
            try:
                m, h, ms = fut.result()
                with lock:
                    all_matches.extend(m)
                    total_hits  += h
                    total_miss  += ms
            except Exception:
                pass

    if cache:
        cache.save()

    return all_matches, total_hits, total_miss


async def _explain_findings_async(findings: list, provider) -> list:
    """Explain multiple findings concurrently (max 3 at a time)."""
    semaphore = asyncio.Semaphore(3)

    async def explain_one(finding):
        async with semaphore:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, provider.complete,
                "You are a SOC analyst. Analyze this finding.",
                str(finding)
            )

    tasks = [explain_one(f) for f in findings[:10]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if not isinstance(r, Exception)]


def run_scan(mode: str) -> ScanResult:
    import socket
    import uuid

    config = get_config()
    hostname = socket.gethostname()
    scan_id = str(uuid.uuid4())[:8].upper()
    started = datetime.now(timezone.utc)

    result = ScanResult(
        scan_id=scan_id,
        hostname=hostname,
        scan_mode=mode,
        started_at=started.isoformat(),
    )

    print(BANNER)

    # Get file cache stats
    cache_total = cache_clean = cache_suspicious = cache_malicious = 0
    try:
        from core.file_cache import FileCache
        _fc = FileCache()
        _stats = _fc.stats()
        cache_total     = _stats.get("total_entries", 0)
        cache_clean     = _stats.get("clean", 0)
        cache_suspicious = _stats.get("suspicious", 0)
        cache_malicious = _stats.get("malicious", 0)
    except Exception:
        pass

    progress = ScanProgress(
        phases=SCAN_PHASES,
        scan_id=scan_id,
        hostname=hostname,
        mode=mode,
        ai_provider=config.ai_provider.upper(),
    )

    # Determine applicable modules for this scan mode
    applicable = SCAN_MODE_MODULES.get(mode)  # None = all modules run
    all_modules = [m for phase in SCAN_PHASES for m in phase.modules]

    # Pre-skip non-applicable modules so overall_percent starts correctly
    for mod in all_modules:
        if applicable is not None and mod not in applicable:
            progress.skip_module(mod)

    report_output_path = ""

    with LiveRenderer(progress) as live:

        live.print_scan_header(
            cache_total=cache_total,
            cache_clean=cache_clean,
            cache_suspicious=cache_suspicious,
            cache_malicious=cache_malicious,
        )

        # ── Phase 0: DATA COLLECTION ─────────────────────────────────────────
        progress.start_phase(0)
        live.phase_started()

        # memory_snapshot
        if applicable is None or 'memory_snapshot' in applicable:
            progress.current_module = "memory_snapshot"
            progress.current_module_status = "Scanning process memory..."
            try:
                live.pause()
                from collectors.py.memory_snapshot import collect_memory_snapshot
                mem_data = collect_memory_snapshot()
                live.resume()
                result.memory_findings = mem_data.get("suspicious_processes", [])
                live.module_done(
                    "memory_snapshot",
                    f"Found {len(result.memory_findings)} suspicious processes [100%]"
                )
                progress.advance_module("memory_snapshot", "done")
            except Exception as exc:
                live.resume()
                log.error(f"memory_snapshot failed: {exc}")
                result.errors.append(f"memory_snapshot: {str(exc)}")
                live.module_done("memory_snapshot", "ERROR")
                progress.advance_module("memory_snapshot", "ERROR")
        else:
            live.module_skipped("memory_snapshot", f"skipped ({mode} mode)")

        # prefetch_parser
        if applicable is None or 'prefetch_parser' in applicable:
            progress.current_module = "prefetch_parser"
            progress.current_module_status = "Parsing prefetch files..."
            try:
                live.pause()
                from collectors.py.prefetch_parser import parse_prefetch_directory
                pf_data = parse_prefetch_directory()
                live.resume()
                result.prefetch_findings = pf_data.get("suspicious", [])
                live.module_done(
                    "prefetch_parser",
                    f"Found {len(result.prefetch_findings)} suspicious entries [100%]"
                )
                progress.advance_module("prefetch_parser", "done")
            except Exception as exc:
                live.resume()
                log.error(f"prefetch_parser failed: {exc}")
                result.errors.append(f"prefetch_parser: {str(exc)}")
                live.module_done("prefetch_parser", "ERROR")
                progress.advance_module("prefetch_parser", "ERROR")
        else:
            live.module_skipped("prefetch_parser", f"skipped ({mode} mode)")

        # ── Phase 1: ANALYSIS ────────────────────────────────────────────────
        progress.start_phase(1)
        live.phase_started()

        # yara_engine
        if applicable is None or 'yara_engine' in applicable:
            progress.current_module = "yara_engine"
            progress.current_module_status = "Loading YARA rules..."
            try:
                from analyzers.yara_engine import YaraEngine
                engine = YaraEngine()
                scan_paths = [Path("C:/Windows/Temp"), Path("C:/Users")]

                # pause_fn/resume_fn passed so YARA tqdm doesn't collide with bar
                yara_results, cache_hits, cache_misses = engine.scan_directory(
                    path=str(scan_paths[0]) if scan_paths[0].exists() else str(scan_paths[1]),
                    progress=progress,
                    pause_fn=live.pause,
                    resume_fn=live.resume,
                )
                # Scan additional paths
                for sp in scan_paths[1:]:
                    if sp.exists():
                        more, h, ms = engine.scan_directory(
                            path=str(sp),
                            progress=progress,
                            pause_fn=live.pause,
                            resume_fn=live.resume,
                        )
                        yara_results.extend(more)
                        cache_hits += h
                        cache_misses += ms

                result.yara_matches = [r.to_dict() for r in yara_results]
                for match in yara_results:
                    result.alerts.append(Alert(
                        alert_id=f"YARA-{scan_id}-{len(result.alerts)}",
                        severity=match.severity,
                        alert_type="YARA_MATCH",
                        message=f"YARA rule '{match.rule_name}' matched: {match.file_path}",
                        mitre_technique=match.mitre_technique,
                        source_module="yara_engine",
                        raw_data=match.to_dict(),
                    ))
                    progress.add_finding(match.severity.lower())

                total_scanned = cache_hits + cache_misses
                efficiency = (
                    f"{cache_hits/total_scanned*100:.0f}%" if total_scanned > 0 else "0%"
                )
                live.module_done(
                    "yara_engine",
                    f"Scanned {total_scanned} files, {len(yara_results)} matches, "
                    f"cache efficiency {efficiency}"
                )
                progress.advance_module("yara_engine", "done")
            except Exception as exc:
                live.resume()
                log.error(f"yara_engine failed: {exc}")
                result.errors.append(f"yara_engine: {str(exc)}")
                live.module_done("yara_engine", "ERROR")
                progress.advance_module("yara_engine", "ERROR")
        else:
            live.module_skipped("yara_engine", f"skipped ({mode} mode)")

        # beaconing_detector
        if applicable is None or 'beaconing_detector' in applicable:
            progress.current_module = "beaconing_detector"
            progress.current_module_status = "Analyzing network connections..."
            try:
                live.pause()
                from analyzers.beaconing_detector import BeaconingDetector
                detector = BeaconingDetector()
                capture_file = Path("cache/latest_capture.json")
                beacons = []
                if capture_file.exists():
                    with open(capture_file) as fh:
                        traffic = json.load(fh)
                    progress.current_module_status = (
                        f"Analysing {len(traffic)} connections — FFT processing"
                    )
                    beacons = detector.analyze(traffic)
                live.resume()
                result.beaconing_alerts = [b.to_dict() for b in beacons]
                for beacon in beacons:
                    result.alerts.append(Alert(
                        alert_id=f"BEACON-{scan_id}-{len(result.alerts)}",
                        severity="High" if beacon.confidence > 70 else "Medium",
                        alert_type="BEACONING",
                        message=f"Beaconing detected to {beacon.dst_ip}:{beacon.dst_port} (confidence: {beacon.confidence:.0f}%)",
                        mitre_technique="T1071",
                        source_module="beaconing_detector",
                        raw_data=beacon.to_dict(),
                    ))
                    progress.add_finding("high" if beacon.confidence > 70 else "medium")
                live.module_done(
                    "beaconing_detector",
                    f"Found {len(result.beaconing_alerts)} beaconing flows [100%]"
                )
                progress.advance_module("beaconing_detector", "done")
            except Exception as exc:
                live.resume()
                log.error(f"beaconing_detector failed: {exc}")
                result.errors.append(f"beaconing_detector: {str(exc)}")
                live.module_done("beaconing_detector", "ERROR")
                progress.advance_module("beaconing_detector", "ERROR")
        else:
            live.module_skipped("beaconing_detector", f"skipped ({mode} mode)")

        # ── Phase 2: THREAT SCORING ──────────────────────────────────────────
        progress.start_phase(2)
        live.phase_started()

        # threat_scorer
        if applicable is None or 'threat_scorer' in applicable:
            progress.current_module = "threat_scorer"
            progress.current_module_status = "Calculating risk score..."
            try:
                from analyzers.threat_scorer import ThreatScorer
                scorer = ThreatScorer()
                result.threat_score = scorer.calculate_score(result)
                live.module_done(
                    "threat_scorer",
                    f"Risk score: {result.threat_score}/100 [100%]"
                )
                progress.advance_module("threat_scorer", "done")
            except Exception as exc:
                log.error(f"threat_scorer failed: {exc}")
                result.errors.append(f"threat_scorer: {str(exc)}")
                live.module_done("threat_scorer", "ERROR")
                progress.advance_module("threat_scorer", "ERROR")
        else:
            live.module_skipped("threat_scorer", f"skipped ({mode} mode)")

        # mitre_mapper
        if applicable is None or 'mitre_mapper' in applicable:
            progress.current_module = "mitre_mapper"
            progress.current_module_status = "Mapping to MITRE ATT&CK..."
            try:
                from analyzers.mitre_mapper import MitreMapper
                mapper = MitreMapper()
                result.mitre_coverage = mapper.generate_navigator_layer(result.alerts)
                live.module_done(
                    "mitre_mapper",
                    f"Mapped {len(result.mitre_coverage.get('techniques', []))} techniques [100%]"
                )
                progress.advance_module("mitre_mapper", "done")
            except Exception as exc:
                log.error(f"mitre_mapper failed: {exc}")
                result.errors.append(f"mitre_mapper: {str(exc)}")
                live.module_done("mitre_mapper", "ERROR")
                progress.advance_module("mitre_mapper", "ERROR")
        else:
            live.module_skipped("mitre_mapper", f"skipped ({mode} mode)")

        # ── Phase 3: AI ANALYSIS ─────────────────────────────────────────────
        progress.start_phase(3)
        live.phase_started()

        # threat_explainer
        if applicable is None or 'threat_explainer' in applicable:
            progress.current_module = "threat_explainer"
            progress.current_module_status = f"Analysing top {min(10, len(result.alerts))} alerts with {config.ai_provider.upper()}..."
            try:
                from ai_engine.threat_explainer import ThreatExplainer
                explainer = ThreatExplainer()
                for alert in result.alerts[:10]:
                    alert.ai_analysis = explainer.explain(
                        alert.to_dict() if hasattr(alert, "to_dict") else alert.__dict__
                    )
                live.module_done(
                    "threat_explainer",
                    f"Explained {min(10, len(result.alerts))} alerts [100%]"
                )
                progress.advance_module("threat_explainer", "done")
            except Exception as exc:
                log.error(f"threat_explainer failed: {exc}")
                result.errors.append(f"threat_explainer: {str(exc)}")
                live.module_done("threat_explainer", "ERROR")
                progress.advance_module("threat_explainer", "ERROR")
        else:
            live.module_skipped("threat_explainer", f"skipped ({mode} mode)")

        # report_narrator
        if applicable is None or 'report_narrator' in applicable:
            progress.current_module = "report_narrator"
            progress.current_module_status = "Generating executive summary..."
            try:
                from ai_engine.report_narrator import ReportNarrator
                narrator = ReportNarrator()
                result.ai_summary = narrator.narrate(result)
                result.ai_provider_used = config.ai_provider
                live.module_done("report_narrator", "Executive summary complete [100%]")
                progress.advance_module("report_narrator", "done")
            except Exception as exc:
                log.error(f"report_narrator failed: {exc}")
                result.errors.append(f"report_narrator: {str(exc)}")
                live.module_done("report_narrator", "ERROR")
                progress.advance_module("report_narrator", "ERROR")
        else:
            live.module_skipped("report_narrator", f"skipped ({mode} mode)")

        # ── Phase 4: REPORTING ───────────────────────────────────────────────
        progress.start_phase(4)
        live.phase_started()

        # html_report_generator
        if applicable is None or 'html_report_generator' in applicable:
            progress.current_module = "html_report_generator"
            progress.current_module_status = "Generating HTML report..."
            try:
                from reporting.html_report_generator import generate_html_report
                report_output_path = str(generate_html_report(result))
                live.module_done(
                    "html_report_generator",
                    f"Saved: {report_output_path} [100%]"
                )
                progress.advance_module("html_report_generator", "done")
            except Exception as exc:
                log.error(f"html_report_generator failed: {exc}")
                result.errors.append(f"html_report_generator: {str(exc)}")
                live.module_done("html_report_generator", "ERROR")
                progress.advance_module("html_report_generator", "ERROR")
        else:
            live.module_skipped("html_report_generator", f"skipped ({mode} mode)")

        # siem_exporter
        if applicable is None or 'siem_exporter' in applicable:
            progress.current_module = "siem_exporter"
            progress.current_module_status = "Exporting to SIEM formats..."
            try:
                from reporting.siem_exporter import SiemExporter
                exporter = SiemExporter()
                exporter.export_all(result)
                live.module_done("siem_exporter", "NDJSON/CEF/Syslog exported [100%]")
                progress.advance_module("siem_exporter", "done")
            except Exception as exc:
                log.error(f"siem_exporter failed: {exc}")
                result.errors.append(f"siem_exporter: {str(exc)}")
                live.module_done("siem_exporter", "ERROR")
                progress.advance_module("siem_exporter", "ERROR")
        else:
            live.module_skipped("siem_exporter", f"skipped ({mode} mode)")

    # Finalize
    completed = datetime.now(timezone.utc)
    result.completed_at = completed.isoformat()
    result.duration_seconds = (completed - started).total_seconds()

    # Cache result
    cache_file = Path("cache") / f"scan_{scan_id}.json"
    cache_file.parent.mkdir(exist_ok=True)
    with open(cache_file, "w") as fh:
        json.dump(result.to_dict(), fh, indent=2)

    live.complete(risk_score=result.threat_score, report_path=report_output_path)

    if result.errors:
        print(f"  {Fore.YELLOW}Errors ({len(result.errors)}):{Style.RESET_ALL}")
        for e in result.errors:
            print(f"    - {e}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BlueSentinel v2.0 — AI-Augmented Threat Detection Platform"
    )
    parser.add_argument("--full-scan", action="store_true", help="Run complete scan (all modules)")
    parser.add_argument("--quick-scan", action="store_true", help="Run quick scan (critical paths only)")
    parser.add_argument("--network-only", action="store_true", help="Network analysis only")
    parser.add_argument("--file-only", action="store_true", help="File/YARA scan only")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard")
    parser.add_argument("--generate-report", action="store_true", help="Generate report from last scan")
    parser.add_argument("--skip-integrity", action="store_true", help="Skip integrity check")
    parser.add_argument("--update-manifest", action="store_true", help="Regenerate integrity manifest")

    args = parser.parse_args()

    if args.update_manifest:
        from core.integrity_check import generate_manifest
        generate_manifest()
        print(f"{Fore.GREEN}[+] Integrity manifest updated.{Style.RESET_ALL}")
        return

    if not args.skip_integrity:
        from core.integrity_check import run_integrity_check
        if not run_integrity_check(auto_update_on_fail=False, require_confirmation=True):
            return

    if args.dashboard:
        from dashboard.app import create_app
        config = get_config()
        app = create_app()
        print(f"{Fore.GREEN}[*] Dashboard starting on http://0.0.0.0:{config.dashboard_port}{Style.RESET_ALL}")
        app.run(host="0.0.0.0", port=config.dashboard_port, debug=False)
        return

    if args.full_scan:
        run_scan("full-scan")
    elif args.quick_scan:
        run_scan("quick-scan")
    elif args.network_only:
        run_scan("network-only")
    elif args.file_only:
        run_scan("file-only")
    elif args.generate_report:
        cache_dir = Path("cache")
        scan_files = sorted(cache_dir.glob("scan_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not scan_files:
            print(f"{Fore.RED}[!] No previous scan results found in cache/{Style.RESET_ALL}")
            return
        with open(scan_files[0]) as fh:
            data = json.load(fh)
        from reporting.html_report_generator import generate_html_report_from_dict
        report_path = generate_html_report_from_dict(data)
        print(f"{Fore.GREEN}[+] Report generated: {report_path}{Style.RESET_ALL}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
