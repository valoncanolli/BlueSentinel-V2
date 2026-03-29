"""
core/progress.py — BlueSentinel V2.0 CLI Progress Renderer
===========================================================
FINAL implementation. Windows PowerShell safe.

Design:
  - Phase headers: static, print once with newline (never overwritten)
  - Module done lines: static, print once with newline
  - Progress bar: single \r line, updated by background thread
  - File scanning: tqdm handles its own output (progress bar paused during)
  - NO text collision: renderer pauses before any static print
"""

import sys
import re
import time
import shutil
import threading
from dataclasses import dataclass, field
from typing import Optional, List
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True, strip=False, convert=True)

# Ensure UTF-8 output on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, Exception):
    pass

C_CYAN  = '\033[38;2;0;212;255m'
C_GREEN = '\033[38;2;0;255;136m'
C_AMBER = '\033[38;2;255;184;0m'
C_RED   = '\033[38;2;255;59;92m'
C_STEEL = '\033[38;2;122;154;184m'
C_DIM   = '\033[38;2;58;85;112m'
C_WHITE = Fore.WHITE
C_RESET = Style.RESET_ALL
C_BOLD  = Style.BRIGHT

# Keep C alias for orchestrator compatibility
class C:
    TEAL    = C_CYAN
    MATRIX  = C_GREEN
    AMBER   = C_AMBER
    CRIMSON = C_RED
    STEEL   = C_STEEL
    DARK    = C_DIM
    DIM     = C_DIM
    WHITE   = C_WHITE
    RESET   = C_RESET
    BOLD    = C_BOLD
    CYAN    = Fore.CYAN

_ANSI = re.compile(r'\033\[[0-9;]*m')
_SPIN = ['|', '/', '-', '\\']


def _tw() -> int:
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def _vlen(s: str) -> int:
    return len(_ANSI.sub('', s))


def _bar(pct: float, w: int = 24) -> str:
    n = int(w * pct / 100)
    e = w - n
    c = C_GREEN if pct >= 86 else C_AMBER if pct >= 50 else C_CYAN
    return f"{c}{'█' * n}{'░' * e}{C_RESET}"


def _fmt(s: Optional[float]) -> str:
    if s is None:
        return '--:--'
    s = int(s)
    return f"{s//60:02d}:{s%60:02d}" if s < 3600 else f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"


@dataclass
class ScanPhase:
    name: str
    modules: List[str]
    weight: float = 1.0


@dataclass
class ScanProgress:
    phases: List[ScanPhase]
    scan_id: str = ""
    hostname: str = ""
    mode: str = "full-scan"
    ai_provider: str = "OPENAI"
    current_phase_index: int = 0
    current_module: str = ""
    current_module_index: int = 0
    current_module_status: str = ""
    total_modules_done: int = 0
    start_time: float = field(default_factory=time.time)
    phase_start_time: float = field(default_factory=time.time)
    findings_count: int = 0
    suspicious_count: int = 0
    critical_count: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _render_paused: bool = field(default=False, repr=False)

    @property
    def total_modules(self) -> int:
        return sum(len(p.modules) for p in self.phases)

    @property
    def overall_percent(self) -> float:
        if self.total_modules == 0:
            return 0.0
        return min(100.0, self.total_modules_done / self.total_modules * 100.0)

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    @property
    def eta_seconds(self) -> Optional[float]:
        pct = self.overall_percent
        el  = self.elapsed_seconds
        if pct < 5.0 and el < 30:
            return None
        if pct <= 0:
            return None
        return max(0.0, el / (pct / 100.0) - el)

    def advance_module(self, name: str, status: str = ''):
        with self._lock:
            self.total_modules_done += 1
            self.current_module_index += 1
            self.current_module = name
            self.current_module_status = status

    def skip_module(self, name: str):
        with self._lock:
            self.total_modules_done += 1
            self.current_module_index += 1

    def start_phase(self, idx: int):
        with self._lock:
            self.current_phase_index = idx
            self.current_module_index = 0
            self.phase_start_time = time.time()

    def add_finding(self, severity: str = 'medium'):
        with self._lock:
            self.findings_count += 1
            if severity in ('critical', 'high'):
                self.critical_count += 1
            else:
                self.suspicious_count += 1

    def pause_render(self):
        self._render_paused = True

    def resume_render(self):
        self._render_paused = False


class ProgressRenderer:

    def __init__(self, p: ScanProgress):
        self.p = p
        self._spin = 0
        self._bar_line_active = False

    def _clear(self):
        """Clear current line."""
        w = _tw()
        sys.stdout.write('\r' + ' ' * (w - 1) + '\r')
        sys.stdout.flush()

    def _print_static(self, text: str):
        """
        Print a static line (phase header, module done, etc).
        Always clears progress bar first to avoid collision.
        """
        if self._bar_line_active:
            self._clear()
            self._bar_line_active = False
        sys.stdout.write(text + '\n')
        sys.stdout.flush()

    def print_scan_header(self, cache_total=0, cache_clean=0,
                          cache_suspicious=0, cache_malicious=0):
        p = self.p
        print()
        print(f"  {C_STEEL}Scan ID   {C_WHITE}{p.scan_id}{C_RESET}")
        print(f"  {C_STEEL}Host      {C_WHITE}{p.hostname}{C_RESET}")
        print(f"  {C_STEEL}Mode      {C_CYAN}{p.mode}{C_RESET}")
        print(f"  {C_STEEL}AI        {C_WHITE}{p.ai_provider}{C_RESET}")
        print(f"  {C_STEEL}Started   {C_WHITE}{time.strftime('%Y-%m-%d %H:%M:%S UTC')}{C_RESET}")
        print()
        if cache_total > 0:
            print(
                f"  {C_STEEL}File cache   "
                f"{C_WHITE}{cache_total:,} entries  "
                f"{C_GREEN}{cache_clean:,} clean  "
                f"{C_AMBER}{cache_suspicious:,} suspicious  "
                f"{C_RED}{cache_malicious:,} malicious{C_RESET}"
            )
        else:
            print(f"  {C_STEEL}File cache   {C_DIM}empty — all files will be scanned{C_RESET}")
        print()

    def print_phase_header(self, name: str, num: int, total: int):
        w = min(_tw() - 4, 56)
        sep = '─' * w
        self._print_static(f"\n  {C_CYAN}{sep}{C_RESET}")
        self._print_static(f"  {C_CYAN}{C_BOLD}PHASE {num}/{total}: {name}{C_RESET}")
        self._print_static(f"  {C_CYAN}{sep}{C_RESET}\n")

    def print_module_done(self, name: str, status: str):
        name_p = name[:24].ljust(24)
        self._print_static(
            f"  {C_GREEN}✓{C_RESET}  {C_STEEL}{name_p}{C_RESET}  {C_DIM}{status}{C_RESET}"
        )

    def print_module_skipped(self, name: str, reason: str = 'skipped (mode)'):
        name_p = name[:24].ljust(24)
        self._print_static(
            f"  {C_DIM}–  {name_p}  {reason}{C_RESET}"
        )

    def render(self):
        """Render in-place progress bar using \\r. Never prints \\n."""
        if self.p._render_paused:
            return

        p = self.p
        pct  = p.overall_percent
        ela  = _fmt(p.elapsed_seconds)
        eta  = _fmt(p.eta_seconds)
        done = p.total_modules_done
        tot  = p.total_modules
        mod  = (p.current_module or 'initializing')[:16]
        spin = _SPIN[self._spin % 4]
        self._spin += 1

        bar = _bar(pct, 22)
        crit_str = f"  {C_RED}⚠{p.critical_count}{C_RESET}" if p.critical_count else ""

        line = (
            f"  {C_AMBER}{spin}{C_RESET} [{bar}] "
            f"{C_WHITE}{pct:5.1f}%{C_RESET}  "
            f"{C_STEEL}eta{C_RESET} {C_AMBER}{eta}{C_RESET}  "
            f"{C_STEEL}elapsed{C_RESET} {C_WHITE}{ela}{C_RESET}  "
            f"{C_CYAN}{done}/{tot}{C_RESET}  "
            f"{C_DIM}{mod}{C_RESET}{crit_str}"
        )

        # Truncate to terminal width
        if _vlen(line) > _tw() - 1:
            line = (
                f"  {C_AMBER}{spin}{C_RESET} [{bar}] "
                f"{C_WHITE}{pct:5.1f}%{C_RESET}  "
                f"{C_AMBER}{eta}{C_RESET}  "
                f"{C_CYAN}{done}/{tot}{C_RESET}{crit_str}"
            )

        sys.stdout.write('\r' + line)
        sys.stdout.flush()
        self._bar_line_active = True

    def complete(self, risk_score: int = 0, report_path: str = ''):
        self._clear()
        p = self.p
        ela = _fmt(p.elapsed_seconds)
        sc  = C_RED if risk_score >= 86 else C_AMBER if risk_score >= 61 else C_GREEN
        w   = min(_tw() - 4, 56)
        sep = '─' * w
        print()
        print(f"  {C_CYAN}{sep}{C_RESET}")
        print(f"  {C_GREEN}✓{C_RESET}  Scan complete  {C_STEEL}duration{C_RESET} {C_WHITE}{ela}{C_RESET}")
        print(f"  {C_STEEL}   Risk       {sc}{C_BOLD}{risk_score}/100{C_RESET}")
        print(
            f"  {C_STEEL}   Findings   "
            f"{C_WHITE}{p.findings_count} total  "
            f"({C_RED}{p.critical_count} critical"
            f"{C_WHITE} / {C_AMBER}{p.suspicious_count} suspicious{C_WHITE}){C_RESET}"
        )
        if report_path:
            print(f"  {C_STEEL}   Report     {C_CYAN}{report_path}{C_RESET}")
        print(f"  {C_CYAN}{sep}{C_RESET}")
        print()


class LiveRenderer:
    """
    Background thread that calls renderer.render() every 0.1s.

    CRITICAL: Call live.pause() before any module that prints to stdout,
    and live.resume() immediately after. This prevents text collision.

    Usage:
        with LiveRenderer(progress) as live:
            progress.start_phase(0)
            live.phase_started()

            live.pause()
            progress.current_module = "yara_engine"
            result = run_yara_with_tqdm()  # tqdm prints to stdout
            live.resume()

            live.module_done("yara_engine", f"Scanned {n} files")
            progress.advance_module("yara_engine")

        live.complete(risk_score=72, report_path="...")
    """

    def __init__(self, p: ScanProgress, interval: float = 0.10):
        self.p        = p
        self.interval = interval
        self._r       = ProgressRenderer(p)
        self._stop    = threading.Event()
        self._thread  = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        while not self._stop.is_set():
            if not self.p._render_paused:
                self._r.render()
            time.sleep(self.interval)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *args):
        self._stop.set()
        self._thread.join(timeout=1.0)

    def pause(self):
        """Pause bar rendering — call before any stdout output."""
        self.p._render_paused = True
        time.sleep(0.12)  # let current render finish
        self._r._clear()

    def resume(self):
        """Resume bar rendering."""
        self.p._render_paused = False

    def phase_started(self):
        idx = self.p.current_phase_index
        if 0 <= idx < len(self.p.phases):
            ph = self.p.phases[idx]
            self.pause()
            self._r.print_phase_header(ph.name, idx + 1, len(self.p.phases))
            self.resume()

    def module_done(self, name: str, status: str = ''):
        self.pause()
        self._r.print_module_done(name, status)
        self.resume()

    def module_skipped(self, name: str, reason: str = 'skipped (mode)'):
        self.pause()
        self._r.print_module_skipped(name, reason)
        self.resume()

    def print_scan_header(self, **kwargs):
        self._r.print_scan_header(**kwargs)

    def complete(self, risk_score: int = 0, report_path: str = ''):
        self._stop.set()
        self._thread.join(timeout=1.0)
        self._r.complete(risk_score, report_path)


def print_phase_header(title: str) -> None:
    """Standalone helper used by some modules directly."""
    w = min(_tw() - 4, 56)
    sep = '─' * w
    print(f"\n  {C_CYAN}{sep}{C_RESET}")
    print(f"  {C_CYAN}{C_BOLD}{title}{C_RESET}")
    print(f"  {C_CYAN}{sep}{C_RESET}\n")
