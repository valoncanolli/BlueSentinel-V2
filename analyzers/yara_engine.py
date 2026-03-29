"""
analyzers/yara_engine.py
YARA rule engine for file and process memory scanning.
Recursively loads all .yar rules, smart cache to avoid rescanning, handles corrupt rules.
"""
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.file_cache import FileCache

log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent.parent / "rules" / "yara"
CACHE_DIR = Path(__file__).parent.parent / "cache"
CACHE_TTL_SECONDS = 86400  # 24 hours
CACHE_FILE = CACHE_DIR / "yara_scan_cache.json"


@dataclass
class YaraMatch:
    rule_name: str
    rule_tags: List[str]
    file_path: str
    matched_strings: List[Dict[str, Any]]
    severity: str
    mitre_technique: str = ""
    scan_time: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "rule_tags": self.rule_tags,
            "file_path": self.file_path,
            "matched_strings": self.matched_strings,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "scan_time": self.scan_time,
        }


SEVERITY_MAP = {
    "ransomware": "Critical",
    "rat": "Critical",
    "backdoor": "Critical",
    "loader": "High",
    "dropper": "High",
    "c2": "High",
    "persistence": "High",
    "lolbin": "Medium",
    "dns_tunnel": "High",
}

MITRE_MAP = {
    "ransomware": "T1486",
    "rat": "T1219",
    "backdoor": "T1505",
    "loader": "T1055",
    "dropper": "T1055",
    "c2": "T1071",
    "persistence": "T1547",
    "lolbin": "T1218",
    "dns_tunnel": "T1071.004",
}


class YaraEngine:
    """Loads YARA rules and scans files/directories with smart caching."""

    def __init__(self, rules_dir: Optional[Path] = None, use_file_cache: bool = True) -> None:
        self.rules_dir = rules_dir or RULES_DIR
        CACHE_DIR.mkdir(exist_ok=True)
        self._rules = None
        self._cache: Dict[str, Any] = self._load_cache()
        self._load_rules()
        self.file_cache = FileCache() if use_file_cache else None
        self._cache_hits = 0
        self._cache_misses = 0

    def _load_cache(self) -> Dict[str, Any]:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE) as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_cache(self) -> None:
        try:
            with open(CACHE_FILE, "w") as fh:
                json.dump(self._cache, fh)
        except IOError as exc:
            log.error(f"Failed to save YARA cache: {exc}")

    def _load_rules(self) -> None:
        """Load all .yar files recursively, skip corrupt files."""
        try:
            import yara
        except ImportError:
            log.error("yara-python not installed. YARA scanning disabled.")
            return

        rule_files = {}
        for yar_file in self.rules_dir.rglob("*.yar"):
            try:
                yara.compile(str(yar_file))  # Validate
                namespace = yar_file.stem.replace("-", "_").replace(" ", "_")
                rule_files[namespace] = str(yar_file)
            except yara.SyntaxError as exc:
                log.warning(f"Corrupt YARA rule file skipped: {yar_file} — {exc}")
            except Exception as exc:
                log.warning(f"Failed to load YARA rule {yar_file}: {exc}")

        if not rule_files:
            log.warning("No valid YARA rules loaded.")
            return

        try:
            self._rules = yara.compile(filepaths=rule_files)
            log.info(f"Loaded {len(rule_files)} YARA rule files")
        except Exception as exc:
            log.error(f"Failed to compile YARA rules: {exc}")

    def _get_file_key(self, path: Path) -> str:
        stat = path.stat()
        return f"{path}:{stat.st_mtime}:{stat.st_size}"

    def _is_cached(self, file_key: str) -> bool:
        if file_key not in self._cache:
            return False
        cached_time = self._cache[file_key].get("scan_time", 0)
        return (time.time() - cached_time) < CACHE_TTL_SECONDS

    def _get_severity(self, tags: List[str]) -> str:
        for tag in tags:
            tag_lower = tag.lower()
            for key, severity in SEVERITY_MAP.items():
                if key in tag_lower:
                    return severity
        return "Medium"

    def _get_mitre(self, tags: List[str]) -> str:
        for tag in tags:
            tag_lower = tag.lower()
            for key, technique in MITRE_MAP.items():
                if key in tag_lower:
                    return technique
        return ""

    def scan_file(self, file_path: Path, max_size_mb: int = 50, progress=None) -> List[YaraMatch]:
        """Scan a single file. Uses hash-based FileCache to skip unchanged clean files."""
        if self._rules is None:
            return []
        if not file_path.exists() or not file_path.is_file():
            return []

        try:
            size_mb = file_path.stat().st_size / (1024 * 1024)
            if size_mb > max_size_mb:
                log.debug(f"Skipping oversized file: {file_path} ({size_mb:.1f}MB)")
                return []
        except OSError:
            return []

        t_start = time.time()

        # ── Hash-based file cache check ────────────────────────────────────
        if self.file_cache:
            cached = self.file_cache.get_if_unchanged(str(file_path))
            if cached is not None:
                self._cache_hits += 1
                if progress:
                    progress.current_module_status = (
                        f"Cache hit: {file_path.name} [skipped — unchanged]"
                    )
                # Return cached matches reconstructed as YaraMatch objects
                if cached.yara_matches:
                    return [
                        YaraMatch(
                            rule_name=rule_name,
                            rule_tags=[],
                            file_path=str(file_path),
                            matched_strings=[],
                            severity=self._get_severity([]),
                            mitre_technique="",
                        )
                        for rule_name in cached.yara_matches
                    ]
                return []

        self._cache_misses += 1

        # ── mtime-based legacy cache (fast secondary check) ────────────────
        file_key = self._get_file_key(file_path)
        if self._is_cached(file_key):
            cached_matches = self._cache[file_key].get("matches", [])
            return [YaraMatch(**m) for m in cached_matches] if cached_matches else []

        # ── Actual YARA scan ───────────────────────────────────────────────
        matches: List[YaraMatch] = []
        try:
            yara_matches = self._rules.match(str(file_path), timeout=30)
            for m in yara_matches:
                strings = []
                for s in m.strings:
                    strings.append({
                        "identifier": s.identifier,
                        "offset": s.instances[0].offset if s.instances else 0,
                        "data": s.instances[0].matched_data.hex() if s.instances else "",
                    })
                tags = list(m.tags) if m.tags else []
                match = YaraMatch(
                    rule_name=m.rule,
                    rule_tags=tags,
                    file_path=str(file_path),
                    matched_strings=strings[:10],
                    severity=self._get_severity(tags),
                    mitre_technique=self._get_mitre(tags),
                )
                matches.append(match)
        except Exception as exc:
            log.debug(f"YARA scan error on {file_path}: {exc}")

        # ── Store in hash-based file cache ─────────────────────────────────
        if self.file_cache:
            elapsed_ms = int((time.time() - t_start) * 1000)
            result_str = "clean" if not matches else "malicious"
            self.file_cache.store(
                file_path=str(file_path),
                result=result_str,
                yara_matches=[m.rule_name for m in matches] if matches else [],
                scan_duration_ms=elapsed_ms,
            )

        # Store in legacy mtime cache as well
        self._cache[file_key] = {
            "scan_time": time.time(),
            "matches": [m.to_dict() for m in matches],
        }
        self._save_cache()
        return matches

    def scan_directory(self, path=None, directory: Path = None,
                       max_size_mb: int = 50, progress=None,
                       pause_fn=None, resume_fn=None) -> tuple:
        """
        Recursively scan all files in directory.
        Returns (List[YaraMatch], cache_hits, cache_misses).
        pause_fn/resume_fn are called around tqdm output to prevent
        collision with the LiveRenderer progress bar.
        """
        # Accept both path (str) and directory (Path) for compatibility
        if path is not None:
            directory = Path(path)
        if directory is None or not directory.exists():
            return [], 0, 0

        self._cache_hits = 0
        self._cache_misses = 0

        files = [
            f for f in directory.rglob("*")
            if f.is_file() and f.stat().st_size <= max_size_mb * 1024 * 1024
        ]

        if not files:
            return [], 0, 0

        all_matches = []

        # Pause progress bar before tqdm output
        if pause_fn:
            pause_fn()

        try:
            import shutil as _shutil
            from tqdm import tqdm
            bar = tqdm(
                files,
                desc=f"  \033[38;2;0;212;255mScanning files\033[0m",
                unit="file",
                colour="blue",
                bar_format=(
                    "  {desc}: {percentage:3.0f}%|{bar:30}|"
                    " {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
                ),
                ncols=min(_shutil.get_terminal_size().columns - 2, 100),
                leave=True,
            )
            for fp in bar:
                all_matches.extend(self.scan_file(fp, max_size_mb, progress=progress))
        except Exception:
            # Fallback without tqdm
            for fp in files:
                all_matches.extend(self.scan_file(fp, max_size_mb, progress=progress))

        # Resume progress bar after tqdm finishes
        if resume_fn:
            resume_fn()

        # Save hash-based cache after directory scan
        if self.file_cache:
            self.file_cache.save()
            log.info(
                f"YARA scan complete — "
                f"cache hits: {self._cache_hits}, "
                f"misses: {self._cache_misses}"
            )

        return all_matches, self._cache_hits, self._cache_misses

    def scan_process_memory(self, pid: int) -> List[YaraMatch]:
        """Scan process memory using yara-python's process scanning."""
        if self._rules is None:
            return []
        matches: List[YaraMatch] = []
        try:
            yara_matches = self._rules.match(pid=pid, timeout=30)
            for m in yara_matches:
                tags = list(m.tags) if m.tags else []
                match = YaraMatch(
                    rule_name=m.rule,
                    rule_tags=tags,
                    file_path=f"PID:{pid}",
                    matched_strings=[],
                    severity=self._get_severity(tags),
                    mitre_technique=self._get_mitre(tags),
                )
                matches.append(match)
        except Exception as exc:
            log.debug(f"Process memory scan failed (PID {pid}): {exc}")
        return matches
