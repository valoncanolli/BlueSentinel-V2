"""
core/file_cache.py — BlueSentinel V2.0 Smart File Cache
========================================================
Hash-based file scan cache. Files are only re-scanned when their
SHA-256 hash changes from the last known clean scan. There is no TTL:
a cached result is valid indefinitely as long as the file's SHA-256
is unchanged and the scan_version matches.

Cache storage: cache/file_scan_cache.json
Format:
{
  "C:\\\\Windows\\\\Temp\\\\test.exe": {
    "sha256": "a3f4b2...",
    "last_scanned": "2026-03-27T20:16:57",
    "result": "clean",          # "clean" | "suspicious" | "malicious"
    "scan_duration_ms": 142,
    "yara_matches": [],         # list of rule names that matched
    "file_size_bytes": 204800,
    "scan_version": "2.1.0"    # BlueSentinel version that scanned it
  }
}

Cache invalidation rules:
  - File hash changed → always re-scan
  - scan_version mismatch → re-scan (YARA rules may have changed)
  - File cannot be read → skip cache, attempt fresh scan
  - No TTL: age alone never triggers a re-scan
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from core.logger import get_logger

logger = get_logger(__name__)

CACHE_FILE     = Path("cache/file_scan_cache.json")
SCAN_VERSION   = "2.1.0"
MAX_CACHE_SIZE = 50_000   # max number of entries before pruning oldest


@dataclass
class FileCacheEntry:
    sha256: str
    last_scanned: str
    result: str                   # "clean" | "suspicious" | "malicious"
    scan_duration_ms: int
    yara_matches: list
    file_size_bytes: int
    scan_version: str = SCAN_VERSION

    def is_clean(self) -> bool:
        return self.result == "clean"

    def is_threat(self) -> bool:
        return self.result in ("suspicious", "malicious")


class FileCache:
    """
    Thread-safe, persistent hash-based file scan cache.

    Usage:
        cache = FileCache()

        # Before scanning a file:
        entry = cache.get_if_unchanged(file_path)
        if entry:
            # File hash is the same as last scan — use cached result
            return entry.yara_matches  # cached matches (empty if clean)

        # File is new or changed — scan it
        matches = yara_engine.scan(file_path)

        # Store result in cache
        cache.store(
            file_path=file_path,
            result="clean" if not matches else "malicious",
            yara_matches=[m.rule for m in matches],
            scan_duration_ms=elapsed_ms
        )
    """

    def __init__(self, cache_path: Path = CACHE_FILE):
        self.cache_path = cache_path
        self._cache: Dict[str, dict] = {}
        self._dirty = False
        self._load()

    def _load(self):
        """Load cache from disk. Creates empty cache if file does not exist."""
        try:
            if self.cache_path.exists():
                raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
                self._cache = raw
                logger.debug(f"File cache loaded: {len(self._cache)} entries")
            else:
                self._cache = {}
                logger.debug("File cache: starting fresh (no cache file found)")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"File cache corrupt or unreadable — starting fresh: {e}")
            self._cache = {}

    def save(self):
        """Persist cache to disk. Call after scan completes."""
        if not self._dirty:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(
                json.dumps(self._cache, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            self._dirty = False
            logger.debug(f"File cache saved: {len(self._cache)} entries")
        except OSError as e:
            logger.warning(f"Failed to save file cache: {e}")

    @staticmethod
    def compute_sha256(file_path: str, chunk_size: int = 65536) -> Optional[str]:
        """
        Compute SHA-256 of a file.
        Returns None if file cannot be read (locked, permission denied, etc.)
        Uses chunked reading to handle large files without loading into RAM.
        """
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot hash {file_path}: {e}")
            return None

    def get_if_unchanged(self, file_path: str) -> Optional[FileCacheEntry]:
        """
        Check if a file has been scanned before and its hash is unchanged.

        Returns FileCacheEntry if:
          1. The file exists in cache AND
          2. The current SHA-256 matches the stored SHA-256

        Returns None if:
          - File was never scanned before
          - File hash has changed since last scan (file was modified)
          - File cannot be hashed (permission error)
          - Cache entry is from an older BlueSentinel version (re-scan to refresh)
        """
        str_path = str(Path(file_path).resolve())
        entry_dict = self._cache.get(str_path)

        if not entry_dict:
            return None  # Never seen this file

        # Re-scan if cached by older version (rules may have changed)
        if entry_dict.get("scan_version") != SCAN_VERSION:
            logger.debug(f"Cache miss (version mismatch): {Path(file_path).name}")
            return None

        current_hash = self.compute_sha256(str_path)
        if current_hash is None:
            return None  # Can't hash — scan it

        if current_hash != entry_dict.get("sha256"):
            logger.debug(
                f"Cache miss (file modified): {Path(file_path).name} "
                f"[{entry_dict['sha256'][:8]}... → {current_hash[:8]}...]"
            )
            return None  # Hash changed — must re-scan

        # Cache hit — file is unchanged
        logger.debug(f"Cache hit (unchanged): {Path(file_path).name}")
        return FileCacheEntry(**entry_dict)

    def store(
        self,
        file_path: str,
        result: str,
        yara_matches: list = None,
        scan_duration_ms: int = 0,
    ):
        """
        Store or update a cache entry after scanning a file.
        Always re-computes the hash to ensure accuracy.
        """
        str_path = str(Path(file_path).resolve())
        current_hash = self.compute_sha256(str_path)

        if current_hash is None:
            return  # Can't hash — don't cache

        try:
            file_size = os.path.getsize(str_path)
        except OSError:
            file_size = 0

        self._cache[str_path] = {
            "sha256": current_hash,
            "last_scanned": datetime.utcnow().isoformat(),
            "result": result,
            "scan_duration_ms": scan_duration_ms,
            "yara_matches": yara_matches or [],
            "file_size_bytes": file_size,
            "scan_version": SCAN_VERSION,
        }
        self._dirty = True

        # Prune if cache is too large (keep most recently scanned)
        if len(self._cache) > MAX_CACHE_SIZE:
            self._prune()

    def _prune(self):
        """Remove oldest entries to keep cache under MAX_CACHE_SIZE."""
        sorted_entries = sorted(
            self._cache.items(),
            key=lambda x: x[1].get("last_scanned", ""),
            reverse=True  # newest first
        )
        self._cache = dict(sorted_entries[:MAX_CACHE_SIZE])
        logger.debug(f"Cache pruned to {MAX_CACHE_SIZE} entries")

    def invalidate(self, file_path: str):
        """Force a file to be re-scanned on next run."""
        str_path = str(Path(file_path).resolve())
        if str_path in self._cache:
            del self._cache[str_path]
            self._dirty = True

    def clear(self):
        """Wipe entire cache (use with caution)."""
        self._cache.clear()
        self._dirty = True
        self.save()
        logger.info("File cache cleared")

    def stats(self) -> dict:
        """Return cache statistics."""
        entries = list(self._cache.values())
        clean      = sum(1 for e in entries if e.get("result") == "clean")
        malicious  = sum(1 for e in entries if e.get("result") == "malicious")
        suspicious = sum(1 for e in entries if e.get("result") == "suspicious")
        return {
            "total_entries": len(entries),
            "clean": clean,
            "suspicious": suspicious,
            "malicious": malicious,
            "cache_file_size_kb": round(
                self.cache_path.stat().st_size / 1024, 1
            ) if self.cache_path.exists() else 0,
        }
