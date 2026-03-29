"""
analyzers/ioc_matcher.py
IOC (Indicator of Compromise) matching against local and threat intel databases.
Supports IPs, domains, hashes (MD5/SHA1/SHA256), and URLs.
"""
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).parent.parent / "cache"
IOC_DB_PATH = CACHE_DIR / "ioc_db.json"
CUSTOM_IOC_PATH = Path(__file__).parent.parent / "config" / "custom_iocs.txt"
IOC_TTL_SECONDS = 6 * 3600  # 6 hours


@dataclass
class IOCMatch:
    indicator: str
    indicator_type: str  # ip, domain, hash, url
    source: str
    confidence: int  # 0-100
    category: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: str = ""
    malware_families: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "source": self.source,
            "confidence": self.confidence,
            "category": self.category,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "description": self.description,
            "malware_families": self.malware_families,
        }


class IOCMatcher:
    """Matches indicators against local IOC database."""

    def __init__(self) -> None:
        CACHE_DIR.mkdir(exist_ok=True)
        self._db: Dict[str, List[Dict]] = self._load_db()

    def _load_db(self) -> Dict[str, List[Dict]]:
        db: Dict[str, List[Dict]] = {"ips": [], "domains": [], "hashes": [], "urls": []}
        if IOC_DB_PATH.exists():
            try:
                with open(IOC_DB_PATH) as fh:
                    loaded = json.load(fh)
                db.update(loaded)
            except (json.JSONDecodeError, IOError) as exc:
                log.warning(f"Failed to load IOC DB: {exc}")
        # Load custom IOCs
        if CUSTOM_IOC_PATH.exists():
            try:
                with open(CUSTOM_IOC_PATH) as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        ioc_type = self._classify_ioc(line)
                        if ioc_type and ioc_type in db:
                            db[ioc_type].append({
                                "indicator": line,
                                "source": "custom",
                                "confidence": 80,
                                "category": "custom",
                            })
            except IOError as exc:
                log.warning(f"Failed to load custom IOCs: {exc}")
        return db

    def save_db(self) -> None:
        try:
            with open(IOC_DB_PATH, "w") as fh:
                json.dump(self._db, fh, indent=2)
        except IOError as exc:
            log.error(f"Failed to save IOC DB: {exc}")

    @staticmethod
    def _classify_ioc(indicator: str) -> Optional[str]:
        indicator = indicator.strip()
        # IP address
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, indicator):
            return "ips"
        # Hash (MD5/SHA1/SHA256)
        if re.match(r"^[a-fA-F0-9]{32}$", indicator) or \
           re.match(r"^[a-fA-F0-9]{40}$", indicator) or \
           re.match(r"^[a-fA-F0-9]{64}$", indicator):
            return "hashes"
        # URL
        if indicator.startswith(("http://", "https://", "ftp://")):
            return "urls"
        # Domain
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", indicator):
            return "domains"
        return None

    def add_iocs(self, iocs: List[Dict[str, Any]], source: str) -> int:
        """Add new IOCs to the database. Returns count added."""
        added = 0
        for ioc in iocs:
            indicator = ioc.get("indicator", "")
            ioc_type = self._classify_ioc(indicator)
            if not ioc_type:
                continue
            # Check for duplicates
            existing = [e for e in self._db.get(ioc_type, []) if e.get("indicator") == indicator]
            if not existing:
                self._db.setdefault(ioc_type, []).append({
                    "indicator": indicator,
                    "source": source,
                    "confidence": ioc.get("confidence", 70),
                    "category": ioc.get("category", "unknown"),
                    "first_seen": ioc.get("first_seen"),
                    "last_seen": ioc.get("last_seen"),
                    "description": ioc.get("description", ""),
                    "malware_families": ioc.get("malware_families", []),
                })
                added += 1
        if added:
            self.save_db()
        return added

    def match(self, indicator: str) -> Optional[IOCMatch]:
        """Look up a single indicator. Returns IOCMatch if found."""
        indicator = indicator.strip().lower()
        ioc_type = self._classify_ioc(indicator)
        if not ioc_type:
            return None

        for entry in self._db.get(ioc_type, []):
            if entry.get("indicator", "").lower() == indicator:
                _type_map = {"ips": "ip", "domains": "domain", "hashes": "hash", "urls": "url"}
                return IOCMatch(
                    indicator=indicator,
                    indicator_type=_type_map.get(ioc_type, ioc_type),
                    source=entry.get("source", ""),
                    confidence=entry.get("confidence", 50),
                    category=entry.get("category", "unknown"),
                    first_seen=entry.get("first_seen"),
                    last_seen=entry.get("last_seen"),
                    description=entry.get("description", ""),
                    malware_families=entry.get("malware_families", []),
                )
        return None

    def match_bulk(self, indicators: List[str]) -> List[IOCMatch]:
        """Match multiple indicators at once."""
        results = []
        for indicator in indicators:
            match = self.match(indicator)
            if match:
                results.append(match)
        return results
