"""
intelligence/abuseipdb_client.py
AbuseIPDB API client for IP reputation lookups.
"""
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

log = logging.getLogger(__name__)
CACHE_DIR = Path(__file__).parent.parent / "cache" / "abuseipdb_cache"
CACHE_TTL = 24 * 3600
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2"


@dataclass
class AbuseIPResult:
    ip: str
    abuse_confidence_score: int
    country_code: str
    isp: str
    total_reports: int
    last_reported_at: Optional[str]
    is_whitelisted: bool
    is_tor: bool
    verdict: str  # CLEAN, SUSPICIOUS, MALICIOUS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "abuse_confidence_score": self.abuse_confidence_score,
            "country_code": self.country_code,
            "isp": self.isp,
            "total_reports": self.total_reports,
            "last_reported_at": self.last_reported_at,
            "is_whitelisted": self.is_whitelisted,
            "is_tor": self.is_tor,
            "verdict": self.verdict,
        }


class AbuseIPDBClient:
    """AbuseIPDB client for IP reputation lookups."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        from core.config_manager import get_config
        cfg = get_config()
        self.api_key = api_key or cfg.abuseipdb_api_key
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, ip: str) -> Path:
        safe = ip.replace(".", "_").replace(":", "_")
        return CACHE_DIR / f"{safe}.json"

    def _get_cached(self, ip: str) -> Optional[Dict]:
        cp = self._cache_path(ip)
        if cp.exists():
            if time.time() - cp.stat().st_mtime < CACHE_TTL:
                try:
                    with open(cp) as fh:
                        return json.load(fh)
                except (json.JSONDecodeError, IOError):
                    pass
        return None

    def lookup_ip(self, ip: str) -> Optional[AbuseIPResult]:
        if not self.api_key:
            log.warning("AbuseIPDB API key not configured")
            return None
        cached = self._get_cached(ip)
        if cached:
            return AbuseIPResult(**cached)
        try:
            resp = requests.get(
                f"{ABUSEIPDB_URL}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
                timeout=10,
            )
            if resp.status_code != 200:
                log.warning(f"AbuseIPDB error {resp.status_code} for {ip}")
                return None
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            verdict = "MALICIOUS" if score >= 75 else ("SUSPICIOUS" if score >= 25 else "CLEAN")
            result = AbuseIPResult(
                ip=ip,
                abuse_confidence_score=score,
                country_code=data.get("countryCode", ""),
                isp=data.get("isp", ""),
                total_reports=data.get("totalReports", 0),
                last_reported_at=data.get("lastReportedAt"),
                is_whitelisted=data.get("isWhitelisted", False),
                is_tor=data.get("isTor", False),
                verdict=verdict,
            )
            cp = self._cache_path(ip)
            with open(cp, "w") as fh:
                json.dump(result.to_dict(), fh)
            return result
        except requests.RequestException as exc:
            log.error(f"AbuseIPDB request failed: {exc}")
            return None
