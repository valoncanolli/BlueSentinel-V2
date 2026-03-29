"""
intelligence/virustotal_client.py
VirusTotal API v3 client with multi-key rotation, rate limiting, and caching.
Supports hash, IP, domain, and URL lookups.
"""
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from itertools import cycle
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

log = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).parent.parent / "cache" / "vt_cache"
VT_BASE_URL = "https://www.virustotal.com/api/v3"
RATE_LIMIT_FREE = 4  # requests per minute
CACHE_TTL_FILES = 7 * 86400
CACHE_TTL_NETWORK = 24 * 3600


@dataclass
class ThreatIntelResult:
    indicator: str
    indicator_type: str
    malicious_count: int
    suspicious_count: int
    total_engines: int
    verdict: str  # CLEAN, SUSPICIOUS, CONFIRMED_MALICIOUS
    reputation: int
    tags: List[str] = field(default_factory=list)
    malware_names: List[str] = field(default_factory=list)
    last_analysis_date: Optional[str] = None
    source: str = "virustotal"
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "malicious_count": self.malicious_count,
            "suspicious_count": self.suspicious_count,
            "total_engines": self.total_engines,
            "verdict": self.verdict,
            "reputation": self.reputation,
            "tags": self.tags,
            "malware_names": self.malware_names,
            "last_analysis_date": self.last_analysis_date,
            "source": self.source,
        }


class VirusTotalClient:
    """VirusTotal API v3 client with key rotation and caching."""

    def __init__(self, api_keys: Optional[List[str]] = None) -> None:
        from core.config_manager import get_config
        cfg = get_config()
        keys = api_keys or cfg.virustotal_api_keys
        if not keys:
            log.warning("No VirusTotal API keys configured")
            keys = []
        self._keys = list(keys)
        self._key_cycle = cycle(self._keys) if self._keys else None
        self._request_times: List[float] = []
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _get_key(self) -> Optional[str]:
        if not self._key_cycle:
            return None
        return next(self._key_cycle)

    def _rate_limit(self) -> None:
        now = time.time()
        self._request_times = [t for t in self._request_times if now - t < 60]
        if len(self._request_times) >= RATE_LIMIT_FREE:
            sleep_time = 60 - (now - self._request_times[0]) + 0.5
            if sleep_time > 0:
                log.debug(f"VT rate limit: sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)
        self._request_times.append(time.time())

    def _cache_path(self, indicator: str, ttl: int) -> Path:
        key = hashlib.md5(indicator.encode()).hexdigest()
        return CACHE_DIR / f"{key}.json"

    def _get_cached(self, indicator: str, ttl: int) -> Optional[Dict]:
        cache_file = self._cache_path(indicator, ttl)
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < ttl:
                try:
                    with open(cache_file) as fh:
                        return json.load(fh)
                except (json.JSONDecodeError, IOError):
                    pass
        return None

    def _from_cache(self, cached: Dict) -> "ThreatIntelResult":
        """Reconstruct ThreatIntelResult from cached dict, handling field renames."""
        data = {k: v for k, v in cached.items() if k != "raw"}
        # Backwards compat: rename malware_families → malware_names
        if "malware_families" in data and "malware_names" not in data:
            data["malware_names"] = data.pop("malware_families")
        elif "malware_families" in data:
            data.pop("malware_families")
        return ThreatIntelResult(**data, raw={})

    def _save_cache(self, indicator: str, data: Dict) -> None:
        cache_file = self._cache_path(indicator, 0)
        try:
            with open(cache_file, "w") as fh:
                json.dump(data, fh)
        except IOError as exc:
            log.debug(f"VT cache write failed: {exc}")

    def _request(self, endpoint: str) -> Optional[Dict]:
        api_key = self._get_key()
        if not api_key:
            return None
        self._rate_limit()
        headers = {"x-apikey": api_key}
        url = f"{VT_BASE_URL}/{endpoint}"
        for attempt in range(3):
            try:
                resp = requests.get(url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 429:
                    wait = (2 ** attempt) * 15
                    log.warning(f"VT rate limited, waiting {wait}s")
                    time.sleep(wait)
                    api_key = self._get_key()
                    headers["x-apikey"] = api_key
                elif resp.status_code == 404:
                    return None
                else:
                    log.warning(f"VT API error {resp.status_code}: {endpoint}")
                    return None
            except requests.RequestException as exc:
                log.warning(f"VT request failed (attempt {attempt+1}): {exc}")
                time.sleep(2 ** attempt)
        return None

    def _parse_result(self, data: Dict, indicator: str, itype: str) -> ThreatIntelResult:
        attrs = data.get("data", {}).get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        total = sum(last_analysis.values())
        threshold_malicious = 3
        threshold_suspicious = 1
        if malicious >= threshold_malicious:
            verdict = "CONFIRMED_MALICIOUS"
        elif malicious >= threshold_suspicious or suspicious >= 3:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
        malware_names = []
        for engine_result in attrs.get("last_analysis_results", {}).values():
            if engine_result.get("category") == "malicious" and engine_result.get("result"):
                malware_names.append(engine_result["result"])
        malware_names = list(set(malware_names))[:10]
        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=itype,
            malicious_count=malicious,
            suspicious_count=suspicious,
            total_engines=total,
            verdict=verdict,
            reputation=attrs.get("reputation", 0),
            tags=attrs.get("tags", []),
            malware_names=malware_names,
            last_analysis_date=str(attrs.get("last_analysis_date", "")),
            raw=data,
        )

    def lookup_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        cached = self._get_cached(file_hash, CACHE_TTL_FILES)
        if cached:
            return self._from_cache(cached)
        data = self._request(f"files/{file_hash}")
        if not data:
            return None
        result = self._parse_result(data, file_hash, "hash")
        self._save_cache(file_hash, result.to_dict())
        return result

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        cached = self._get_cached(ip, CACHE_TTL_NETWORK)
        if cached:
            return self._from_cache(cached)
        data = self._request(f"ip_addresses/{ip}")
        if not data:
            return None
        result = self._parse_result(data, ip, "ip")
        self._save_cache(ip, result.to_dict())
        return result

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        cached = self._get_cached(domain, CACHE_TTL_NETWORK)
        if cached:
            return self._from_cache(cached)
        data = self._request(f"domains/{domain}")
        if not data:
            return None
        result = self._parse_result(data, domain, "domain")
        self._save_cache(domain, result.to_dict())
        return result

    def lookup_url(self, url: str) -> Optional[ThreatIntelResult]:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        cached = self._get_cached(url, CACHE_TTL_NETWORK)
        if cached:
            return self._from_cache(cached)
        data = self._request(f"urls/{url_id}")
        if not data:
            return None
        result = self._parse_result(data, url, "url")
        self._save_cache(url, result.to_dict())
        return result
