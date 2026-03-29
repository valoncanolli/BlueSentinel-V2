"""
intelligence/otx_client.py
AlienVault OTX (Open Threat Exchange) API client.
Fetches pulses and performs IOC lookups. Stores IOCs to local DB.
"""
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

log = logging.getLogger(__name__)
CACHE_DIR = Path(__file__).parent.parent / "cache"
OTX_BASE = "https://otx.alienvault.com/api/v1"
PULSE_CACHE_TTL = 6 * 3600


class OTXClient:
    """AlienVault OTX client for pulse and IOC intelligence."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        from core.config_manager import get_config
        cfg = get_config()
        self.api_key = api_key or cfg.otx_api_key
        self._session = requests.Session()
        if self.api_key:
            self._session.headers.update({"X-OTX-API-KEY": self.api_key})
        CACHE_DIR.mkdir(exist_ok=True)

    def _get(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        if not self.api_key:
            return None
        try:
            resp = self._session.get(f"{OTX_BASE}/{endpoint}", params=params, timeout=20)
            if resp.status_code == 200:
                return resp.json()
            log.warning(f"OTX API {resp.status_code}: {endpoint}")
        except requests.RequestException as exc:
            log.warning(f"OTX request failed: {exc}")
        return None

    def get_latest_pulses(self, days: int = 1) -> List[Dict[str, Any]]:
        """Fetch recent OTX pulses from the last N days."""
        cache_file = CACHE_DIR / "otx_pulses.json"
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < PULSE_CACHE_TTL:
                try:
                    with open(cache_file) as fh:
                        return json.load(fh)
                except (json.JSONDecodeError, IOError):
                    pass

        data = self._get("pulses/subscribed", {"modified_since": f"{days}d", "limit": "100"})
        if not data:
            return []

        pulses = data.get("results", [])
        try:
            with open(cache_file, "w") as fh:
                json.dump(pulses, fh)
        except IOError:
            pass
        return pulses

    def _lookup_indicator(self, indicator_type: str, indicator: str, section: str = "general") -> Optional[Dict]:
        return self._get(f"indicators/{indicator_type}/{indicator}/{section}")

    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        return self._lookup_indicator("IPv4", ip)

    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        return self._lookup_indicator("domain", domain)

    def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        return self._lookup_indicator("file", file_hash)

    def extract_iocs_from_pulses(self, pulses: List[Dict]) -> List[Dict[str, Any]]:
        """Extract IOC indicators from OTX pulses for local database storage."""
        iocs = []
        for pulse in pulses:
            pulse_name = pulse.get("name", "")
            for indicator in pulse.get("indicators", []):
                iocs.append({
                    "indicator": indicator.get("indicator", ""),
                    "type": indicator.get("type", ""),
                    "source": f"OTX:{pulse_name[:50]}",
                    "confidence": 70,
                    "category": "otx_pulse",
                    "description": pulse_name,
                    "malware_families": pulse.get("malware_families", []),
                })
        return iocs

    def update_ioc_database(self) -> int:
        """Fetch latest pulses and store IOCs to local DB. Returns count added."""
        from analyzers.ioc_matcher import IOCMatcher
        pulses = self.get_latest_pulses(days=7)
        if not pulses:
            return 0
        iocs = self.extract_iocs_from_pulses(pulses)
        matcher = IOCMatcher()
        return matcher.add_iocs(iocs, "OTX")
