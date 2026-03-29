"""
intelligence/misp_client.py
MISP (Malware Information Sharing Platform) API client.
Performs IOC lookups and attribute searches.
"""
import logging
from typing import Any, Dict, List, Optional

import requests

log = logging.getLogger(__name__)


class MISPClient:
    """Client for MISP threat intelligence platform."""

    def __init__(self, url: Optional[str] = None, key: Optional[str] = None) -> None:
        from core.config_manager import get_config
        cfg = get_config()
        self.url = (url or cfg.misp_url).rstrip("/")
        self.key = key or cfg.misp_key
        self._session = requests.Session()
        if self.url and self.key:
            self._session.headers.update({
                "Authorization": self.key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
            self._session.verify = False  # Allow self-signed certs in enterprise environments

    def _is_configured(self) -> bool:
        return bool(self.url and self.key)

    def search_attribute(self, value: str, attr_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search MISP for attributes matching the given value."""
        if not self._is_configured():
            return []
        try:
            payload: Dict[str, Any] = {"value": value, "returnFormat": "json"}
            if attr_type:
                payload["type"] = attr_type
            resp = self._session.post(
                f"{self.url}/attributes/restSearch",
                json=payload,
                timeout=15,
            )
            if resp.status_code == 200:
                return resp.json().get("response", {}).get("Attribute", [])
            log.warning(f"MISP search returned {resp.status_code}")
        except requests.RequestException as exc:
            log.warning(f"MISP request failed: {exc}")
        return []

    def lookup_ip(self, ip: str) -> List[Dict[str, Any]]:
        return self.search_attribute(ip, "ip-dst")

    def lookup_domain(self, domain: str) -> List[Dict[str, Any]]:
        return self.search_attribute(domain, "domain")

    def lookup_hash(self, file_hash: str) -> List[Dict[str, Any]]:
        hash_len = len(file_hash)
        type_map = {32: "md5", 40: "sha1", 64: "sha256"}
        return self.search_attribute(file_hash, type_map.get(hash_len, "md5"))

    def get_events(self, days: int = 7) -> List[Dict[str, Any]]:
        """Fetch recent MISP events."""
        if not self._is_configured():
            return []
        try:
            resp = self._session.get(
                f"{self.url}/events/index",
                params={"last": f"{days}d"},
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json() if isinstance(resp.json(), list) else []
        except requests.RequestException as exc:
            log.warning(f"MISP events fetch failed: {exc}")
        return []
