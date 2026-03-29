"""
intelligence/feed_aggregator.py
Async threat intelligence aggregator. Queries multiple sources in parallel.
De-duplicates results and produces consensus verdicts.
"""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

MAX_WORKERS = 10
VERDICT_WEIGHTS = {
    "CONFIRMED_MALICIOUS": 3,
    "MALICIOUS": 3,
    "SUSPICIOUS": 1,
    "CLEAN": 0,
}


@dataclass
class AggregatedResult:
    indicator: str
    verdict: str  # CONFIRMED_MALICIOUS, SUSPICIOUS, CLEAN
    malicious_sources: List[str] = field(default_factory=list)
    suspicious_sources: List[str] = field(default_factory=list)
    source_results: Dict[str, Any] = field(default_factory=dict)
    confidence: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "verdict": self.verdict,
            "malicious_sources": self.malicious_sources,
            "suspicious_sources": self.suspicious_sources,
            "confidence": self.confidence,
        }


class FeedAggregator:
    """Aggregates threat intelligence from multiple providers in parallel."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def _query_vt(self, indicator: str, itype: str) -> Optional[Dict]:
        try:
            from intelligence.virustotal_client import VirusTotalClient
            client = VirusTotalClient()
            method_map = {
                "hash": client.lookup_hash,
                "ip": client.lookup_ip,
                "domain": client.lookup_domain,
                "url": client.lookup_url,
            }
            fn = method_map.get(itype)
            if fn:
                result = fn(indicator)
                return result.to_dict() if result else None
        except Exception as exc:
            log.debug(f"VT query failed: {exc}")
        return None

    def _query_abuseipdb(self, indicator: str, itype: str) -> Optional[Dict]:
        if itype != "ip":
            return None
        try:
            from intelligence.abuseipdb_client import AbuseIPDBClient
            client = AbuseIPDBClient()
            result = client.lookup_ip(indicator)
            return result.to_dict() if result else None
        except Exception as exc:
            log.debug(f"AbuseIPDB query failed: {exc}")
        return None

    def _query_otx(self, indicator: str, itype: str) -> Optional[Dict]:
        try:
            from intelligence.otx_client import OTXClient
            client = OTXClient()
            method_map = {
                "ip": client.lookup_ip,
                "domain": client.lookup_domain,
                "hash": client.lookup_hash,
            }
            fn = method_map.get(itype)
            if fn:
                return fn(indicator)
        except Exception as exc:
            log.debug(f"OTX query failed: {exc}")
        return None

    def _compute_verdict(self, source_results: Dict[str, Any]) -> AggregatedResult:
        malicious = []
        suspicious = []
        total_weight = 0

        for source, result in source_results.items():
            if not result:
                continue
            verdict = result.get("verdict", "CLEAN")
            weight = VERDICT_WEIGHTS.get(verdict, 0)
            total_weight += weight
            if weight >= 3:
                malicious.append(source)
            elif weight >= 1:
                suspicious.append(source)

        if total_weight >= 3 or len(malicious) >= 2:
            verdict = "CONFIRMED_MALICIOUS"
            confidence = min(100, total_weight * 20)
        elif total_weight >= 1 or len(suspicious) >= 1:
            verdict = "SUSPICIOUS"
            confidence = min(80, total_weight * 15)
        else:
            verdict = "CLEAN"
            confidence = 90

        return AggregatedResult(
            indicator="",
            verdict=verdict,
            malicious_sources=malicious,
            suspicious_sources=suspicious,
            source_results=source_results,
            confidence=confidence,
        )

    def lookup(self, indicator: str, indicator_type: str) -> AggregatedResult:
        """Query all sources in parallel. Returns aggregated verdict."""
        queries = {
            "virustotal": (self._query_vt, indicator, indicator_type),
            "abuseipdb": (self._query_abuseipdb, indicator, indicator_type),
            "otx": (self._query_otx, indicator, indicator_type),
        }
        source_results: Dict[str, Any] = {}
        futures = {
            self._executor.submit(fn, ind, itype): name
            for name, (fn, ind, itype) in queries.items()
        }
        for future in as_completed(futures, timeout=30):
            name = futures[future]
            try:
                source_results[name] = future.result()
            except Exception as exc:
                log.debug(f"Source {name} failed: {exc}")
                source_results[name] = None

        result = self._compute_verdict(source_results)
        result.indicator = indicator
        return result

    def lookup_bulk(self, indicators: List[Dict[str, str]]) -> List[AggregatedResult]:
        """
        Bulk lookup of multiple indicators.
        Each item: {"indicator": "...", "type": "ip|domain|hash|url"}
        """
        results = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self.lookup, item["indicator"], item["type"]): item
                for item in indicators[:100]  # cap at 100
            }
            for future in as_completed(futures, timeout=120):
                try:
                    results.append(future.result())
                except Exception as exc:
                    log.warning(f"Bulk lookup failed: {exc}")
        return results
