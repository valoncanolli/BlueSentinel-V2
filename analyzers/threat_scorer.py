"""
analyzers/threat_scorer.py
Weighted threat scoring engine for BlueSentinel v2.0.
Aggregates findings from all analyzers into a normalized risk score 0-100.
"""
import logging
from typing import TYPE_CHECKING, Any

log = logging.getLogger(__name__)

# Scoring weights
WEIGHTS = {
    "yara_malware_family": 35,
    "confirmed_beaconing": 30,
    "ioc_match_c2": 25,
    "process_hollowing": 30,
    "suspicious_persistence": 20,
    "event_log_anomaly": 15,
    "unusual_prefetch": 10,
    "encoded_powershell": 20,
    "download_cradle": 25,
    "office_spawn_shell": 20,
    "registry_modification": 15,
}

THRESHOLDS = {
    "critical": 86,
    "high": 61,
    "medium": 31,
    "low": 0,
}


class ThreatScorer:
    """Calculates composite threat score from scan results."""

    def calculate_score(self, result: Any) -> int:
        """
        Calculate threat score 0-100 from ScanResult.
        Uses weighted scoring with diminishing returns above 100.
        """
        raw_score = 0

        # YARA matches
        yara_matches = getattr(result, "yara_matches", [])
        malware_families = [m for m in yara_matches if any(
            tag in str(m.get("rule_tags", [])).lower()
            for tag in ["ransomware", "rat", "backdoor", "loader", "dropper"]
        )]
        if malware_families:
            raw_score += WEIGHTS["yara_malware_family"]
            if len(malware_families) > 2:
                raw_score += 10  # Bonus for multiple hits

        # Beaconing
        beaconing = getattr(result, "beaconing_alerts", [])
        high_conf_beacons = [b for b in beaconing if b.get("confidence", 0) > 70]
        if high_conf_beacons:
            raw_score += WEIGHTS["confirmed_beaconing"]
            if len(high_conf_beacons) > 3:
                raw_score += 10

        # IOC matches
        ioc_matches = getattr(result, "ioc_matches", [])
        c2_iocs = [m for m in ioc_matches if "c2" in str(m.get("category", "")).lower()]
        if c2_iocs:
            raw_score += WEIGHTS["ioc_match_c2"]
        elif ioc_matches:
            raw_score += 15

        # Memory/process findings
        memory = getattr(result, "memory_findings", [])
        hollowing = [p for p in memory if any(
            "UNEXPECTED_PARENT" in f or "DUPLICATE_SINGLETON" in f or "WRONG_PATH" in f
            for f in p.get("suspicious_flags", [])
        )]
        if hollowing:
            raw_score += WEIGHTS["process_hollowing"]

        # Registry
        registry = getattr(result, "registry_findings", [])
        if registry:
            raw_score += WEIGHTS["suspicious_persistence"]

        # Prefetch
        prefetch = getattr(result, "prefetch_findings", [])
        if prefetch:
            raw_score += WEIGHTS["unusual_prefetch"]

        # Alert-based scoring
        alerts = getattr(result, "alerts", [])
        for alert in alerts:
            alert_type = getattr(alert, "alert_type", "")
            if "ENCODED_POWERSHELL" in alert_type:
                raw_score += WEIGHTS["encoded_powershell"]
            elif "DOWNLOAD_CRADLE" in alert_type:
                raw_score += WEIGHTS["download_cradle"]
            elif "OFFICE_SPAWN" in alert_type:
                raw_score += WEIGHTS["office_spawn_shell"]

        # Cap at 100
        final_score = min(100, raw_score)
        category = self.get_category(final_score)
        log.info(f"Threat score: {final_score}/100 ({category})")
        return final_score

    @staticmethod
    def get_category(score: int) -> str:
        if score >= THRESHOLDS["critical"]:
            return "Critical"
        elif score >= THRESHOLDS["high"]:
            return "High"
        elif score >= THRESHOLDS["medium"]:
            return "Medium"
        else:
            return "Low"
