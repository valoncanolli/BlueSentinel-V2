"""
analyzers/beaconing_detector.py
Network beaconing detection using FFT and statistical analysis.
Detects C2 communication patterns via inter-arrival time regularity.
"""
import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

log = logging.getLogger(__name__)

MIN_CONNECTIONS = 6
JITTER_THRESHOLD = 0.20
CONFIDENCE_THRESHOLD = 70


@dataclass
class BeaconingAlert:
    dst_ip: str
    dst_port: int
    src_ip: str
    connection_count: int
    mean_iat_seconds: float
    jitter: float
    confidence: float
    periodic_score: float
    total_bytes: int = 0
    is_ioc_match: bool = False
    ioc_source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "src_ip": self.src_ip,
            "connection_count": self.connection_count,
            "mean_iat_seconds": round(self.mean_iat_seconds, 2),
            "jitter": round(self.jitter, 4),
            "confidence": round(self.confidence, 1),
            "periodic_score": round(self.periodic_score, 3),
            "total_bytes": self.total_bytes,
            "is_ioc_match": self.is_ioc_match,
            "ioc_source": self.ioc_source,
        }


class BeaconingDetector:
    """Detects periodic network beaconing using FFT and statistical methods."""

    def __init__(
        self,
        min_connections: int = MIN_CONNECTIONS,
        jitter_threshold: float = JITTER_THRESHOLD,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
    ) -> None:
        self.min_connections = min_connections
        self.jitter_threshold = jitter_threshold
        self.confidence_threshold = confidence_threshold

    def _parse_tshark_json(self, raw_data: List[Dict]) -> List[Dict[str, Any]]:
        """Parse TShark JSON output into normalized connection records."""
        connections = []
        for pkt in raw_data:
            try:
                layers = pkt.get("_source", {}).get("layers", pkt)
                timestamp = float(
                    layers.get("frame.time_epoch", [0])[0]
                    if isinstance(layers.get("frame.time_epoch"), list)
                    else layers.get("frame.time_epoch", 0)
                )
                src_ip = self._extract_field(layers, "ip.src")
                dst_ip = self._extract_field(layers, "ip.dst")
                dst_port = int(
                    self._extract_field(layers, "tcp.dstport") or
                    self._extract_field(layers, "udp.dstport") or 0
                )
                frame_len = int(self._extract_field(layers, "frame.len") or 0)
                if src_ip and dst_ip and dst_port > 0:
                    connections.append({
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "bytes": frame_len,
                    })
            except (ValueError, TypeError, KeyError):
                continue
        return sorted(connections, key=lambda x: x["timestamp"])

    def _extract_field(self, layers: Dict, field_name: str) -> str:
        val = layers.get(field_name, "")
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""

    def _calculate_periodicity_fft(self, timestamps: List[float]) -> float:
        """Use FFT to detect dominant frequency in connection timing. Returns 0-1 score."""
        if len(timestamps) < 4:
            return 0.0
        iats = np.diff(sorted(timestamps))
        if len(iats) < 3:
            return 0.0
        # Perfect periodicity: all IATs identical (zero variance) → maximum score
        if float(np.std(iats)) == 0.0:
            return 1.0
        n = len(iats)
        fft_vals = np.abs(np.fft.fft(iats - np.mean(iats)))
        freqs = np.fft.fftfreq(n)
        positive_mask = freqs > 0
        if not np.any(positive_mask):
            return 0.0
        pos_fft = fft_vals[positive_mask]
        if pos_fft.sum() == 0:
            return 0.0
        dominant_power = pos_fft.max()
        total_power = pos_fft.sum()
        return float(dominant_power / total_power)

    def _calculate_confidence(
        self,
        conn_count: int,
        jitter: float,
        periodic_score: float,
    ) -> float:
        """
        Confidence score 0-100 based on:
        - Connection count (more = more confident)
        - Low jitter (< 0.20 = beaconing)
        - High FFT periodicity score
        """
        # Connection count contribution (max 20 points — only meaningful with low jitter)
        count_score = min(20, conn_count * 1.5)
        # Jitter contribution (max 50 points — low jitter = high score)
        jitter_score = max(0, 50 * (1 - (jitter / self.jitter_threshold))) if jitter < self.jitter_threshold else 0
        # Periodicity contribution (max 30 points)
        periodic_contrib = periodic_score * 30
        return min(100, count_score + jitter_score + periodic_contrib)

    def analyze(self, traffic_data: Any) -> List[BeaconingAlert]:
        """
        Analyze network traffic for beaconing patterns.
        Input: TShark JSON list or pre-parsed connection list.
        Returns list of BeaconingAlert objects above confidence threshold.
        """
        if not traffic_data:
            return []

        # Parse input
        if isinstance(traffic_data, list) and traffic_data and isinstance(traffic_data[0], dict):
            if "timestamp" in traffic_data[0] and "dst_ip" in traffic_data[0]:
                connections = traffic_data
            else:
                connections = self._parse_tshark_json(traffic_data)
        else:
            log.warning("Unknown traffic data format")
            return []

        # Group by (src_ip, dst_ip, dst_port)
        flows: Dict[str, List[Dict]] = {}
        for conn in connections:
            key = f"{conn['src_ip']}:{conn['dst_ip']}:{conn['dst_port']}"
            flows.setdefault(key, []).append(conn)

        alerts = []
        for flow_key, flow_conns in flows.items():
            if len(flow_conns) < self.min_connections:
                continue

            timestamps = [c["timestamp"] for c in flow_conns]
            iats = np.diff(sorted(timestamps))
            mean_iat = float(np.mean(iats))
            std_iat = float(np.std(iats))

            if mean_iat == 0:
                continue

            jitter = std_iat / mean_iat
            periodic_score = self._calculate_periodicity_fft(timestamps)
            confidence = self._calculate_confidence(len(flow_conns), jitter, periodic_score)

            if confidence >= self.confidence_threshold:
                parts = flow_key.split(":")
                alert = BeaconingAlert(
                    dst_ip=parts[1] if len(parts) >= 2 else flow_conns[0]["dst_ip"],
                    dst_port=flow_conns[0]["dst_port"],
                    src_ip=flow_conns[0]["src_ip"],
                    connection_count=len(flow_conns),
                    mean_iat_seconds=mean_iat,
                    jitter=jitter,
                    confidence=confidence,
                    periodic_score=periodic_score,
                    total_bytes=sum(c.get("bytes", 0) for c in flow_conns),
                )
                alerts.append(alert)
                log.info(
                    f"Beaconing detected: {alert.dst_ip}:{alert.dst_port} "
                    f"confidence={confidence:.1f}% jitter={jitter:.3f}"
                )

        return sorted(alerts, key=lambda a: a.confidence, reverse=True)
