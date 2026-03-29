"""
tests/py/test_beaconing_detector.py
pytest tests for analyzers/beaconing_detector.py

Tests:
  1. Perfect beaconing (10 conns, 60s interval, ~0% jitter) → confidence ≥ 85
  2. Random intervals → confidence < 30
  3. Fewer than 6 connections → empty result
  4. Mixed traffic → only beaconing flows flagged
"""
import sys
import time
from pathlib import Path
from typing import List, Dict, Any

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# Helpers to build synthetic traffic data
# ---------------------------------------------------------------------------

def _build_perfect_beacon(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    count: int,
    interval_seconds: float,
    jitter_fraction: float = 0.0,
    base_time: float = 1_700_000_000.0,
) -> List[Dict[str, Any]]:
    """Generate synthetic periodic connection records with very low jitter."""
    import random
    records = []
    t = base_time
    for _ in range(count):
        jitter = jitter_fraction * interval_seconds * (random.random() - 0.5)
        records.append({
            "timestamp": t + jitter,
            "src_ip":   src_ip,
            "dst_ip":   dst_ip,
            "dst_port": dst_port,
            "bytes":    512,
        })
        t += interval_seconds
    return records


def _build_random_traffic(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    count: int,
    base_time: float = 1_700_000_000.0,
) -> List[Dict[str, Any]]:
    """Generate synthetic random-interval connection records."""
    import random
    records = []
    t = base_time
    for _ in range(count):
        t += random.uniform(1, 600)  # 1s to 10 min — highly random
        records.append({
            "timestamp": t,
            "src_ip":   src_ip,
            "dst_ip":   dst_ip,
            "dst_port": dst_port,
            "bytes":    random.randint(64, 4096),
        })
    return records


# ---------------------------------------------------------------------------
# Test 1: Perfect beaconing → confidence ≥ 85
# ---------------------------------------------------------------------------

class TestPerfectBeaconing:
    def test_perfect_60s_beacon_confidence_above_85(self):
        """
        10 connections at exactly 60s intervals with 0% jitter
        should produce a beaconing alert with confidence ≥ 85%.
        """
        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector(
            min_connections=6,
            jitter_threshold=0.20,
            confidence_threshold=70.0,  # Lower threshold so we can check the confidence value
        )
        traffic = _build_perfect_beacon(
            src_ip="192.168.1.100",
            dst_ip="198.51.100.42",
            dst_port=4444,
            count=10,
            interval_seconds=60.0,
            jitter_fraction=0.0,
        )
        alerts = detector.analyze(traffic)
        assert len(alerts) > 0, "Expected at least one beaconing alert for perfect 60s beacon"
        top = alerts[0]
        assert top.confidence >= 85.0, (
            f"Expected confidence ≥ 85 for perfect beaconing, got {top.confidence:.2f}"
        )

    def test_beacon_targets_correct_ip(self):
        """Alert should reference the correct destination IP and port."""
        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector(min_connections=6, confidence_threshold=60.0)
        traffic = _build_perfect_beacon(
            src_ip="10.0.0.5",
            dst_ip="203.0.113.99",
            dst_port=8080,
            count=12,
            interval_seconds=30.0,
            jitter_fraction=0.01,
        )
        alerts = detector.analyze(traffic)
        assert len(alerts) > 0
        alert = alerts[0]
        assert alert.dst_ip == "203.0.113.99"
        assert alert.dst_port == 8080

    def test_beacon_includes_connection_count(self):
        """Alert should report correct connection count."""
        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector(min_connections=6, confidence_threshold=60.0)
        traffic = _build_perfect_beacon(
            src_ip="10.0.0.1",
            dst_ip="203.0.113.10",
            dst_port=443,
            count=15,
            interval_seconds=120.0,
        )
        alerts = detector.analyze(traffic)
        assert len(alerts) > 0
        assert alerts[0].connection_count == 15


# ---------------------------------------------------------------------------
# Test 2: Random intervals → confidence < 30
# ---------------------------------------------------------------------------

class TestRandomIntervals:
    def test_random_traffic_confidence_below_30(self):
        """
        Highly irregular inter-arrival times should produce
        no alerts (or alerts with confidence well below 30%).
        """
        import random
        random.seed(42)

        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector(
            min_connections=6,
            jitter_threshold=0.20,
            confidence_threshold=0.0,  # Allow everything through so we can check confidence
        )
        traffic = _build_random_traffic(
            src_ip="192.168.1.50",
            dst_ip="10.10.10.10",
            dst_port=80,
            count=20,
        )
        alerts = detector.analyze(traffic)
        # Either no alerts, or all have confidence < 30
        for alert in alerts:
            assert alert.confidence < 30, (
                f"Random traffic produced unexpected high confidence: {alert.confidence:.2f}"
            )

    def test_default_threshold_filters_random_traffic(self):
        """With default 70% threshold, random traffic produces no alerts."""
        import random
        random.seed(123)

        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector()  # uses defaults
        traffic = _build_random_traffic(
            src_ip="10.1.1.1",
            dst_ip="8.8.8.8",
            dst_port=53,
            count=30,
        )
        alerts = detector.analyze(traffic)
        assert alerts == [], (
            f"Expected no alerts for random traffic, got {len(alerts)}"
        )


# ---------------------------------------------------------------------------
# Test 3: < 6 connections → empty result
# ---------------------------------------------------------------------------

class TestMinConnectionsEnforcement:
    def test_five_connections_returns_empty(self):
        """Exactly 5 connections (below min=6) → empty result regardless of regularity."""
        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector(min_connections=6, confidence_threshold=0.0)
        traffic = _build_perfect_beacon(
            src_ip="10.0.0.1",
            dst_ip="1.2.3.4",
            dst_port=4444,
            count=5,
            interval_seconds=60.0,
        )
        alerts = detector.analyze(traffic)
        assert alerts == [], (
            "Expected empty result for 5 connections (below min_connections=6)"
        )

    def test_exactly_six_connections_is_allowed(self):
        """Exactly 6 connections (at min threshold) should be analysed."""
        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector(min_connections=6, confidence_threshold=0.0)
        traffic = _build_perfect_beacon(
            src_ip="10.0.0.1",
            dst_ip="1.2.3.4",
            dst_port=4444,
            count=6,
            interval_seconds=60.0,
        )
        alerts = detector.analyze(traffic)
        # Not necessarily an alert (confidence depends on FFT with only 6 points),
        # but should not crash
        assert isinstance(alerts, list)

    def test_zero_connections_returns_empty(self):
        """Empty traffic list → empty result."""
        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector()
        alerts = detector.analyze([])
        assert alerts == []

    def test_none_input_returns_empty(self):
        """None input → empty result, no crash."""
        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector()
        alerts = detector.analyze(None)
        assert alerts == []


# ---------------------------------------------------------------------------
# Test 4: Mixed traffic → only beaconing flows flagged
# ---------------------------------------------------------------------------

class TestMixedTrafficDiscrimination:
    def test_only_beaconing_flow_flagged(self):
        """
        Traffic containing one regular beacon flow and one random flow:
        only the beacon flow should be in the results.
        """
        import random
        random.seed(99)

        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector(
            min_connections=6,
            jitter_threshold=0.20,
            confidence_threshold=70.0,
        )

        # Beaconing flow: 12 connections at 60s, 0% jitter
        beacon_traffic = _build_perfect_beacon(
            src_ip="10.0.0.100",
            dst_ip="198.51.100.1",
            dst_port=4444,
            count=12,
            interval_seconds=60.0,
            jitter_fraction=0.0,
        )

        # Random/noisy flow: 15 connections, high variance
        random_traffic = _build_random_traffic(
            src_ip="10.0.0.100",
            dst_ip="192.0.2.50",
            dst_port=80,
            count=15,
        )

        combined = beacon_traffic + random_traffic
        random.shuffle(combined)  # mix the records

        alerts = detector.analyze(combined)

        # Only the beaconing flow should be flagged
        flagged_dsts = {a.dst_ip for a in alerts}
        assert "198.51.100.1" in flagged_dsts, (
            "Expected beacon destination to be flagged"
        )
        assert "192.0.2.50" not in flagged_dsts, (
            "Random flow destination should not be flagged"
        )

    def test_multiple_beacon_flows_all_flagged(self):
        """Two distinct beacon flows should both be detected."""
        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector(min_connections=6, confidence_threshold=70.0)

        traffic = (
            _build_perfect_beacon("10.0.0.1", "198.51.100.1", 4444, 12, 60.0)
            + _build_perfect_beacon("10.0.0.1", "198.51.100.2", 8080, 10, 30.0)
        )

        alerts = detector.analyze(traffic)
        flagged_dsts = {a.dst_ip for a in alerts}
        assert "198.51.100.1" in flagged_dsts
        assert "198.51.100.2" in flagged_dsts

    def test_results_sorted_by_confidence_descending(self):
        """Alerts should be sorted highest confidence first."""
        from analyzers.beaconing_detector import BeaconingDetector
        detector = BeaconingDetector(min_connections=6, confidence_threshold=0.0)
        traffic = (
            _build_perfect_beacon("10.0.0.1", "198.51.100.1", 4444, 20, 60.0, 0.0)
            + _build_perfect_beacon("10.0.0.1", "198.51.100.2", 80,   8,  60.0, 0.15)
        )
        alerts = detector.analyze(traffic)
        if len(alerts) >= 2:
            confidences = [a.confidence for a in alerts]
            assert confidences == sorted(confidences, reverse=True)
