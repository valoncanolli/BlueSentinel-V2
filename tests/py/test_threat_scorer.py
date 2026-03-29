"""
tests/py/test_threat_scorer.py
pytest tests for analyzers/threat_scorer.py

Tests:
  1. YARA match adds correct weight
  2. Beaconing adds correct weight
  3. Multiple findings stack correctly
  4. Empty findings = score 0
  5. Score capped at 100
  6. Severity categories assigned correctly
"""
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# Minimal stub of ScanResult to avoid importing the full orchestrator
# ---------------------------------------------------------------------------

@dataclass
class _FakeScanResult:
    """Minimal stub matching the interface ThreatScorer.calculate_score() expects."""
    yara_matches:     List[Dict[str, Any]] = field(default_factory=list)
    beaconing_alerts: List[Dict[str, Any]] = field(default_factory=list)
    ioc_matches:      List[Dict[str, Any]] = field(default_factory=list)
    memory_findings:  List[Dict[str, Any]] = field(default_factory=list)
    registry_findings: List[Dict[str, Any]] = field(default_factory=list)
    prefetch_findings: List[Dict[str, Any]] = field(default_factory=list)
    alerts:           List[Any]             = field(default_factory=list)


def _malware_yara_match(tag: str = "ransomware") -> Dict[str, Any]:
    return {
        "rule_name":      f"Test_{tag}_Rule",
        "rule_tags":      [tag],
        "file_path":      "/tmp/malicious.exe",
        "matched_strings": [],
        "severity":       "Critical",
        "mitre_technique": "T1486",
    }


def _high_conf_beacon(confidence: float = 85.0) -> Dict[str, Any]:
    return {
        "dst_ip":           "198.51.100.42",
        "dst_port":         4444,
        "src_ip":           "10.0.0.1",
        "connection_count": 10,
        "mean_iat_seconds": 60.0,
        "jitter":           0.02,
        "confidence":       confidence,
        "periodic_score":   0.85,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestYaraMatchWeight:
    def test_ransomware_yara_adds_weight(self):
        """A ransomware YARA match should add WEIGHTS['yara_malware_family'] to the score."""
        from analyzers.threat_scorer import ThreatScorer, WEIGHTS
        scorer = ThreatScorer()
        result = _FakeScanResult(
            yara_matches=[_malware_yara_match("ransomware")]
        )
        score = scorer.calculate_score(result)
        assert score >= WEIGHTS["yara_malware_family"], (
            f"Expected score >= {WEIGHTS['yara_malware_family']}, got {score}"
        )

    def test_rat_yara_adds_weight(self):
        """A RAT YARA match should also add yara_malware_family weight."""
        from analyzers.threat_scorer import ThreatScorer, WEIGHTS
        scorer = ThreatScorer()
        result = _FakeScanResult(yara_matches=[_malware_yara_match("rat")])
        score = scorer.calculate_score(result)
        assert score >= WEIGHTS["yara_malware_family"]

    def test_multiple_malware_families_add_bonus(self):
        """More than 2 malware family matches should add the bonus points."""
        from analyzers.threat_scorer import ThreatScorer, WEIGHTS
        scorer = ThreatScorer()
        result = _FakeScanResult(yara_matches=[
            _malware_yara_match("ransomware"),
            _malware_yara_match("rat"),
            _malware_yara_match("backdoor"),
        ])
        score_single = ThreatScorer().calculate_score(
            _FakeScanResult(yara_matches=[_malware_yara_match("ransomware")])
        )
        score_multi = scorer.calculate_score(result)
        # Multiple families should yield a higher score than a single
        assert score_multi > score_single


class TestBeaconingWeight:
    def test_high_confidence_beacon_adds_weight(self):
        """A high-confidence beacon should add WEIGHTS['confirmed_beaconing']."""
        from analyzers.threat_scorer import ThreatScorer, WEIGHTS
        scorer = ThreatScorer()
        result = _FakeScanResult(beaconing_alerts=[_high_conf_beacon(confidence=85.0)])
        score = scorer.calculate_score(result)
        assert score >= WEIGHTS["confirmed_beaconing"], (
            f"Expected score >= {WEIGHTS['confirmed_beaconing']}, got {score}"
        )

    def test_low_confidence_beacon_below_threshold_not_counted(self):
        """A beacon with confidence ≤ 70 should not trigger confirmed_beaconing weight."""
        from analyzers.threat_scorer import ThreatScorer, WEIGHTS
        scorer = ThreatScorer()
        result = _FakeScanResult(beaconing_alerts=[_high_conf_beacon(confidence=50.0)])
        score = scorer.calculate_score(result)
        # Low-confidence beacon should not add confirmed_beaconing weight
        assert score < WEIGHTS["confirmed_beaconing"], (
            f"Low-confidence beacon should not add full weight, got {score}"
        )

    def test_multiple_high_conf_beacons_add_bonus(self):
        """More than 3 high-confidence beacons should add an extra 10 points."""
        from analyzers.threat_scorer import ThreatScorer, WEIGHTS
        scorer_single = ThreatScorer()
        scorer_multi  = ThreatScorer()

        single_result = _FakeScanResult(beaconing_alerts=[_high_conf_beacon(85)])
        multi_result  = _FakeScanResult(beaconing_alerts=[
            _high_conf_beacon(85), _high_conf_beacon(85),
            _high_conf_beacon(85), _high_conf_beacon(85),
        ])

        score_single = scorer_single.calculate_score(single_result)
        score_multi  = scorer_multi.calculate_score(multi_result)
        assert score_multi >= score_single + 10


class TestMultipleFindingsStack:
    def test_yara_plus_beaconing_stack(self):
        """YARA and beaconing findings should combine to produce a higher score."""
        from analyzers.threat_scorer import ThreatScorer, WEIGHTS
        scorer = ThreatScorer()
        result = _FakeScanResult(
            yara_matches=[_malware_yara_match("ransomware")],
            beaconing_alerts=[_high_conf_beacon(85.0)],
        )
        combined_score = scorer.calculate_score(result)
        expected_min = WEIGHTS["yara_malware_family"] + WEIGHTS["confirmed_beaconing"]
        # Allow for capping at 100
        assert combined_score >= min(100, expected_min), (
            f"Expected combined score >= {min(100, expected_min)}, got {combined_score}"
        )

    def test_all_findings_produce_high_score(self):
        """All major finding types should combine to a high score."""
        from analyzers.threat_scorer import ThreatScorer
        scorer = ThreatScorer()
        result = _FakeScanResult(
            yara_matches=[_malware_yara_match("ransomware"), _malware_yara_match("rat"), _malware_yara_match("backdoor")],
            beaconing_alerts=[_high_conf_beacon(90.0)],
            ioc_matches=[{"indicator": "1.2.3.4", "category": "c2"}],
            registry_findings=[{"key": "HKLM\\...", "value": "malicious.exe"}],
            prefetch_findings=[{"name": "RUNDLL32.EXE", "suspicious": True}],
        )
        score = scorer.calculate_score(result)
        assert score >= 80, f"All findings should produce score ≥ 80, got {score}"


class TestEmptyFindings:
    def test_empty_result_scores_zero(self):
        """No findings should produce a score of 0."""
        from analyzers.threat_scorer import ThreatScorer
        scorer = ThreatScorer()
        result = _FakeScanResult()
        score = scorer.calculate_score(result)
        assert score == 0, f"Empty findings should produce score 0, got {score}"

    def test_non_malware_yara_tags_do_not_score(self):
        """YARA matches with non-malware tags (e.g. 'info') should not add score."""
        from analyzers.threat_scorer import ThreatScorer
        scorer = ThreatScorer()
        result = _FakeScanResult(yara_matches=[{
            "rule_name":      "InfoRule",
            "rule_tags":      ["info"],
            "file_path":      "/tmp/test.txt",
            "matched_strings": [],
            "severity":       "Low",
        }])
        score = scorer.calculate_score(result)
        assert score == 0


class TestScoreCap:
    def test_score_never_exceeds_100(self):
        """Score must be capped at 100 regardless of input."""
        from analyzers.threat_scorer import ThreatScorer
        scorer = ThreatScorer()

        # Pile on every possible finding type
        many_matches = [_malware_yara_match(t) for t in ["ransomware"] * 20]
        many_beacons = [_high_conf_beacon(95.0) for _ in range(10)]
        c2_iocs = [{"indicator": f"1.2.3.{i}", "category": "c2"} for i in range(10)]

        result = _FakeScanResult(
            yara_matches=many_matches,
            beaconing_alerts=many_beacons,
            ioc_matches=c2_iocs,
            registry_findings=[{"key": "k"}],
            prefetch_findings=[{"name": "evil.exe"}],
        )
        score = scorer.calculate_score(result)
        assert score <= 100, f"Score capped at 100, got {score}"
        assert score == 100, f"Expected max score of 100 with overwhelming findings, got {score}"

    def test_score_is_integer(self):
        """Score should be an integer (or int-compatible)."""
        from analyzers.threat_scorer import ThreatScorer
        scorer = ThreatScorer()
        score = scorer.calculate_score(_FakeScanResult(yara_matches=[_malware_yara_match("ransomware")]))
        assert isinstance(score, int)


class TestSeverityCategories:
    """ThreatScorer.get_category() should return correct labels."""

    @pytest.mark.parametrize("score,expected", [
        (0,   "Low"),
        (1,   "Low"),
        (30,  "Low"),
        (31,  "Medium"),
        (60,  "Medium"),
        (61,  "High"),
        (85,  "High"),
        (86,  "Critical"),
        (100, "Critical"),
    ])
    def test_get_category(self, score, expected):
        from analyzers.threat_scorer import ThreatScorer
        result = ThreatScorer.get_category(score)
        assert result == expected, f"Score {score} → expected '{expected}', got '{result}'"

    def test_zero_score_is_low(self):
        from analyzers.threat_scorer import ThreatScorer
        assert ThreatScorer.get_category(0) == "Low"

    def test_critical_boundary(self):
        from analyzers.threat_scorer import ThreatScorer
        assert ThreatScorer.get_category(86) == "Critical"
        assert ThreatScorer.get_category(85) == "High"
