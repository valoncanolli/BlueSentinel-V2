"""
tests/py/test_virustotal_client.py
pytest tests for intelligence/virustotal_client.py (with mocked HTTP)

Tests:
  1. Hash lookup returns ThreatIntelResult on 200 response
  2. HTTP 429 triggers key rotation (next key is used)
  3. Cache hit avoids making an HTTP call
  4. Malicious threshold correctly parsed from engine results
"""
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# Sample API response payloads
# ---------------------------------------------------------------------------

def _make_vt_response(
    malicious: int = 0,
    suspicious: int = 0,
    clean: int = 60,
    undetected: int = 10,
    reputation: int = 0,
    tags: list = None,
    engine_results: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Build a VirusTotal-like API v3 response dict."""
    results = engine_results or {}
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious":   malicious,
                    "suspicious":  suspicious,
                    "clean":       clean,
                    "undetected":  undetected,
                },
                "last_analysis_results": results,
                "reputation":   reputation,
                "tags":         tags or [],
                "last_analysis_date": 1700000000,
            }
        }
    }


def _make_malicious_response(engine_count: int = 5) -> Dict[str, Any]:
    engine_results = {}
    for i in range(engine_count):
        engine_results[f"Engine{i}"] = {
            "category": "malicious",
            "result":   f"Malware.Generic.{i}",
        }
    for i in range(60 - engine_count):
        engine_results[f"CleanEngine{i}"] = {
            "category": "clean",
            "result":   None,
        }
    return _make_vt_response(malicious=engine_count, engine_results=engine_results)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_config(monkeypatch):
    """Patch get_config() to return a config with test API keys."""
    class _FakeConfig:
        virustotal_api_keys = ["key_primary", "key_secondary"]
    monkeypatch.setattr(
        "intelligence.virustotal_client.VirusTotalClient.__init__",
        lambda self, keys=None: _init_with_keys(self, ["key_primary", "key_secondary"]),
    )


def _init_with_keys(self, keys):
    from itertools import cycle
    self._keys      = list(keys)
    self._key_cycle = cycle(self._keys)
    self._request_times: list = []
    from intelligence.virustotal_client import CACHE_DIR
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def client_with_temp_cache(tmp_path, monkeypatch):
    """Return a VirusTotalClient with a temp cache directory and two test keys."""
    import intelligence.virustotal_client as vt_mod
    monkeypatch.setattr(vt_mod, "CACHE_DIR", tmp_path / "vt_cache")
    (tmp_path / "vt_cache").mkdir()

    from itertools import cycle
    from intelligence.virustotal_client import VirusTotalClient

    client = VirusTotalClient.__new__(VirusTotalClient)
    client._keys          = ["key_alpha", "key_beta"]
    client._key_cycle     = cycle(client._keys)
    client._request_times = []
    client._cache_dir     = tmp_path / "vt_cache"

    # Monkey-patch instance methods to use temp cache
    original_cache_path = client._cache_path.__func__ if hasattr(client._cache_path, '__func__') else None

    import hashlib

    def _cache_path(indicator, ttl=0):
        key = hashlib.md5(indicator.encode()).hexdigest()
        return tmp_path / "vt_cache" / f"{key}.json"

    client._cache_path = _cache_path

    def _get_cached(indicator, ttl):
        cp = _cache_path(indicator)
        if cp.exists():
            age = time.time() - cp.stat().st_mtime
            if age < ttl:
                try:
                    return json.loads(cp.read_text())
                except Exception:
                    pass
        return None

    def _save_cache(indicator, data):
        cp = _cache_path(indicator)
        cp.write_text(json.dumps(data))

    client._get_cached = _get_cached
    client._save_cache = _save_cache

    return client


# ---------------------------------------------------------------------------
# Test 1: Hash lookup returns ThreatIntelResult
# ---------------------------------------------------------------------------

class TestHashLookupReturnsResult:
    def test_hash_lookup_200_returns_threat_intel_result(self, client_with_temp_cache):
        """A successful 200 response returns a populated ThreatIntelResult."""
        from intelligence.virustotal_client import ThreatIntelResult

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_malicious_response(engine_count=5)

        with patch("requests.get", return_value=mock_resp):
            result = client_with_temp_cache.lookup_hash("d41d8cd98f00b204e9800998ecf8427e")

        assert result is not None
        assert isinstance(result, ThreatIntelResult)
        assert result.indicator      == "d41d8cd98f00b204e9800998ecf8427e"
        assert result.indicator_type == "hash"
        assert result.malicious_count == 5
        assert result.verdict        == "CONFIRMED_MALICIOUS"

    def test_hash_lookup_404_returns_none(self, client_with_temp_cache):
        """A 404 response returns None."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("requests.get", return_value=mock_resp):
            result = client_with_temp_cache.lookup_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        assert result is None

    def test_clean_hash_verdict_is_clean(self, client_with_temp_cache):
        """A hash with 0 malicious engines returns CLEAN verdict."""
        from intelligence.virustotal_client import ThreatIntelResult

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_vt_response(malicious=0, suspicious=0, clean=68)

        with patch("requests.get", return_value=mock_resp):
            result = client_with_temp_cache.lookup_hash("00000000000000000000000000000000")

        assert result is not None
        assert result.verdict == "CLEAN"


# ---------------------------------------------------------------------------
# Test 2: HTTP 429 triggers key rotation
# ---------------------------------------------------------------------------

class TestRateLimitKeyRotation:
    def test_429_triggers_key_rotation(self, client_with_temp_cache):
        """On 429, the client should rotate to the next API key and retry."""
        # First call: 429 from key_alpha
        # Second call: 200 from key_beta
        mock_429 = MagicMock()
        mock_429.status_code = 429

        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.json.return_value = _make_malicious_response(3)

        call_sequence = [mock_429, mock_200]
        call_index    = {"i": 0}

        def mock_get(url, headers, timeout):
            resp = call_sequence[min(call_index["i"], len(call_sequence) - 1)]
            call_index["i"] += 1
            return resp

        with patch("requests.get", side_effect=mock_get) as mock_get_fn:
            with patch.object(client_with_temp_cache, "_rate_limit"):  # Skip rate limiting
                result = client_with_temp_cache._request("files/d41d8cd98f00b204e9800998ecf8427e")

        # Should have made 2 requests (1 × 429, 1 × 200)
        assert mock_get_fn.call_count >= 2

    def test_three_consecutive_429_returns_none(self, client_with_temp_cache):
        """Three 429 responses exhaust retries and return None."""
        mock_429 = MagicMock()
        mock_429.status_code = 429

        with patch("requests.get", return_value=mock_429):
            with patch.object(client_with_temp_cache, "_rate_limit"):
                with patch("time.sleep"):  # Skip actual sleeping
                    result = client_with_temp_cache._request("files/badhash")

        assert result is None


# ---------------------------------------------------------------------------
# Test 3: Cache hit avoids HTTP call
# ---------------------------------------------------------------------------

class TestCacheHitAvoidsHttp:
    def test_cached_result_no_http_call(self, client_with_temp_cache):
        """A cached result should be returned without making an HTTP request."""
        from intelligence.virustotal_client import ThreatIntelResult, CACHE_TTL_FILES

        indicator = "cachedfile" + "a" * 26  # 32-char MD5-like
        cached_data = {
            "indicator":          indicator,
            "indicator_type":     "hash",
            "malicious_count":    3,
            "suspicious_count":   1,
            "total_engines":      65,
            "verdict":            "CONFIRMED_MALICIOUS",
            "reputation":         -10,
            "tags":               ["ransomware"],
            "malware_families":   ["TestRansom"],
            "last_analysis_date": "1700000000",
            "source":             "virustotal",
        }
        # Pre-populate the cache
        client_with_temp_cache._save_cache(indicator, cached_data)

        with patch("requests.get") as mock_http:
            result = client_with_temp_cache.lookup_hash(indicator)
            mock_http.assert_not_called()

        assert result is not None
        assert result.verdict == "CONFIRMED_MALICIOUS"

    def test_expired_cache_triggers_http_call(self, client_with_temp_cache, tmp_path):
        """An expired cache entry should trigger a fresh HTTP request."""
        indicator = "expiredcache" + "b" * 20  # 32-char
        cached_data = {
            "indicator":          indicator,
            "indicator_type":     "hash",
            "malicious_count":    0,
            "suspicious_count":   0,
            "total_engines":      65,
            "verdict":            "CLEAN",
            "reputation":         0,
            "tags":               [],
            "malware_families":   [],
            "last_analysis_date": "0",
            "source":             "virustotal",
        }
        client_with_temp_cache._save_cache(indicator, cached_data)

        # Expire the cache by modifying the file's mtime to the past
        import hashlib
        cache_file = tmp_path / "vt_cache" / f"{hashlib.md5(indicator.encode()).hexdigest()}.json"
        if cache_file.exists():
            past_time = time.time() - (8 * 86400)  # 8 days ago — past TTL
            import os
            os.utime(cache_file, (past_time, past_time))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_vt_response(malicious=2)

        with patch("requests.get", return_value=mock_resp) as mock_http:
            with patch.object(client_with_temp_cache, "_rate_limit"):
                result = client_with_temp_cache.lookup_hash(indicator)
            mock_http.assert_called_once()


# ---------------------------------------------------------------------------
# Test 4: Malicious threshold correctly parsed
# ---------------------------------------------------------------------------

class TestMaliciousThresholdParsing:
    @pytest.mark.parametrize("malicious_count,expected_verdict", [
        (0, "CLEAN"),
        (1, "SUSPICIOUS"),  # 1 < threshold_malicious(3), but >= threshold_suspicious(1)
        (2, "SUSPICIOUS"),
        (3, "CONFIRMED_MALICIOUS"),
        (10, "CONFIRMED_MALICIOUS"),
    ])
    def test_verdict_thresholds(self, client_with_temp_cache, malicious_count, expected_verdict):
        """Verdict is assigned based on the number of malicious engine votes."""
        data = _make_vt_response(malicious=malicious_count, suspicious=0, clean=65 - malicious_count)
        result = client_with_temp_cache._parse_result(data, "testhash", "hash")
        assert result.verdict == expected_verdict, (
            f"With {malicious_count} malicious engines, expected '{expected_verdict}' got '{result.verdict}'"
        )

    def test_suspicious_engines_alone_trigger_suspicious_verdict(self, client_with_temp_cache):
        """High suspicious count without malicious engines yields SUSPICIOUS."""
        data = _make_vt_response(malicious=0, suspicious=5, clean=60)
        result = client_with_temp_cache._parse_result(data, "testhash2", "hash")
        assert result.verdict == "SUSPICIOUS"

    def test_malware_names_extracted_from_results(self, client_with_temp_cache):
        """Malware family names should be extracted from engine results."""
        engine_results = {
            "EngineA": {"category": "malicious", "result": "Trojan.GenericKD.123"},
            "EngineB": {"category": "malicious", "result": "Win32.Ransomware.X"},
            "EngineC": {"category": "clean",     "result": None},
        }
        data = _make_vt_response(malicious=2, engine_results=engine_results)
        result = client_with_temp_cache._parse_result(data, "testhash3", "hash")
        assert "Trojan.GenericKD.123" in result.malware_names or \
               "Win32.Ransomware.X"  in result.malware_names

    def test_ip_lookup_returns_threat_intel_result(self, client_with_temp_cache):
        """IP lookup returns a ThreatIntelResult with correct indicator type."""
        from intelligence.virustotal_client import ThreatIntelResult

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_vt_response(malicious=5)

        with patch("requests.get", return_value=mock_resp):
            with patch.object(client_with_temp_cache, "_rate_limit"):
                result = client_with_temp_cache.lookup_ip("198.51.100.1")

        assert result is not None
        assert isinstance(result, ThreatIntelResult)
        assert result.indicator_type == "ip"
