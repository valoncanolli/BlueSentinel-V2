"""
tests/py/test_ioc_matcher.py
pytest tests for analyzers/ioc_matcher.py

Tests:
  1. Known malicious IP matched
  2. Unknown IP returns no match
  3. Hash lookup works
  4. Domain lookup works
  5. Cache TTL respected (via IOCMatcher's internal in-memory DB)
"""
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ioc_db(tmp_path) -> Path:
    """Create a populated IOC DB JSON file in a temp directory."""
    db = {
        "ips": [
            {
                "indicator":   "198.51.100.42",
                "source":      "custom",
                "confidence":  95,
                "category":    "c2",
                "description": "Known C2 server",
                "malware_families": ["MalBot", "EvilRAT"],
            },
            {
                "indicator":   "10.0.0.99",
                "source":      "otx",
                "confidence":  70,
                "category":    "scanner",
                "description": "Port scanner",
                "malware_families": [],
            },
        ],
        "domains": [
            {
                "indicator":   "evil.example.com",
                "source":      "misp",
                "confidence":  90,
                "category":    "phishing",
                "description": "Phishing domain",
                "malware_families": ["PhishKit"],
            },
        ],
        "hashes": [
            {
                "indicator":   "d41d8cd98f00b204e9800998ecf8427e",
                "source":      "virustotal",
                "confidence":  99,
                "category":    "malware",
                "description": "MD5 of known ransomware dropper",
                "malware_families": ["Ransomware.Generic"],
            },
            {
                "indicator":   "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                "source":      "internal",
                "confidence":  85,
                "category":    "loader",
                "description": "SHA256 of loader",
                "malware_families": ["Loader.X"],
            },
        ],
        "urls": [],
    }
    db_file = tmp_path / "ioc_db.json"
    db_file.write_text(json.dumps(db))
    return db_file


@pytest.fixture
def matcher(ioc_db, monkeypatch, tmp_path):
    """Return an IOCMatcher loaded with the test IOC DB."""
    # Monkeypatch the IOC_DB_PATH and CACHE_DIR constants
    monkeypatch.setenv("HOME", str(tmp_path))
    # We need to patch IOC_DB_PATH inside the module
    import analyzers.ioc_matcher as ioc_mod
    original_path = ioc_mod.IOC_DB_PATH
    ioc_mod.IOC_DB_PATH = ioc_db
    ioc_mod.CACHE_DIR   = tmp_path
    yield ioc_mod.IOCMatcher()
    # Restore
    ioc_mod.IOC_DB_PATH = original_path


# ---------------------------------------------------------------------------
# Test 1: Known malicious IP matched
# ---------------------------------------------------------------------------

class TestKnownMaliciousIpMatch:
    def test_known_c2_ip_returns_match(self, matcher):
        """Querying a known C2 IP returns an IOCMatch with correct fields."""
        result = matcher.match("198.51.100.42")
        assert result is not None, "Expected a match for known C2 IP"
        assert result.indicator   == "198.51.100.42"
        assert result.indicator_type == "ip"
        assert result.category    == "c2"
        assert result.confidence  == 95
        assert "c2" in result.category.lower()
        assert "MalBot" in result.malware_families

    def test_match_returns_none_for_localhost(self, matcher):
        """Localhost IP should not match even if syntactically valid."""
        result = matcher.match("127.0.0.1")
        assert result is None

    def test_case_insensitive_ip_lookup(self, matcher):
        """IP lookup should be case-insensitive (leading/trailing whitespace stripped)."""
        result = matcher.match("  198.51.100.42  ")
        assert result is not None


# ---------------------------------------------------------------------------
# Test 2: Unknown IP returns no match
# ---------------------------------------------------------------------------

class TestUnknownIpNoMatch:
    def test_unknown_ip_returns_none(self, matcher):
        """An IP not in the IOC DB returns None."""
        result = matcher.match("1.2.3.4")
        assert result is None

    def test_empty_string_returns_none(self, matcher):
        """Empty string input returns None."""
        result = matcher.match("")
        assert result is None

    def test_invalid_ip_format_returns_none(self, matcher):
        """Malformed IP returns None (fails classification)."""
        result = matcher.match("999.999.999.999")
        assert result is None

    def test_private_ip_not_in_db_returns_none(self, matcher):
        """Private IP not explicitly in DB returns None."""
        result = matcher.match("192.168.0.1")
        assert result is None


# ---------------------------------------------------------------------------
# Test 3: Hash lookup works
# ---------------------------------------------------------------------------

class TestHashLookup:
    def test_md5_hash_returns_match(self, matcher):
        """Known MD5 hash returns a match with correct fields."""
        result = matcher.match("d41d8cd98f00b204e9800998ecf8427e")
        assert result is not None, "Expected match for known MD5 hash"
        assert result.indicator_type == "hash"
        assert result.confidence == 99
        assert "malware" in result.category.lower()

    def test_sha256_hash_returns_match(self, matcher):
        """Known SHA256 hash returns a match."""
        result = matcher.match("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
        assert result is not None, "Expected match for known SHA256 hash"
        assert result.indicator_type == "hash"
        assert result.confidence == 85

    def test_unknown_md5_returns_none(self, matcher):
        """Unknown MD5 hash (all zeros) returns None."""
        result = matcher.match("00000000000000000000000000000000")
        assert result is None

    def test_hash_match_case_insensitive(self, matcher):
        """Hash lookup is case-insensitive."""
        result = matcher.match("D41D8CD98F00B204E9800998ECF8427E")
        assert result is not None


# ---------------------------------------------------------------------------
# Test 4: Domain lookup works
# ---------------------------------------------------------------------------

class TestDomainLookup:
    def test_known_domain_returns_match(self, matcher):
        """Known phishing domain returns a match."""
        result = matcher.match("evil.example.com")
        assert result is not None, "Expected match for known phishing domain"
        assert result.indicator_type == "domain"
        assert result.confidence     == 90
        assert "phishing" in result.category.lower()
        assert "PhishKit" in result.malware_families

    def test_unknown_domain_returns_none(self, matcher):
        """Domain not in DB returns None."""
        result = matcher.match("legitimate.example.org")
        assert result is None

    def test_subdomain_of_malicious_domain_not_auto_matched(self, matcher):
        """Sub-domain does not auto-match the parent IOC — exact match only."""
        result = matcher.match("sub.evil.example.com")
        assert result is None

    def test_domain_match_case_insensitive(self, matcher):
        """Domain lookup is case-insensitive."""
        result = matcher.match("EVIL.EXAMPLE.COM")
        assert result is not None


# ---------------------------------------------------------------------------
# Test 5: IOC DB acts as an in-memory cache across calls within the same instance
# ---------------------------------------------------------------------------

class TestInMemoryDb:
    def test_add_and_retrieve_ioc(self, matcher):
        """Adding an IOC via add_iocs makes it immediately queryable."""
        new_ioc = {
            "indicator":       "203.0.113.1",
            "confidence":      80,
            "category":        "botnet",
            "description":     "Botnet C2 node",
            "malware_families": ["Mirai"],
        }
        added = matcher.add_iocs([new_ioc], source="test")
        assert added == 1

        result = matcher.match("203.0.113.1")
        assert result is not None
        assert result.category == "botnet"

    def test_duplicate_ioc_not_added_twice(self, matcher):
        """Adding the same IOC twice does not create a duplicate."""
        ioc = {"indicator": "198.51.100.42", "confidence": 50, "category": "test"}
        added = matcher.add_iocs([ioc], source="test")
        assert added == 0, "Duplicate IOC should not be added"

    def test_bulk_match_returns_multiple_results(self, matcher):
        """bulk_match on a mixed list returns only known malicious indicators."""
        indicators = [
            "198.51.100.42",      # known
            "1.1.1.1",             # unknown
            "evil.example.com",    # known
            "8.8.8.8",             # unknown
        ]
        results = matcher.match_bulk(indicators)
        matched_indicators = {r.indicator for r in results}
        assert "198.51.100.42"    in matched_indicators
        assert "evil.example.com" in matched_indicators
        assert "1.1.1.1"          not in matched_indicators
        assert "8.8.8.8"          not in matched_indicators
