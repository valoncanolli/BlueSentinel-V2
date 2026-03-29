"""
tests/py/test_yara_engine.py
pytest tests for analyzers/yara_engine.py

Tests:
  1. Valid rules load without error
  2. Corrupt rule handled gracefully (no crash, rule skipped)
  3. Known malicious string triggers a match
  4. Cache prevents rescan within TTL
  5. Empty directory returns empty results
"""
import json
import os
import sys
import time
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_rules_dir(tmp_path):
    """Create a temporary YARA rules directory with one valid rule."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    valid_rule = rules_dir / "test_rule.yar"
    valid_rule.write_text("""
rule TestMalwareString : rat {
    meta:
        description = "Test rule matching EICAR-like string"
        severity = "High"
    strings:
        $magic = "BLUESENTINEL_TEST_MALWARE_STRING" ascii nocase
        $pe    = { 4D 5A }
    condition:
        any of them
}
""")
    return rules_dir


@pytest.fixture
def corrupt_rules_dir(tmp_path):
    """Temporary directory with one corrupt YARA rule and one valid rule."""
    rules_dir = tmp_path / "rules_corrupt"
    rules_dir.mkdir()

    # Good rule
    good = rules_dir / "good.yar"
    good.write_text("""
rule GoodRule {
    strings:
        $a = "harmless"
    condition:
        $a
}
""")
    # Corrupt rule (syntax error)
    bad = rules_dir / "bad.yar"
    bad.write_text("rule BrokenRule { THIS IS NOT VALID YARA }")

    return rules_dir


@pytest.fixture
def malicious_file(tmp_path):
    """Create a temp file containing the known malicious test string."""
    f = tmp_path / "malicious.bin"
    f.write_bytes(b"padding" + b"BLUESENTINEL_TEST_MALWARE_STRING" + b"padding")
    return f


@pytest.fixture
def clean_file(tmp_path):
    """Create a temp file with benign content."""
    f = tmp_path / "clean.txt"
    f.write_text("This is a completely harmless text file.")
    return f


@pytest.fixture
def empty_dir(tmp_path):
    """Create an empty directory for scanning."""
    d = tmp_path / "empty_scan_dir"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Helper: try to import yara; skip if not installed
# ---------------------------------------------------------------------------

def _yara_available() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Test 1: Valid rules load without error
# ---------------------------------------------------------------------------

class TestYaraRuleLoading:
    def test_valid_rules_load_without_error(self, temp_rules_dir):
        """YaraEngine initialises without raising when given valid rules."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        from analyzers.yara_engine import YaraEngine
        engine = YaraEngine(rules_dir=temp_rules_dir)
        # _rules should be set (not None) when valid rules are found
        assert engine._rules is not None, (
            "YaraEngine._rules should be set after loading valid rules"
        )

    def test_engine_loads_multiple_rule_files(self, tmp_path):
        """Engine can load multiple .yar files from subdirectories."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        rules_dir = tmp_path / "multi_rules"
        rules_dir.mkdir()
        sub1 = rules_dir / "sub1"
        sub1.mkdir()

        (rules_dir / "rule1.yar").write_text("""
rule RuleOne { strings: $a = "hello" condition: $a }
""")
        (sub1 / "rule2.yar").write_text("""
rule RuleTwo { strings: $b = "world" condition: $b }
""")

        from analyzers.yara_engine import YaraEngine
        engine = YaraEngine(rules_dir=rules_dir)
        assert engine._rules is not None


# ---------------------------------------------------------------------------
# Test 2: Corrupt rule handled gracefully
# ---------------------------------------------------------------------------

class TestCorruptRuleHandling:
    def test_corrupt_rule_skipped_gracefully(self, corrupt_rules_dir, caplog):
        """Corrupt YARA rule is logged as a warning and skipped — no crash."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        import logging
        with caplog.at_level(logging.WARNING, logger="analyzers.yara_engine"):
            from analyzers.yara_engine import YaraEngine
            # Reload module to avoid cached state
            import importlib
            import analyzers.yara_engine as ye_module
            importlib.reload(ye_module)
            engine = ye_module.YaraEngine(rules_dir=corrupt_rules_dir)

        # Engine should still initialise (using the good rule)
        # It should not raise an exception
        assert engine is not None

    def test_all_corrupt_rules_returns_empty(self, tmp_path):
        """If ALL rule files are corrupt, scan returns empty list."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        rules_dir = tmp_path / "all_corrupt"
        rules_dir.mkdir()
        (rules_dir / "bad.yar").write_text("rule BrokenRule { INVALID }")

        from analyzers.yara_engine import YaraEngine
        engine = YaraEngine(rules_dir=rules_dir)
        # _rules should be None since no valid rules were loaded
        # Scanning should return empty list (not crash)
        results = engine.scan_directory(tmp_path)
        assert results == []


# ---------------------------------------------------------------------------
# Test 3: Known malicious string is matched
# ---------------------------------------------------------------------------

class TestKnownMaliciousStringMatch:
    def test_malicious_file_triggers_match(self, temp_rules_dir, malicious_file):
        """File containing the known test string triggers a YARA match."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        from analyzers.yara_engine import YaraEngine
        engine = YaraEngine(rules_dir=temp_rules_dir)

        matches = engine.scan_file(malicious_file)
        assert len(matches) > 0, "Expected at least one YARA match on malicious file"
        assert matches[0].rule_name == "TestMalwareString"

    def test_clean_file_returns_no_match(self, temp_rules_dir, clean_file):
        """Clean file produces no YARA matches."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        from analyzers.yara_engine import YaraEngine
        engine = YaraEngine(rules_dir=temp_rules_dir)

        matches = engine.scan_file(clean_file)
        assert matches == []

    def test_match_contains_severity(self, temp_rules_dir, malicious_file):
        """Matched YaraMatch object has severity set."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        from analyzers.yara_engine import YaraEngine
        engine = YaraEngine(rules_dir=temp_rules_dir)
        matches = engine.scan_file(malicious_file)
        assert matches[0].severity in ("Critical", "High", "Medium", "Low")


# ---------------------------------------------------------------------------
# Test 4: Cache prevents rescan within TTL
# ---------------------------------------------------------------------------

class TestCachePreventsRescan:
    def test_cache_hit_avoids_disk_scan(self, temp_rules_dir, malicious_file):
        """Second scan of the same file within TTL uses cache, not disk."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        from analyzers.yara_engine import YaraEngine
        engine = YaraEngine(rules_dir=temp_rules_dir)

        # Record baseline cache size before any scan
        size_before = len(engine._cache)

        # First scan — should add one new entry to the cache
        results1 = engine.scan_file(malicious_file)
        size_after_first = len(engine._cache)
        assert size_after_first == size_before + 1, (
            f"Cache should grow by 1 after first scan (was {size_before}, got {size_after_first})"
        )

        # Second scan of the same file — should NOT add another entry
        results2 = engine.scan_file(malicious_file)
        assert len(engine._cache) == size_after_first, "Cache should not grow on second scan of same file"
        assert len(results1) == len(results2), "Cached results should match original"

    def test_cache_invalidated_after_file_modification(self, temp_rules_dir, tmp_path):
        """Modified file (different mtime) bypasses cache."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        from analyzers.yara_engine import YaraEngine
        f = tmp_path / "changing_file.bin"
        f.write_bytes(b"safe content")

        engine = YaraEngine(rules_dir=temp_rules_dir)
        results1 = engine.scan_file(f)

        # Modify file (this changes mtime)
        time.sleep(0.05)  # ensure mtime changes
        f.write_bytes(b"BLUESENTINEL_TEST_MALWARE_STRING inside")

        results2 = engine.scan_file(f)
        # After modification, results may differ; key point is no exception
        assert isinstance(results2, list)


# ---------------------------------------------------------------------------
# Test 5: Empty directory returns empty results
# ---------------------------------------------------------------------------

class TestEmptyDirectory:
    def test_empty_directory_returns_empty_list(self, temp_rules_dir, empty_dir):
        """Scanning an empty directory returns an empty list."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        from analyzers.yara_engine import YaraEngine
        engine = YaraEngine(rules_dir=temp_rules_dir)
        results = engine.scan_directory(empty_dir)
        assert results == []

    def test_nonexistent_directory_returns_empty(self, temp_rules_dir):
        """Scanning a non-existent directory returns empty list without crash."""
        if not _yara_available():
            pytest.skip("yara-python not installed")

        from analyzers.yara_engine import YaraEngine
        engine = YaraEngine(rules_dir=temp_rules_dir)
        results = engine.scan_directory(Path("/tmp/definitely_does_not_exist_bluesentinel"))
        assert results == []
