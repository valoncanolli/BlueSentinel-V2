"""
core/integrity_check.py
SHA-256 integrity checking for all Python and PowerShell source files.
Compares against a baseline manifest and alerts on changes.
"""
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict
from core.logger import get_logger

log = get_logger(__name__)
BASE_DIR = Path(__file__).parent.parent
MANIFEST_PATH = BASE_DIR / "config" / "integrity_manifest.json"


def _hash_file(path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _collect_source_files() -> Dict[str, str]:
    results: Dict[str, str] = {}
    for pattern in ("**/*.py", "**/*.ps1"):
        for fp in BASE_DIR.glob(pattern):
            if any(part.startswith(".") for part in fp.parts):
                continue
            rel = str(fp.relative_to(BASE_DIR))
            results[rel] = _hash_file(fp)
    return results


def generate_manifest() -> None:
    """Create or update the integrity baseline manifest."""
    hashes = _collect_source_files()
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_PATH, "w") as fh:
        json.dump(hashes, fh, indent=2, sort_keys=True)
    log.info(f"Integrity manifest generated: {len(hashes)} files", {"path": str(MANIFEST_PATH)})


def verify_integrity(interactive: bool = True) -> bool:
    """
    Compare current file hashes against the baseline manifest.
    Returns True if all files match, False if any have changed.
    On change: logs CRITICAL and optionally prompts user.
    """
    if not MANIFEST_PATH.exists():
        log.warning("No integrity manifest found. Run generate_manifest() to create baseline.")
        return True

    with open(MANIFEST_PATH) as fh:
        baseline: Dict[str, str] = json.load(fh)

    current = _collect_source_files()
    changed = []
    added = []
    removed = []

    for rel_path, current_hash in current.items():
        if rel_path not in baseline:
            added.append(rel_path)
        elif baseline[rel_path] != current_hash:
            changed.append(rel_path)

    for rel_path in baseline:
        if rel_path not in current:
            removed.append(rel_path)

    if not (changed or added or removed):
        log.info("Integrity check PASSED — all files match baseline.")
        return True

    log.critical(
        "INTEGRITY CHECK FAILED",
        {
            "changed_files": changed,
            "added_files": added,
            "removed_files": removed,
        },
    )

    if changed:
        print(f"\n[!] MODIFIED FILES ({len(changed)}):")
        for f in changed:
            print(f"    - {f}")
    if added:
        print(f"\n[!] NEW FILES ({len(added)}):")
        for f in added:
            print(f"    + {f}")
    if removed:
        print(f"\n[!] MISSING FILES ({len(removed)}):")
        for f in removed:
            print(f"    x {f}")

    if interactive:
        answer = input("\n[?] Continue despite integrity failures? (yes/no): ").strip().lower()
        if answer != "yes":
            print("[!] Aborting. Re-run generate_manifest() if changes are intentional.")
            sys.exit(1)
        else:
            generate_manifest()  # auto-update so next run is clean
            log.info("Integrity manifest updated after user confirmation.")

    return False


def check_integrity():
    """
    Return list of violation dicts (type='modified'|'new'|'removed', path=...).
    Empty list means all files match baseline.
    """
    if not MANIFEST_PATH.exists():
        return []

    with open(MANIFEST_PATH) as fh:
        baseline: Dict[str, str] = json.load(fh)

    current = _collect_source_files()
    violations = []

    for rel_path, current_hash in current.items():
        if rel_path not in baseline:
            violations.append({"type": "new", "path": rel_path})
        elif baseline[rel_path] != current_hash:
            violations.append({"type": "modified", "path": rel_path})

    for rel_path in baseline:
        if rel_path not in current:
            violations.append({"type": "removed", "path": rel_path})

    return violations


def run_integrity_check(auto_update_on_fail: bool = False,
                        require_confirmation: bool = True) -> bool:
    """
    Run integrity check. Returns True if OK.

    auto_update_on_fail: if True, regenerate manifest instead of failing
    require_confirmation: if True, ask user before continuing on failure
    """
    violations = check_integrity()

    if not violations:
        log.info("Integrity check PASSED — all files match baseline.")
        return True

    if auto_update_on_fail:
        generate_manifest()
        log.info("Integrity manifest updated automatically")
        return True

    log.critical("INTEGRITY CHECK FAILED")
    modified  = [v for v in violations if v['type'] == 'modified']
    new_files = [v for v in violations if v['type'] == 'new']
    removed   = [v for v in violations if v['type'] == 'removed']

    if modified:
        print(f"\n[!] MODIFIED FILES ({len(modified)}):")
        for v in modified:
            print(f"    - {v['path']}")
    if new_files:
        print(f"\n[!] NEW FILES ({len(new_files)}):")
        for v in new_files:
            print(f"    + {v['path']}")
    if removed:
        print(f"\n[!] MISSING FILES ({len(removed)}):")
        for v in removed:
            print(f"    x {v['path']}")

    if not require_confirmation:
        return False

    response = input("\n[?] Continue despite integrity failures? (yes/no): ").strip().lower()
    if response == 'yes':
        generate_manifest()  # update manifest so next run is clean
        log.info("Integrity manifest updated after user confirmation.")
        return True
    return False
