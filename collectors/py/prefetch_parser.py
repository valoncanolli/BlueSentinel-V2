"""
collectors/py/prefetch_parser.py
Windows Prefetch file parser — pure Python, no Windows-only dependencies.
Parses C:\\Windows\\Prefetch\\ to extract execution history and flag anomalies.
"""
import logging
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

PREFETCH_DIR = Path("C:/Windows/Prefetch")
SUSPICIOUS_PATHS = [
    "\\temp\\", "\\appdata\\roaming\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\recycle", "\\users\\public\\",
]
REMOVABLE_DRIVE_LETTERS = list("DEFGHIJKLMNOPQRSTUVWXYZ")


def _filetime_to_datetime(filetime: int) -> Optional[str]:
    """Convert Windows FILETIME (100-nanosecond intervals since 1601-01-01) to ISO 8601."""
    if filetime == 0:
        return None
    try:
        epoch_delta = timedelta(microseconds=filetime // 10)
        win_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return (win_epoch + epoch_delta).isoformat()
    except (OverflowError, OSError):
        return None


def _parse_prefetch_v17(data: bytes, filename: str) -> Optional[Dict[str, Any]]:
    """Parse Windows XP/Vista prefetch format (version 17)."""
    if len(data) < 84:
        return None
    try:
        exe_name_bytes = data[16:76]
        exe_name = exe_name_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
        prefetch_hash = struct.unpack_from("<I", data, 76)[0]
        run_count = struct.unpack_from("<I", data, 80)[0]
        last_run = _filetime_to_datetime(struct.unpack_from("<Q", data, 84)[0]) if len(data) > 92 else None
        return {
            "exe_name": exe_name,
            "prefetch_hash": f"{prefetch_hash:08X}",
            "run_count": run_count,
            "last_run_times": [last_run] if last_run else [],
            "loaded_dlls": [],
            "accessed_paths": [],
            "version": 17,
        }
    except struct.error:
        return None


def _parse_prefetch_v26(data: bytes, filename: str) -> Optional[Dict[str, Any]]:
    """Parse Windows 7/8 prefetch format (version 26)."""
    if len(data) < 240:
        return None
    try:
        exe_name_bytes = data[16:76]
        exe_name = exe_name_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
        prefetch_hash = struct.unpack_from("<I", data, 76)[0]
        run_count = struct.unpack_from("<I", data, 208)[0]
        last_run_times = []
        for i in range(min(run_count, 8)):
            offset = 128 + (i * 8)
            if offset + 8 <= len(data):
                ts = struct.unpack_from("<Q", data, offset)[0]
                dt = _filetime_to_datetime(ts)
                if dt:
                    last_run_times.append(dt)
        # Extract string section (paths)
        accessed_paths: List[str] = []
        if len(data) > 84 + 4:
            str_offset = struct.unpack_from("<I", data, 84)[0]
            str_length = struct.unpack_from("<I", data, 88)[0]
            if str_offset + str_length <= len(data):
                raw_str = data[str_offset: str_offset + str_length]
                paths = raw_str.decode("utf-16-le", errors="replace").split("\x00")
                accessed_paths = [p for p in paths if p.strip()][:50]
        return {
            "exe_name": exe_name,
            "prefetch_hash": f"{prefetch_hash:08X}",
            "run_count": run_count,
            "last_run_times": last_run_times,
            "loaded_dlls": [p for p in accessed_paths if p.lower().endswith(".dll")],
            "accessed_paths": accessed_paths,
            "version": 26,
        }
    except struct.error:
        return None


def _parse_prefetch_v30(data: bytes, filename: str) -> Optional[Dict[str, Any]]:
    """Parse Windows 10 prefetch format (version 30)."""
    # Try MAM-compressed (Windows 10 uses MAM compression)
    if data[:4] == b"MAM\x04":
        try:
            import ctypes
            # Try using Python's lznt1 via ctypes on Windows; fallback to raw parse
            # For cross-platform compatibility, attempt raw after decompression header
            data = data[8:]  # Skip MAM header, attempt uncompressed body
        except Exception:
            pass
    # Delegate to v26 parser as format is similar
    return _parse_prefetch_v26(data, filename)


def _parse_prefetch_file(path: Path) -> Optional[Dict[str, Any]]:
    """Parse a single .pf prefetch file."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) < 4:
            return None
        version = struct.unpack_from("<I", data, 0)[0]
        if version == 17:
            result = _parse_prefetch_v17(data, path.name)
        elif version == 26:
            result = _parse_prefetch_v26(data, path.name)
        elif version == 30:
            result = _parse_prefetch_v30(data, path.name)
        else:
            log.debug(f"Unknown prefetch version {version} for {path.name}")
            return None
        if result:
            result["filename"] = path.name
            result["file_size_bytes"] = path.stat().st_size
        return result
    except (IOError, OSError, struct.error) as exc:
        log.debug(f"Failed to parse prefetch file {path}: {exc}")
        return None


def _flag_suspicious_prefetch(entry: Dict[str, Any]) -> List[str]:
    flags = []
    exe = entry.get("exe_name", "").lower()
    paths = [p.lower() for p in entry.get("accessed_paths", [])]

    for sus_path in SUSPICIOUS_PATHS:
        if sus_path in exe:
            flags.append(f"EXECUTED_FROM_SUSPICIOUS_PATH: {exe}")
            break

    for path_str in paths:
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in path_str:
                flags.append(f"ACCESSED_SUSPICIOUS_PATH: {path_str[:100]}")
                break

    # Check for execution from removable drives
    for letter in REMOVABLE_DRIVE_LETTERS:
        if exe.startswith(f"\\device\\harddiskvolume") or exe.lower().startswith(f"{letter.lower()}:\\"):
            if letter in list("EFGHIJKLMNOPQRSTUVWXYZ"):
                flags.append(f"POSSIBLE_REMOVABLE_DRIVE_EXECUTION: {exe[:50]}")
                break

    return flags


def parse_prefetch_directory(prefetch_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Parse all .pf files from the Windows Prefetch directory.
    Returns dict with all entries and flagged suspicious ones.
    """
    scan_dir = prefetch_dir or PREFETCH_DIR
    all_entries = []
    suspicious = []
    errors = []

    if not scan_dir.exists():
        log.warning(f"Prefetch directory not found: {scan_dir}")
        return {"all_entries": [], "suspicious": [], "errors": [f"Directory not found: {scan_dir}"]}

    for pf_file in scan_dir.glob("*.pf"):
        entry = _parse_prefetch_file(pf_file)
        if entry is None:
            errors.append(f"Failed to parse: {pf_file.name}")
            continue
        flags = _flag_suspicious_prefetch(entry)
        entry["suspicious_flags"] = flags
        all_entries.append(entry)
        if flags:
            suspicious.append(entry)

    log.info(f"Prefetch: parsed {len(all_entries)} files, {len(suspicious)} suspicious")
    return {
        "parsed_at": datetime.now(timezone.utc).isoformat(),
        "total_entries": len(all_entries),
        "suspicious_count": len(suspicious),
        "all_entries": all_entries,
        "suspicious": suspicious,
        "errors": errors,
    }
