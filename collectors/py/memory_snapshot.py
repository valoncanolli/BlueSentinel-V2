"""
collectors/py/memory_snapshot.py
Process memory and runtime state collector using psutil.
Flags suspicious processes: hollow, no-exe, unusual parents, temp-path executables.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

log = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).parent.parent.parent / "cache"
SUSPICIOUS_PARENTS = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
SUSPICIOUS_PATHS = [
    Path("C:/Windows/Temp"),
    Path("C:/Users"),
    Path("C:/ProgramData"),
    Path("C:/AppData"),
]
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"}
SHELL_PROCESSES = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}


def _is_in_suspicious_path(exe_path: str) -> bool:
    if not exe_path:
        return False
    p = Path(exe_path).as_posix().lower()
    suspicious_patterns = ["/temp/", "/appdata/roaming/", "/appdata/local/temp/", "/downloads/"]
    return any(pat in p for pat in suspicious_patterns)


def _get_process_info(proc: psutil.Process) -> Optional[Dict[str, Any]]:
    try:
        with proc.oneshot():
            info: Dict[str, Any] = {
                "pid": proc.pid,
                "name": proc.name(),
                "status": proc.status(),
                "create_time": datetime.fromtimestamp(proc.create_time(), tz=timezone.utc).isoformat(),
                "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
                "exe": "",
                "cmdline": [],
                "ppid": 0,
                "parent_name": "",
                "open_files": [],
                "connections": [],
            }
            try:
                info["exe"] = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
                pass
            try:
                info["cmdline"] = proc.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                info["ppid"] = proc.ppid()
                parent = proc.parent()
                if parent:
                    info["parent_name"] = parent.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                info["open_files"] = [f.path for f in proc.open_files()[:10]]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                conns = proc.net_connections(kind="all")
                info["connections"] = [
                    {
                        "fd": c.fd,
                        "type": str(c.type),
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                        "status": c.status,
                    }
                    for c in conns[:5]
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass
        return info
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _flag_suspicious(proc_info: Dict[str, Any]) -> List[str]:
    flags = []
    name = proc_info.get("name", "").lower()
    exe = proc_info.get("exe", "")
    parent_name = proc_info.get("parent_name", "").lower()

    if not exe:
        flags.append("NO_EXECUTABLE_PATH")

    if _is_in_suspicious_path(exe):
        flags.append("EXECUTING_FROM_SUSPICIOUS_PATH")

    if parent_name in OFFICE_APPS and name in SHELL_PROCESSES:
        flags.append(f"OFFICE_SPAWNING_SHELL: {parent_name} -> {name}")

    if name in SHELL_PROCESSES:
        cmdline = " ".join(proc_info.get("cmdline", []))
        if "-enc" in cmdline.lower() or "-encodedcommand" in cmdline.lower():
            flags.append("ENCODED_POWERSHELL_COMMAND")
        if "downloadstring" in cmdline.lower() or "downloadfile" in cmdline.lower():
            flags.append("POWERSHELL_DOWNLOAD_CRADLE")
        if "iex" in cmdline.lower() or "invoke-expression" in cmdline.lower():
            flags.append("POWERSHELL_IEX")

    if name == "svchost.exe" and parent_name and parent_name not in {"services.exe", ""}:
        flags.append(f"SVCHOST_UNUSUAL_PARENT: {parent_name}")

    return flags


def collect_memory_snapshot() -> Dict[str, Any]:
    """
    Collect process list with full metadata and flag suspicious processes.
    Saves snapshot to cache/. Returns dict with all_processes and suspicious_processes.
    """
    CACHE_DIR.mkdir(exist_ok=True)
    all_procs = []
    suspicious = []

    for proc in psutil.process_iter():
        info = _get_process_info(proc)
        if info is None:
            continue
        flags = _flag_suspicious(info)
        info["suspicious_flags"] = flags
        all_procs.append(info)
        if flags:
            suspicious.append(info)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    snapshot = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "total_processes": len(all_procs),
        "suspicious_count": len(suspicious),
        "all_processes": all_procs,
        "suspicious_processes": suspicious,
    }

    output_path = CACHE_DIR / f"memory_snapshot_{timestamp}.json"
    with open(output_path, "w") as fh:
        json.dump(snapshot, fh, indent=2)

    log.info(f"Memory snapshot: {len(all_procs)} processes, {len(suspicious)} suspicious")
    return snapshot
