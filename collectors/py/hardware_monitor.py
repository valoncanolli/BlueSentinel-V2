"""
hardware_monitor.py — Real-time hardware and system resource monitoring.

Collects: CPU usage/temperature, RAM, disk I/O, network interface stats,
          open ports, active connections with threat classification
          (legitimate/suspicious/malicious).

Author: Valon Canolli — Cyber Security Engineer
"""

import ipaddress
import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil

log = logging.getLogger(__name__)

# ── Classification constants ────────────────────────────────────────────────

LEGITIMATE_PORTS: Dict[int, str] = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    3389: "RDP",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    5000: "Flask-Dashboard",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    49152: "Windows-Dynamic",
    49153: "Windows-Dynamic",
}

SUSPICIOUS_PORTS: Dict[int, str] = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite/Back Orifice",
    12345: "NetBus",
    6667: "IRC C2",
    6666: "IRC C2 alt",
    9001: "Tor",
    9050: "Tor SOCKS",
    1080: "SOCKS proxy",
    8888: "Jupyter/common backdoor",
    2222: "Alt SSH backdoor",
    4545: "Common RAT port",
    5555: "Android Debug Bridge / RAT",
    7777: "Common backdoor",
    65535: "Common backdoor",
}

# Private IP ranges for classification
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

COLOR_GREEN = "#00ff88"
COLOR_YELLOW = "#ffb800"
COLOR_RED = "#ff3b5c"


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class ConnectionInfo:
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    pid: int
    process_name: str
    process_path: str
    classification: str       # "legitimate", "suspicious", "malicious"
    classification_reason: str
    color: str                # "#00ff88", "#ffb800", "#ff3b5c"
    bytes_sent: int
    bytes_recv: int
    duration_seconds: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Helper functions ─────────────────────────────────────────────────────────

def _is_private_ip(addr: str) -> bool:
    """Return True if addr is a private/loopback/link-local IP."""
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _safe_proc_info(pid: int) -> Tuple[str, str]:
    """Return (process_name, process_path) for a PID; handles access denial."""
    try:
        p = psutil.Process(pid)
        name = p.name()
        try:
            path = p.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            path = ""
        return name, path
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown", ""


# ── Main class ───────────────────────────────────────────────────────────────

class HardwareMonitor:
    """
    Real-time hardware and system resource monitor.

    Usage::

        hm = HardwareMonitor()
        snapshot = hm.collect_snapshot()      # one-shot
        hm.start_background_thread(socketio)  # continuous Socket.IO emission
    """

    HISTORY_LEN = 60  # points (each ≈ 2 seconds → 2-minute window)

    def __init__(self) -> None:
        self._cpu_history: deque = deque(maxlen=self.HISTORY_LEN)
        self._ram_history: deque = deque(maxlen=self.HISTORY_LEN)
        # baseline counters for delta calculations
        self._prev_disk_io = psutil.disk_io_counters()
        self._prev_net_io = psutil.net_io_counters(pernic=True)
        self._prev_time = time.monotonic()
        self._ioc_ips: set = self._load_ioc_ips()
        self._conn_start_times: Dict[Tuple, float] = {}  # (laddr, raddr) → epoch

    # ── IOC DB ──────────────────────────────────────────────────────────────

    def _load_ioc_ips(self) -> set:
        """Load malicious IPs from local IOC cache for offline matching."""
        ioc_path = Path(__file__).parent.parent.parent / "cache" / "ioc_db.json"
        ips: set = set()
        try:
            if ioc_path.exists():
                with open(ioc_path) as fh:
                    db = json.load(fh)
                for entry in db.get("ips", []):
                    if isinstance(entry, dict):
                        ips.add(entry.get("indicator", ""))
                    elif isinstance(entry, str):
                        ips.add(entry)
        except Exception as exc:
            log.debug("IOC DB load skipped: %s", exc)
        return ips

    # ── CPU ─────────────────────────────────────────────────────────────────

    def _collect_cpu(self) -> Dict[str, Any]:
        overall = psutil.cpu_percent(interval=None)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        self._cpu_history.append(round(overall, 1))

        temperature: Optional[float] = None
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for key in ("coretemp", "cpu_thermal", "k10temp", "acpitz"):
                    if key in temps and temps[key]:
                        temperature = round(temps[key][0].current, 1)
                        break
        except AttributeError:
            # sensors_temperatures() not available on Windows
            pass
        except Exception:
            pass

        freq = psutil.cpu_freq()
        return {
            "percent": round(overall, 1),
            "per_core": [round(c, 1) for c in per_core],
            "temperature": temperature,
            "frequency_mhz": round(freq.current) if freq else None,
            "frequency_min_mhz": round(freq.min) if freq else None,
            "frequency_max_mhz": round(freq.max) if freq else None,
            "process_count": len(psutil.pids()),
            "thread_count": sum(p.num_threads() for p in psutil.process_iter(["num_threads"])
                                if p.info.get("num_threads")),
            "history": list(self._cpu_history),
        }

    # ── RAM ─────────────────────────────────────────────────────────────────

    def _collect_ram(self) -> Dict[str, Any]:
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        used_gb = round(mem.used / 1e9, 2)
        total_gb = round(mem.total / 1e9, 2)
        self._ram_history.append(round(mem.percent, 1))

        top_procs = []
        for p in sorted(psutil.process_iter(["pid", "name", "memory_info"]),
                        key=lambda x: (x.info.get("memory_info") or psutil._common.pmem(0, 0)).rss,
                        reverse=True)[:10]:
            try:
                mi = p.info.get("memory_info")
                if mi:
                    top_procs.append({
                        "pid": p.info["pid"],
                        "name": p.info["name"],
                        "mb": round(mi.rss / 1e6, 1),
                    })
            except Exception:
                pass

        return {
            "total_gb": total_gb,
            "used_gb": used_gb,
            "available_gb": round(mem.available / 1e9, 2),
            "free_gb": round(mem.free / 1e9, 2),
            "percent": round(mem.percent, 1),
            "swap_total_gb": round(swap.total / 1e9, 2),
            "swap_used_gb": round(swap.used / 1e9, 2),
            "swap_percent": round(swap.percent, 1),
            "top_processes": top_procs,
            "history": list(self._ram_history),
        }

    # ── Disk ─────────────────────────────────────────────────────────────────

    def _collect_disk(self) -> Dict[str, Any]:
        now = time.monotonic()
        elapsed = max(now - self._prev_time, 0.001)

        current_io = psutil.disk_io_counters()
        read_mbps = 0.0
        write_mbps = 0.0
        suspicious_activity = False

        if self._prev_disk_io and current_io:
            read_bytes = current_io.read_bytes - self._prev_disk_io.read_bytes
            write_bytes = current_io.write_bytes - self._prev_disk_io.write_bytes
            read_mbps = round(read_bytes / elapsed / 1e6, 2)
            write_mbps = round(write_bytes / elapsed / 1e6, 2)
            if write_mbps > 500:
                suspicious_activity = True
                log.warning("SUSPICIOUS: Disk write rate %.1f MB/s — possible ransomware activity", write_mbps)

        self._prev_disk_io = current_io

        drives = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                drives.append({
                    "mount": part.mountpoint,
                    "device": part.device,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / 1e9, 1),
                    "used_gb": round(usage.used / 1e9, 1),
                    "free_gb": round(usage.free / 1e9, 1),
                    "percent": round(usage.percent, 1),
                    "read_mbps": read_mbps,
                    "write_mbps": write_mbps,
                })
            except (PermissionError, OSError):
                pass

        return {
            "drives": drives,
            "total_read_mbps": read_mbps,
            "total_write_mbps": write_mbps,
            "suspicious_activity": suspicious_activity,
        }

    # ── Network interfaces ───────────────────────────────────────────────────

    def _collect_network_interfaces(self) -> List[Dict[str, Any]]:
        now = time.monotonic()
        elapsed = max(now - self._prev_time, 0.001)
        current_net = psutil.net_io_counters(pernic=True)
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        result = []
        for iface, counters in current_net.items():
            prev = self._prev_net_io.get(iface)
            bytes_sent_ps = 0
            bytes_recv_ps = 0
            if prev:
                bytes_sent_ps = int((counters.bytes_sent - prev.bytes_sent) / elapsed)
                bytes_recv_ps = int((counters.bytes_recv - prev.bytes_recv) / elapsed)

            is_up = stats.get(iface, None)
            result.append({
                "name": iface,
                "bytes_sent_ps": max(0, bytes_sent_ps),
                "bytes_recv_ps": max(0, bytes_recv_ps),
                "bytes_sent_total": counters.bytes_sent,
                "bytes_recv_total": counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
                "errors_in": counters.errin,
                "errors_out": counters.errout,
                "drops_in": counters.dropin,
                "drops_out": counters.dropout,
                "is_up": bool(is_up.isup) if is_up else False,
                "speed_mbps": is_up.speed if is_up else 0,
            })

        self._prev_net_io = current_net
        return result

    # ── Connection classification ────────────────────────────────────────────

    def _classify_connection(
        self,
        remote_addr: str,
        remote_port: int,
        local_port: int,
        proc_name: str,
        proc_path: str,
    ) -> Tuple[str, str, str]:
        """
        Returns (classification, reason, color).
        classification: "legitimate" | "suspicious" | "malicious"
        """
        # Check IOC DB first (malicious)
        if remote_addr and remote_addr in self._ioc_ips:
            return "malicious", f"Remote IP {remote_addr} in local IOC database", COLOR_RED

        # Suspicious port on remote side
        if remote_port and remote_port in SUSPICIOUS_PORTS:
            desc = SUSPICIOUS_PORTS[remote_port]
            return "malicious", f"Remote port {remote_port} ({desc})", COLOR_RED

        # Suspicious port on local side (listening)
        if local_port and local_port in SUSPICIOUS_PORTS:
            desc = SUSPICIOUS_PORTS[local_port]
            return "malicious", f"Local port {local_port} ({desc})", COLOR_RED

        # External IP + non-standard port = suspicious
        if remote_addr and not _is_private_ip(remote_addr):
            if remote_port and remote_port not in LEGITIMATE_PORTS:
                return (
                    "suspicious",
                    f"External IP {remote_addr} on non-standard port {remote_port}",
                    COLOR_YELLOW,
                )

        # Process executing from suspicious path
        suspicious_proc_paths = ("\\temp\\", "\\tmp\\", "\\appdata\\roaming\\", "\\downloads\\")
        if proc_path:
            lp = proc_path.lower()
            for sp in suspicious_proc_paths:
                if sp in lp:
                    return (
                        "suspicious",
                        f"Process {proc_name!r} running from suspicious path",
                        COLOR_YELLOW,
                    )

        return "legitimate", LEGITIMATE_PORTS.get(remote_port or local_port, "Standard port"), COLOR_GREEN

    # ── Connections ──────────────────────────────────────────────────────────

    def _collect_connections(self) -> List[ConnectionInfo]:
        connections: List[ConnectionInfo] = []
        now = time.time()

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except Exception as exc:
            log.warning("net_connections failed: %s", exc)
            return []

        for conn in raw_conns:
            try:
                laddr = conn.laddr.ip if conn.laddr else ""
                lport = conn.laddr.port if conn.laddr else 0
                raddr = conn.raddr.ip if conn.raddr else ""
                rport = conn.raddr.port if conn.raddr else 0
                pid = conn.pid or 0

                proc_name, proc_path = _safe_proc_info(pid) if pid else ("", "")

                key = (laddr, lport, raddr, rport, pid)
                if key not in self._conn_start_times:
                    self._conn_start_times[key] = now
                duration = now - self._conn_start_times[key]

                classification, reason, color = self._classify_connection(
                    raddr, rport, lport, proc_name, proc_path
                )

                connections.append(ConnectionInfo(
                    local_addr=laddr,
                    local_port=lport,
                    remote_addr=raddr,
                    remote_port=rport,
                    status=conn.status or "UNKNOWN",
                    pid=pid,
                    process_name=proc_name,
                    process_path=proc_path,
                    classification=classification,
                    classification_reason=reason,
                    color=color,
                    bytes_sent=0,
                    bytes_recv=0,
                    duration_seconds=round(duration, 1),
                ))
            except Exception as exc:
                log.debug("Connection parse error: %s", exc)

        # Prune stale start times (connections that no longer exist)
        active_keys = {
            (c.laddr.ip if c.laddr else "", c.laddr.port if c.laddr else 0,
             c.raddr.ip if c.raddr else "", c.raddr.port if c.raddr else 0, c.pid or 0)
            for c in raw_conns
        }
        stale = [k for k in self._conn_start_times if k not in active_keys]
        for k in stale:
            del self._conn_start_times[k]

        # Sort: malicious first, then suspicious, then legitimate
        order = {"malicious": 0, "suspicious": 1, "legitimate": 2}
        connections.sort(key=lambda c: order.get(c.classification, 3))
        return connections

    # ── Open ports summary ───────────────────────────────────────────────────

    def _collect_open_ports(self, connections: List[ConnectionInfo]) -> List[Dict[str, Any]]:
        """Derive open-port summary from connection list."""
        seen: Dict[int, Dict] = {}
        for conn in connections:
            port = conn.local_port
            if port and conn.status in ("LISTEN", "ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT"):
                if port not in seen:
                    seen[port] = {
                        "port": port,
                        "process": conn.process_name,
                        "pid": conn.pid,
                        "classification": conn.classification,
                        "color": conn.color,
                        "service": LEGITIMATE_PORTS.get(port,
                                   SUSPICIOUS_PORTS.get(port, "unknown")),
                        "connection_count": 0,
                    }
                seen[port]["connection_count"] += 1

        return sorted(seen.values(), key=lambda p: p["port"])

    # ── Main snapshot ────────────────────────────────────────────────────────

    def collect_snapshot(self) -> Dict[str, Any]:
        """
        Collect a complete hardware + network snapshot.

        Returns a dict ready for JSON serialization / Socket.IO emission.
        """
        cpu = self._collect_cpu()
        ram = self._collect_ram()
        disk = self._collect_disk()
        interfaces = self._collect_network_interfaces()
        connections = self._collect_connections()
        open_ports = self._collect_open_ports(connections)

        # Update time reference AFTER all delta collections
        self._prev_time = time.monotonic()

        return {
            "cpu": cpu,
            "ram": ram,
            "disk": disk,
            "network_interfaces": interfaces,
            "connections": [c.to_dict() for c in connections],
            "open_ports": open_ports,
            "summary": {
                "total_connections": len(connections),
                "malicious_connections": sum(1 for c in connections if c.classification == "malicious"),
                "suspicious_connections": sum(1 for c in connections if c.classification == "suspicious"),
                "legitimate_connections": sum(1 for c in connections if c.classification == "legitimate"),
                "suspicious_disk": disk["suspicious_activity"],
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── Background thread ────────────────────────────────────────────────────

    def start_background_thread(self, socketio: Any, interval: int = 2) -> threading.Thread:
        """
        Start a daemon thread that emits 'hardware_update' via Socket.IO
        every *interval* seconds.

        Args:
            socketio: Flask-SocketIO instance
            interval: emission interval in seconds (default 2)

        Returns:
            The started Thread object.
        """
        def _run() -> None:
            log.info("Hardware monitor background thread started (interval=%ds)", interval)
            while True:
                try:
                    snapshot = self.collect_snapshot()
                    socketio.emit("hardware_update", snapshot)
                except Exception as exc:
                    log.error("hardware_monitor emission error: %s", exc)
                time.sleep(interval)

        t = threading.Thread(target=_run, daemon=True, name="hardware-monitor")
        t.start()
        return t
