"""
core/notifications.py
ThreatNotification dataclass for real-time threat alerting via Socket.IO.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ThreatNotification:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Classification
    severity: str = "suspicious"        # "suspicious" | "malicious" | "critical"
    confidence: int = 0                 # 0-100

    # What happened
    title: str = ""
    description: str = ""
    technical_detail: str = ""

    # Verdict
    is_confirmed_breach: bool = False
    verdict_reason: str = ""

    # Connection details
    remote_ip: str = ""
    remote_port: int = 0
    local_port: int = 0
    process_name: str = ""
    process_pid: int = 0
    process_path: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    connection_duration: float = 0.0

    # MITRE mapping
    mitre_technique: str = ""
    mitre_tactic: str = ""

    # Actions
    can_kill_process: bool = True
    can_blacklist_ip: bool = True
    is_killed: bool = False
    is_blacklisted: bool = False
    is_acknowledged: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "technical_detail": self.technical_detail,
            "is_confirmed_breach": self.is_confirmed_breach,
            "verdict_reason": self.verdict_reason,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "local_port": self.local_port,
            "process_name": self.process_name,
            "process_pid": self.process_pid,
            "process_path": self.process_path,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "connection_duration": self.connection_duration,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "can_kill_process": self.can_kill_process,
            "can_blacklist_ip": self.can_blacklist_ip,
            "is_killed": self.is_killed,
            "is_blacklisted": self.is_blacklisted,
            "is_acknowledged": self.is_acknowledged,
        }


MALICIOUS_PORTS = {
    4444: "Metasploit default listener",
    31337: "Back Orifice / elite backdoor",
    1337: "Common backdoor port",
    6667: "IRC-based C2 channel",
    6666: "IRC-based C2 channel (alt)",
    9001: "Tor relay port",
    9050: "Tor SOCKS proxy",
    9150: "Tor Browser SOCKS",
    1080: "SOCKS proxy / malware tunnel",
    4545: "Common RAT port",
    5555: "Android Debug Bridge / RAT",
    7777: "Common backdoor",
    8888: "Jupyter / backdoor overlap",
    2222: "Alternate SSH backdoor",
    65535: "Common backdoor (max port)",
    12345: "NetBus RAT",
    54321: "Reverse shell common",
    3333: "Common RAT",
    8443: "Alternate HTTPS / C2 overlap",
}


def evaluate_connection_threat(conn: dict) -> Optional[ThreatNotification]:
    """
    Evaluate a single connection dict and return a ThreatNotification if suspicious.
    Returns None if the connection is classified as legitimate.
    """
    remote_ip = conn.get("remote_addr", "")
    remote_port = conn.get("remote_port", 0)
    process_name = conn.get("process_name", "unknown")
    process_pid = conn.get("pid", 0)
    classification = conn.get("classification", "legitimate")

    if classification == "legitimate":
        return None

    notif = ThreatNotification(
        remote_ip=remote_ip,
        remote_port=remote_port,
        local_port=conn.get("local_port", 0),
        process_name=process_name,
        process_pid=process_pid,
        process_path=conn.get("process_path", ""),
        bytes_sent=conn.get("bytes_sent", 0),
        bytes_recv=conn.get("bytes_recv", 0),
        connection_duration=conn.get("duration_seconds", 0.0),
    )

    if remote_port in MALICIOUS_PORTS:
        notif.severity = "critical"
        notif.confidence = 95
        notif.is_confirmed_breach = True
        notif.title = f"CRITICAL: {process_name} connecting to known malware port"
        notif.description = (
            f"Process '{process_name}' (PID {process_pid}) has established an outbound "
            f"connection to {remote_ip}:{remote_port}. "
            f"Port {remote_port} is associated with {MALICIOUS_PORTS[remote_port]}. "
            f"This is a strong indicator of active compromise or malware execution."
        )
        notif.technical_detail = (
            f"Remote: {remote_ip}:{remote_port} | "
            f"Process: {process_name} (PID {process_pid}) | "
            f"Path: {conn.get('process_path', 'N/A')} | "
            f"Sent: {conn.get('bytes_sent', 0):,} bytes | "
            f"Recv: {conn.get('bytes_recv', 0):,} bytes | "
            f"Duration: {conn.get('duration_seconds', 0):.1f}s"
        )
        notif.verdict_reason = (
            f"Port {remote_port} is a well-known indicator of {MALICIOUS_PORTS[remote_port]}. "
            f"Legitimate software does not use this port. Immediate process termination recommended."
        )
        notif.mitre_technique = "T1071.001"
        notif.mitre_tactic = "Command and Control"

    elif classification == "malicious":
        notif.severity = "malicious"
        notif.confidence = 80
        notif.is_confirmed_breach = False
        notif.title = f"Malicious traffic detected from {process_name}"
        notif.description = (
            f"'{process_name}' (PID {process_pid}) has been flagged for suspicious network behaviour. "
            f"The connection to {remote_ip}:{remote_port} matches known malicious patterns. "
            f"Manual investigation is required to confirm breach status."
        )
        notif.technical_detail = (
            f"Remote: {remote_ip}:{remote_port} | Process: {process_name} (PID {process_pid})"
        )
        notif.verdict_reason = (
            "Connection pattern matches malicious profile. "
            "Not yet confirmed as active breach — investigate process lineage and network history."
        )
        notif.mitre_technique = "T1071"
        notif.mitre_tactic = "Command and Control"

    else:
        notif.severity = "suspicious"
        notif.confidence = 45
        notif.is_confirmed_breach = False
        notif.title = f"Suspicious connection from {process_name}"
        notif.description = (
            f"'{process_name}' is connecting to {remote_ip}:{remote_port}, "
            f"which does not match expected behaviour for this process. "
            f"This may be legitimate but warrants investigation."
        )
        notif.technical_detail = (
            f"Remote: {remote_ip}:{remote_port} | Process: {process_name} (PID {process_pid})"
        )
        notif.verdict_reason = (
            "Unusual port or destination for this process. "
            "Probability of false positive: medium. Verify process legitimacy."
        )
        notif.mitre_technique = "T1071"
        notif.mitre_tactic = "Discovery / C2"

    return notif
