"""
demo/generate_demo_data.py
Generates a complete demo scan result with realistic threat data for
BlueSentinel V2.0 dashboard testing and demonstration purposes.

Usage:
    python demo/generate_demo_data.py

Then load into a running dashboard:
    python -c "
    import requests
    r = requests.post('http://localhost:5000/api/load-demo-data',
                      auth=('admin', 'changeme'))
    print(r.json())
    "
"""
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure project root is importable
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

CACHE_DIR = _ROOT / "cache"
DEMO_OUTPUT = CACHE_DIR / "demo_scan_result.json"

# ── Demo connections ───────────────────────────────────────────────────────────

DEMO_CONNECTIONS = [
    {
        "remote_addr": "185.220.101.45",
        "remote_port": 4444,
        "local_addr": "192.168.1.100",
        "local_port": 52341,
        "process_name": "svchost.exe",
        "pid": 4421,
        "process_path": "C:\\Windows\\System32\\svchost.exe",
        "status": "ESTABLISHED",
        "classification": "malicious",
        "classification_reason": "Metasploit default port",
        "bytes_sent": 2048,
        "bytes_recv": 8192,
        "duration_seconds": 3600,
        "beacon_confidence": 97,
        "color": "#ff3b5c",
    },
    {
        "remote_addr": "45.142.212.100",
        "remote_port": 9050,
        "local_addr": "192.168.1.100",
        "local_port": 54212,
        "process_name": "tor.exe",
        "pid": 5512,
        "process_path": "C:\\Users\\Public\\tor.exe",
        "status": "ESTABLISHED",
        "classification": "malicious",
        "classification_reason": "Tor SOCKS proxy — anonymized C2 channel",
        "bytes_sent": 512000,
        "bytes_recv": 204800,
        "duration_seconds": 1800,
        "color": "#ff3b5c",
    },
    {
        "remote_addr": "8.8.8.8",
        "remote_port": 53,
        "local_addr": "192.168.1.100",
        "local_port": 49152,
        "process_name": "dns_beacon.exe",
        "pid": 6601,
        "process_path": "C:\\Windows\\Temp\\dns_beacon.exe",
        "status": "ESTABLISHED",
        "classification": "suspicious",
        "classification_reason": "High-frequency DNS queries — possible DNS tunneling",
        "bytes_sent": 102400,
        "bytes_recv": 51200,
        "duration_seconds": 900,
        "color": "#ffb800",
    },
    {
        "remote_addr": "192.168.100.200",
        "remote_port": 443,
        "local_addr": "192.168.1.100",
        "local_port": 55123,
        "process_name": "rundll32.exe",
        "pid": 7712,
        "process_path": "C:\\Windows\\System32\\rundll32.exe",
        "status": "ESTABLISHED",
        "classification": "malicious",
        "classification_reason": "rundll32 with suspicious C2 pattern — Cobalt Strike indicator",
        "bytes_sent": 4096,
        "bytes_recv": 16384,
        "duration_seconds": 2400,
        "beacon_confidence": 89,
        "color": "#ff3b5c",
    },
    {
        "remote_addr": "10.1.1.50",
        "remote_port": 445,
        "local_addr": "192.168.1.100",
        "local_port": 49200,
        "process_name": "cmd.exe",
        "pid": 8823,
        "process_path": "C:\\Windows\\System32\\cmd.exe",
        "status": "ESTABLISHED",
        "classification": "suspicious",
        "classification_reason": "cmd.exe accessing remote SMB — possible lateral movement",
        "bytes_sent": 1024,
        "bytes_recv": 2048,
        "duration_seconds": 120,
        "color": "#ffb800",
    },
    {
        "remote_addr": "203.0.113.42",
        "remote_port": 1337,
        "local_addr": "192.168.1.100",
        "local_port": 51234,
        "process_name": "powershell.exe",
        "pid": 9934,
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "status": "ESTABLISHED",
        "classification": "malicious",
        "classification_reason": "PowerShell reverse shell on port 1337",
        "bytes_sent": 8192,
        "bytes_recv": 32768,
        "duration_seconds": 600,
        "color": "#ff3b5c",
    },
    {
        "remote_addr": "198.51.100.77",
        "remote_port": 21,
        "local_addr": "192.168.1.100",
        "local_port": 20001,
        "process_name": "ftp.exe",
        "pid": 1045,
        "process_path": "C:\\Windows\\System32\\ftp.exe",
        "status": "ESTABLISHED",
        "classification": "suspicious",
        "classification_reason": "Large FTP upload — potential data exfiltration (500 MB)",
        "bytes_sent": 524288000,
        "bytes_recv": 1024,
        "duration_seconds": 1200,
        "color": "#ffb800",
    },
    {
        "remote_addr": "91.195.240.117",
        "remote_port": 8080,
        "local_addr": "192.168.1.100",
        "local_port": 52100,
        "process_name": "notepad.exe",
        "pid": 2156,
        "process_path": "C:\\Windows\\System32\\notepad.exe",
        "status": "ESTABLISHED",
        "classification": "malicious",
        "classification_reason": "notepad.exe making HTTP connections — process injection indicator",
        "bytes_sent": 512,
        "bytes_recv": 4096,
        "duration_seconds": 300,
        "color": "#ff3b5c",
    },
    {
        "remote_addr": "194.165.16.18",
        "remote_port": 6667,
        "local_addr": "192.168.1.100",
        "local_port": 50001,
        "process_name": "explorer.exe",
        "pid": 3267,
        "process_path": "C:\\Windows\\explorer.exe",
        "status": "ESTABLISHED",
        "classification": "malicious",
        "classification_reason": "IRC connection from explorer.exe — botnet C2 indicator",
        "bytes_sent": 256,
        "bytes_recv": 1024,
        "duration_seconds": 7200,
        "color": "#ff3b5c",
    },
    {
        "remote_addr": "172.16.200.5",
        "remote_port": 31337,
        "local_addr": "192.168.1.100",
        "local_port": 49999,
        "process_name": "winlogon.exe",
        "pid": 4378,
        "process_path": "C:\\Windows\\System32\\winlogon.exe",
        "status": "ESTABLISHED",
        "classification": "malicious",
        "classification_reason": "Port 31337 (Back Orifice) from winlogon.exe",
        "bytes_sent": 128,
        "bytes_recv": 512,
        "duration_seconds": 480,
        "color": "#ff3b5c",
    },
]

# ── Demo YARA matches ──────────────────────────────────────────────────────────

DEMO_YARA_MATCHES = [
    {
        "rule_name": "Ransomware_Generic_NotePattern",
        "file_path": "C:\\Users\\Public\\Downloads\\invoice_2026.exe",
        "matched_strings": ["YOUR FILES HAVE BEEN ENCRYPTED", "bitcoin wallet"],
        "severity": "Critical",
        "mitre_technique": "T1486",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "yara_match",
        "message": "Ransomware_Generic_NotePattern matched in C:\\Users\\Public\\Downloads\\invoice_2026.exe",
    },
    {
        "rule_name": "CobaltStrike_Beacon_Config",
        "file_path": "C:\\Windows\\Temp\\csrss_helper.dll",
        "matched_strings": ["beacon", "\\x00\\x00\\x00\\x00\\xc8\\x00"],
        "severity": "Critical",
        "mitre_technique": "T1055.012",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "yara_match",
        "message": "CobaltStrike_Beacon_Config matched in C:\\Windows\\Temp\\csrss_helper.dll",
    },
    {
        "rule_name": "PowerShell_DownloadCradle",
        "file_path": "C:\\Users\\psy\\AppData\\Roaming\\update.ps1",
        "matched_strings": ["IEX (New-Object Net.WebClient).DownloadString"],
        "severity": "High",
        "mitre_technique": "T1059.001",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "yara_match",
        "message": "PowerShell_DownloadCradle matched in update.ps1",
    },
    {
        "rule_name": "LOLBin_CertUtil_Decode",
        "file_path": "C:\\Windows\\Temp\\payload.b64",
        "matched_strings": ["certutil -decode", "certutil.exe -urlcache"],
        "severity": "High",
        "mitre_technique": "T1218",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "yara_match",
        "message": "LOLBin_CertUtil_Decode matched in payload.b64",
    },
    {
        "rule_name": "RAT_AsyncRAT_Strings",
        "file_path": "C:\\ProgramData\\WindowsUpdate\\wuagent.exe",
        "matched_strings": ["AsyncClient", "Stub.exe", "Server.crt"],
        "severity": "Critical",
        "mitre_technique": "T1219",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "yara_match",
        "message": "RAT_AsyncRAT_Strings matched in wuagent.exe",
    },
    {
        "rule_name": "Persistence_RunKey_Malware",
        "file_path": "C:\\Users\\psy\\AppData\\Local\\Temp\\svchost32.exe",
        "matched_strings": ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "severity": "High",
        "mitre_technique": "T1547.001",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "yara_match",
        "message": "Persistence_RunKey_Malware matched in svchost32.exe",
    },
    {
        "rule_name": "DNS_Tunneling_Pattern",
        "file_path": "C:\\Windows\\System32\\dns_tool.exe",
        "matched_strings": ["dnscat", "dns_tunnel"],
        "severity": "Medium",
        "mitre_technique": "T1071.004",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "yara_match",
        "message": "DNS_Tunneling_Pattern matched in dns_tool.exe",
    },
    {
        "rule_name": "Credential_Dumping_Strings",
        "file_path": "C:\\Temp\\lsass_dump.exe",
        "matched_strings": ["lsass.exe", "MiniDumpWriteDump", "SeDebugPrivilege"],
        "severity": "Critical",
        "mitre_technique": "T1003.001",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "yara_match",
        "message": "Credential_Dumping_Strings matched in lsass_dump.exe",
    },
]

# ── Demo beaconing alerts ──────────────────────────────────────────────────────

DEMO_BEACONING = [
    {
        "dst_ip": "185.220.101.45",
        "dst_port": 4444,
        "process": "svchost.exe",
        "pid": 4421,
        "confidence": 97,
        "beacon_interval_s": 60.0,
        "connection_count": 60,
        "total_bytes": 614400,
        "mitre_technique": "T1071.001",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "beaconing",
        "severity": "Critical",
        "message": "C2 beaconing detected: svchost.exe → 185.220.101.45:4444 (60s intervals, 97% confidence)",
    },
    {
        "dst_ip": "192.168.100.200",
        "dst_port": 443,
        "process": "rundll32.exe",
        "pid": 7712,
        "confidence": 89,
        "beacon_interval_s": 30.0,
        "connection_count": 120,
        "total_bytes": 204800,
        "mitre_technique": "T1071.001",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "beaconing",
        "severity": "Critical",
        "message": "Cobalt Strike beacon: rundll32.exe → 192.168.100.200:443 (30s intervals, 89% confidence)",
    },
    {
        "dst_ip": "45.142.212.100",
        "dst_port": 9050,
        "process": "tor.exe",
        "pid": 5512,
        "confidence": 78,
        "beacon_interval_s": 120.0,
        "connection_count": 30,
        "total_bytes": 716800,
        "mitre_technique": "T1090.003",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "beaconing",
        "severity": "High",
        "message": "Tor beaconing: tor.exe → 45.142.212.100:9050 (120s intervals, 78% confidence)",
    },
]

# ── Demo registry persistence ──────────────────────────────────────────────────

DEMO_REGISTRY = [
    {
        "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "name": "WindowsSecurityUpdate",
        "value": "C:\\Users\\Public\\winsec.exe /silent",
        "status": "NEW",
        "reason": "Executable in Public folder added to Run key",
        "severity": "High",
        "mitre_technique": "T1547.001",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "registry_persistence",
        "message": "NEW Run key: WindowsSecurityUpdate → C:\\Users\\Public\\winsec.exe",
    },
    {
        "key": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "name": "OneDriveHelper",
        "value": "C:\\Windows\\Temp\\svchost32.exe",
        "status": "NEW",
        "reason": "svchost32.exe (typosquatting svchost.exe) in Temp folder",
        "severity": "Critical",
        "mitre_technique": "T1547.001",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "registry_persistence",
        "message": "NEW Run key: OneDriveHelper → C:\\Windows\\Temp\\svchost32.exe",
    },
]

# ── Demo event log anomalies ───────────────────────────────────────────────────

DEMO_EVENTS = [
    {
        "event_id": 4625,
        "count": 847,
        "description": "847 failed login attempts in 10 minutes — brute force attack",
        "severity": "Critical",
        "mitre_technique": "T1110",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "event_log",
        "message": "EventID 4625: 847 failed logins in 10 minutes (brute force)",
    },
    {
        "event_id": 4688,
        "process": "whoami.exe",
        "parent": "cmd.exe",
        "parent_parent": "powershell.exe",
        "description": "Reconnaissance command chain: PowerShell → cmd → whoami",
        "severity": "High",
        "mitre_technique": "T1082",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "event_log",
        "message": "EventID 4688: Suspicious process chain powershell → cmd → whoami",
    },
    {
        "event_id": 4698,
        "description": "New scheduled task: 'WindowsDefenderUpdate' runs C:\\Temp\\update.exe",
        "severity": "High",
        "mitre_technique": "T1053.005",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "event_log",
        "message": "EventID 4698: Malicious scheduled task 'WindowsDefenderUpdate' created",
    },
    {
        "event_id": 4720,
        "description": "New local administrator account created: 'helpdesk_admin'",
        "severity": "Critical",
        "mitre_technique": "T1136.001",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "event_log",
        "message": "EventID 4720: New admin account 'helpdesk_admin' created",
    },
    {
        "event_id": 4104,
        "description": "PowerShell script block: IEX with base64-encoded payload",
        "severity": "High",
        "mitre_technique": "T1059.001",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "event_log",
        "message": "EventID 4104: PowerShell IEX with base64 payload detected",
    },
    {
        "event_id": 7045,
        "description": "New service installed: 'NetBridge' — binary path in ProgramData",
        "severity": "High",
        "mitre_technique": "T1543.003",
        "alert_id": str(uuid.uuid4())[:8],
        "alert_type": "event_log",
        "message": "EventID 7045: New suspicious service 'NetBridge' installed",
    },
]

# ── Demo notifications ─────────────────────────────────────────────────────────

DEMO_NOTIFICATIONS = [
    {
        "id": "demo0001",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        "severity": "critical",
        "confidence": 97,
        "title": "CRITICAL: svchost.exe connecting to Metasploit C2",
        "description": (
            "Process 'svchost.exe' (PID 4421) has established an outbound connection to "
            "185.220.101.45:4444. Port 4444 is the Metasploit Framework default listener port. "
            "This is a strong indicator of active compromise."
        ),
        "technical_detail": (
            "Remote: 185.220.101.45:4444 | Process: svchost.exe (PID 4421) | "
            "Path: C:\\Windows\\System32\\svchost.exe | Sent: 2,048 bytes | "
            "Recv: 8,192 bytes | Duration: 3600.0s"
        ),
        "is_confirmed_breach": True,
        "verdict_reason": (
            "Port 4444 is a well-known indicator of Metasploit default listener. "
            "Legitimate software does not use this port. Immediate process termination recommended."
        ),
        "remote_ip": "185.220.101.45",
        "remote_port": 4444,
        "local_port": 52341,
        "process_name": "svchost.exe",
        "process_pid": 4421,
        "process_path": "C:\\Windows\\System32\\svchost.exe",
        "bytes_sent": 2048,
        "bytes_recv": 8192,
        "connection_duration": 3600.0,
        "mitre_technique": "T1071.001",
        "mitre_tactic": "Command and Control",
        "can_kill_process": True,
        "can_blacklist_ip": True,
        "is_killed": False,
        "is_blacklisted": False,
        "is_acknowledged": False,
    },
    {
        "id": "demo0002",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat(),
        "severity": "critical",
        "confidence": 89,
        "title": "CRITICAL: Cobalt Strike beacon — rundll32.exe",
        "description": (
            "rundll32.exe (PID 7712) is beaconing to 192.168.100.200:443 every 30 seconds. "
            "This matches the Cobalt Strike malleable C2 profile pattern. "
            "Process injection via rundll32 is a classic Cobalt Strike TTP."
        ),
        "technical_detail": (
            "Remote: 192.168.100.200:443 | Process: rundll32.exe (PID 7712) | "
            "Beacon interval: 30s | Connections: 120 | Total bytes: 204,800"
        ),
        "is_confirmed_breach": True,
        "verdict_reason": (
            "rundll32.exe making outbound HTTPS connections to an internal IP is highly anomalous. "
            "Beacon interval and jitter match Cobalt Strike defaults."
        ),
        "remote_ip": "192.168.100.200",
        "remote_port": 443,
        "local_port": 55123,
        "process_name": "rundll32.exe",
        "process_pid": 7712,
        "process_path": "C:\\Windows\\System32\\rundll32.exe",
        "bytes_sent": 4096,
        "bytes_recv": 16384,
        "connection_duration": 2400.0,
        "mitre_technique": "T1071.001",
        "mitre_tactic": "Command and Control",
        "can_kill_process": True,
        "can_blacklist_ip": True,
        "is_killed": False,
        "is_blacklisted": False,
        "is_acknowledged": False,
    },
    {
        "id": "demo0003",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "severity": "malicious",
        "confidence": 80,
        "title": "Malicious traffic: notepad.exe making HTTP connections",
        "description": (
            "notepad.exe (PID 2156) is making HTTP connections to 91.195.240.117:8080. "
            "This is a strong indicator of process injection — notepad.exe is a common "
            "injection target. The destination IP is not a known legitimate service."
        ),
        "technical_detail": (
            "Remote: 91.195.240.117:8080 | Process: notepad.exe (PID 2156) | "
            "Path: C:\\Windows\\System32\\notepad.exe | Duration: 300s"
        ),
        "is_confirmed_breach": False,
        "verdict_reason": (
            "notepad.exe should never make network connections. This is almost certainly "
            "the result of shellcode injection. Investigate parent process and memory."
        ),
        "remote_ip": "91.195.240.117",
        "remote_port": 8080,
        "local_port": 52100,
        "process_name": "notepad.exe",
        "process_pid": 2156,
        "process_path": "C:\\Windows\\System32\\notepad.exe",
        "bytes_sent": 512,
        "bytes_recv": 4096,
        "connection_duration": 300.0,
        "mitre_technique": "T1055",
        "mitre_tactic": "Defense Evasion",
        "can_kill_process": True,
        "can_blacklist_ip": True,
        "is_killed": False,
        "is_blacklisted": False,
        "is_acknowledged": False,
    },
    {
        "id": "demo0004",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": "suspicious",
        "confidence": 45,
        "title": "Suspicious: Large FTP upload from ftp.exe",
        "description": (
            "ftp.exe (PID 1045) has uploaded ~500 MB to 198.51.100.77:21. "
            "This volume of outbound data over FTP may indicate data exfiltration. "
            "Verify whether this transfer was authorised."
        ),
        "technical_detail": (
            "Remote: 198.51.100.77:21 | Process: ftp.exe (PID 1045) | "
            "Sent: 524,288,000 bytes (500 MB) | Recv: 1,024 bytes | Duration: 1200s"
        ),
        "is_confirmed_breach": False,
        "verdict_reason": (
            "500 MB FTP upload is unusual for most environments. "
            "Medium probability of false positive if scheduled backup jobs exist."
        ),
        "remote_ip": "198.51.100.77",
        "remote_port": 21,
        "local_port": 20001,
        "process_name": "ftp.exe",
        "process_pid": 1045,
        "process_path": "C:\\Windows\\System32\\ftp.exe",
        "bytes_sent": 524288000,
        "bytes_recv": 1024,
        "connection_duration": 1200.0,
        "mitre_technique": "T1041",
        "mitre_tactic": "Exfiltration",
        "can_kill_process": True,
        "can_blacklist_ip": True,
        "is_killed": False,
        "is_blacklisted": False,
        "is_acknowledged": False,
    },
]

# ── MITRE ATT&CK coverage ──────────────────────────────────────────────────────

DEMO_MITRE_COVERAGE = {
    "T1071.001": {"tactic": "command-and-control", "count": 4, "severity": "Critical"},
    "T1055":     {"tactic": "defense-evasion",     "count": 2, "severity": "Critical"},
    "T1486":     {"tactic": "impact",              "count": 1, "severity": "Critical"},
    "T1003.001": {"tactic": "credential-access",   "count": 1, "severity": "Critical"},
    "T1059.001": {"tactic": "execution",           "count": 2, "severity": "High"},
    "T1547.001": {"tactic": "persistence",         "count": 2, "severity": "High"},
    "T1110":     {"tactic": "credential-access",   "count": 1, "severity": "Critical"},
    "T1082":     {"tactic": "discovery",           "count": 1, "severity": "High"},
    "T1053.005": {"tactic": "persistence",         "count": 1, "severity": "High"},
    "T1136.001": {"tactic": "persistence",         "count": 1, "severity": "Critical"},
    "T1090.003": {"tactic": "command-and-control", "count": 1, "severity": "High"},
    "T1218":     {"tactic": "defense-evasion",     "count": 1, "severity": "High"},
    "T1219":     {"tactic": "command-and-control", "count": 1, "severity": "Critical"},
    "T1041":     {"tactic": "exfiltration",        "count": 1, "severity": "Medium"},
    "T1543.003": {"tactic": "persistence",         "count": 1, "severity": "High"},
    "T1071.004": {"tactic": "command-and-control", "count": 1, "severity": "Medium"},
    "T1055.012": {"tactic": "defense-evasion",     "count": 1, "severity": "Critical"},
}


# ── Timeline generation ────────────────────────────────────────────────────────

def _generate_timeline(threat_score: int) -> list:
    """Generate 2 hours of synthetic risk score history (120 points × 1 min)."""
    random.seed(42)
    now = time.time()
    points = []
    for i in range(120):
        ts = now - (120 - i) * 60
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M")
        if i < 90:
            score = random.randint(0, 10)
            alerts = 0
        else:
            # Simulate attack ramping up
            ramp = (i - 90) / 30.0
            score = min(100, int(threat_score * ramp) + random.randint(-3, 3))
            alerts = max(0, int(len(DEMO_YARA_MATCHES) * ramp) + random.randint(-1, 1))
        points.append({"time": dt, "risk_score": max(0, score), "alert_count": alerts})
    return points


# ── Build complete scan result ─────────────────────────────────────────────────

def build_scan_result() -> dict:
    all_alerts = []

    # Alerts from YARA matches
    for y in DEMO_YARA_MATCHES:
        all_alerts.append({
            "alert_id": y["alert_id"],
            "alert_type": y["alert_type"],
            "severity": y["severity"],
            "message": y["message"],
            "mitre_technique": y["mitre_technique"],
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 30))).isoformat(),
            "acknowledged": False,
        })

    # Alerts from beaconing
    for b in DEMO_BEACONING:
        all_alerts.append({
            "alert_id": b["alert_id"],
            "alert_type": b["alert_type"],
            "severity": b["severity"],
            "message": b["message"],
            "mitre_technique": b.get("mitre_technique", "T1071"),
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 15))).isoformat(),
            "acknowledged": False,
        })

    # Alerts from registry
    for r in DEMO_REGISTRY:
        all_alerts.append({
            "alert_id": r["alert_id"],
            "alert_type": r["alert_type"],
            "severity": r["severity"],
            "message": r["message"],
            "mitre_technique": r["mitre_technique"],
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=random.randint(5, 60))).isoformat(),
            "acknowledged": False,
        })

    # Alerts from events
    for e in DEMO_EVENTS:
        all_alerts.append({
            "alert_id": e["alert_id"],
            "alert_type": e["alert_type"],
            "severity": e["severity"],
            "message": e["message"],
            "mitre_technique": e.get("mitre_technique", ""),
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=random.randint(2, 20))).isoformat(),
            "acknowledged": False,
        })

    threat_score = 94  # critical-level
    critical_count = sum(1 for a in all_alerts if a["severity"] == "Critical")
    high_count = sum(1 for a in all_alerts if a["severity"] == "High")
    medium_count = sum(1 for a in all_alerts if a["severity"] == "Medium")
    low_count = sum(1 for a in all_alerts if a["severity"] == "Low")

    return {
        "scan_id": "DEMO-" + str(uuid.uuid4())[:8].upper(),
        "hostname": os.environ.get("COMPUTERNAME", "DEMO-WORKSTATION"),
        "scan_mode": "full-scan",
        "started_at": (datetime.now(timezone.utc) - timedelta(seconds=12)).isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": 12.4,
        "threat_score": threat_score,
        "risk_score": threat_score,
        "total_alerts": len(all_alerts),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "alerts": all_alerts,
        "yara_matches": DEMO_YARA_MATCHES,
        "beaconing_alerts": DEMO_BEACONING,
        "ioc_matches": [],
        "connections": DEMO_CONNECTIONS,
        "registry_persistence": DEMO_REGISTRY,
        "event_anomalies": DEMO_EVENTS,
        "mitre_coverage": DEMO_MITRE_COVERAGE,
        "ai_provider_used": os.environ.get("AI_PROVIDER", "openai"),
        "ai_summary": (
            "CRITICAL BREACH DETECTED. Multiple indicators confirm active adversary control: "
            "Cobalt Strike C2 beacon via rundll32.exe, Metasploit reverse shell via svchost.exe, "
            "ransomware staging (invoice_2026.exe), credential dumping (lsass_dump.exe), "
            "847 brute-force attempts, and a rogue administrator account. "
            "Immediate incident response is required. Isolate affected endpoints."
        ),
        "timeline": _generate_timeline(threat_score),
        "notifications": DEMO_NOTIFICATIONS,
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    result = build_scan_result()

    DEMO_OUTPUT.write_text(json.dumps(result, indent=2, default=str))
    print(f"\n[+] Demo scan result written to: {DEMO_OUTPUT}")
    print(f"    Alerts:        {result['total_alerts']}")
    print(f"      Critical:    {result['critical_count']}")
    print(f"      High:        {result['high_count']}")
    print(f"    YARA matches:  {len(result['yara_matches'])}")
    print(f"    Beaconing:     {len(result['beaconing_alerts'])}")
    print(f"    Connections:   {len(result['connections'])} ({sum(1 for c in result['connections'] if c['classification']=='malicious')} malicious)")
    print(f"    MITRE tactics: {len(result['mitre_coverage'])} techniques")
    print(f"    Notifications: {len(result['notifications'])}")
    print(f"    Risk score:    {result['threat_score']}/100")
    print()
    print("[*] To load into dashboard:")
    print("    1. Start the dashboard:  python dashboard/app.py")
    print("    2. Load demo data:       python -c \"import requests; r=requests.post(")
    print("         'http://localhost:5000/api/load-demo-data',")
    print("         auth=('admin', 'changeme')); print(r.json())\"")

    # Save sample_data copies
    samples_dir = Path(__file__).parent / "sample_data"
    samples_dir.mkdir(exist_ok=True)
    (samples_dir / "demo_connections.json").write_text(
        json.dumps(result["connections"], indent=2))
    (samples_dir / "demo_alerts.json").write_text(
        json.dumps(result["alerts"], indent=2))
    (samples_dir / "demo_scan_result.json").write_text(
        json.dumps(result, indent=2, default=str))
    print(f"\n[+] Sample data files saved to: {samples_dir}/")


if __name__ == "__main__":
    main()
