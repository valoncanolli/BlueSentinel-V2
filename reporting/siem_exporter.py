"""
reporting/siem_exporter.py
SIEM export module for BlueSentinel v2.0.
Supports three export formats: JSON (ELK/OpenSearch), CEF, and Syslog UDP.
"""
import json
import logging
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

log = logging.getLogger(__name__)

REPORTS_DIR = Path(__file__).parent.parent / "reports"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_to_cef_severity(severity: str) -> int:
    """Map BlueSentinel severity to CEF severity 0-10."""
    mapping = {
        "Critical": 10,
        "High": 7,
        "Medium": 5,
        "Low": 3,
        "Info": 1,
    }
    return mapping.get(severity, 5)


def _escape_cef_value(value: str) -> str:
    """Escape special characters in CEF extension values."""
    value = str(value)
    value = value.replace("\\", "\\\\")
    value = value.replace("|", "\\|")
    value = value.replace("=", "\\=")
    value = value.replace("\n", "\\n")
    value = value.replace("\r", "\\r")
    return value


class SiemExporter:
    """
    Exports BlueSentinel scan results to SIEM-compatible formats.

    Supported formats:
      - JSON  : ELK/OpenSearch compatible with @timestamp field
      - CEF   : ArcSight Common Event Format (plain text, one event per line)
      - Syslog: UDP syslog with CEF payload (RFC 3164)
    """

    CEF_VERSION = 0
    CEF_DEVICE_VENDOR = "BlueSentinel"
    CEF_DEVICE_PRODUCT = "ThreatDetectionPlatform"
    CEF_DEVICE_VERSION = "2.0"

    def __init__(
        self,
        siem_host: Optional[str] = None,
        siem_port: int = 514,
        output_dir: Optional[Path] = None,
    ) -> None:
        self.output_dir = output_dir or REPORTS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Try to load SIEM config from environment
        if siem_host is None:
            try:
                from core.config_manager import get_config
                cfg = get_config()
                self.siem_host = cfg.siem_host
                self.siem_port = cfg.siem_port
            except Exception:
                import os
                self.siem_host = os.getenv("SIEM_HOST", "")
                self.siem_port = int(os.getenv("SIEM_PORT", str(siem_port)))
        else:
            self.siem_host = siem_host
            self.siem_port = siem_port

    # ------------------------------------------------------------------ #
    # JSON / ELK / OpenSearch export                                       #
    # ------------------------------------------------------------------ #

    def _alert_to_elk_doc(self, alert: Dict[str, Any], scan_meta: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a single alert dict to an ELK-compatible document."""
        timestamp = alert.get("timestamp", _utc_now_iso())
        # Ensure @timestamp is in ISO 8601 with UTC offset
        try:
            # Parse and re-format if needed
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            at_timestamp = dt.isoformat()
        except (ValueError, AttributeError):
            at_timestamp = _utc_now_iso()

        return {
            "@timestamp": at_timestamp,
            "@version": "1",
            "event": {
                "module": "bluesentinel",
                "dataset": "threat_alert",
                "kind": "alert",
                "category": ["malware", "network", "host"],
                "type": ["indicator"],
                "severity": _severity_to_cef_severity(alert.get("severity", "Medium")),
                "risk_score": scan_meta.get("threat_score", 0),
                "id": alert.get("alert_id", ""),
                "original": json.dumps(alert),
            },
            "message": alert.get("message", ""),
            "rule": {
                "name": alert.get("type", alert.get("alert_type", "")),
                "category": alert.get("type", ""),
                "reference": alert.get("mitre_technique", ""),
            },
            "threat": {
                "technique": {
                    "id": [alert.get("mitre_technique", "")],
                    "name": [],
                },
                "tactic": {
                    "id": [],
                    "name": [alert.get("mitre_tactic", "")],
                },
            },
            "host": {
                "hostname": scan_meta.get("hostname", socket.gethostname()),
                "name": scan_meta.get("hostname", socket.gethostname()),
            },
            "labels": {
                "scan_id": scan_meta.get("scan_id", ""),
                "source_module": alert.get("source_module", ""),
                "severity": alert.get("severity", ""),
                "acknowledged": str(alert.get("acknowledged", False)).lower(),
            },
            "tags": ["bluesentinel", "threat-detection", alert.get("severity", "").lower()],
        }

    def export_json(self, scan_result: Union[Dict[str, Any], Any]) -> Path:
        """
        Export scan result as NDJSON (newline-delimited JSON) for ELK/OpenSearch bulk import.
        Returns path to the generated file.
        """
        if hasattr(scan_result, "to_dict"):
            data = scan_result.to_dict()
        else:
            data = dict(scan_result)

        scan_id = data.get("scan_id", "UNKNOWN")
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"siem_elk_{scan_id}_{timestamp_str}.ndjson"

        alerts = data.get("alerts", [])
        meta = {
            "scan_id": data.get("scan_id", ""),
            "hostname": data.get("hostname", socket.gethostname()),
            "threat_score": data.get("threat_score", 0),
            "scan_mode": data.get("scan_mode", ""),
            "started_at": data.get("started_at", ""),
        }

        lines_written = 0
        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                for alert in alerts:
                    doc = self._alert_to_elk_doc(alert, meta)
                    fh.write(json.dumps(doc, ensure_ascii=False) + "\n")
                    lines_written += 1

                # Also write a summary document
                summary_doc = {
                    "@timestamp": _utc_now_iso(),
                    "@version": "1",
                    "event": {
                        "module": "bluesentinel",
                        "dataset": "scan_summary",
                        "kind": "event",
                    },
                    "message": f"BlueSentinel scan {scan_id} completed with risk score {data.get('threat_score', 0)}/100",
                    "host": {"hostname": meta["hostname"]},
                    "bluesentinel": {
                        "scan_id": scan_id,
                        "threat_score": data.get("threat_score", 0),
                        "total_alerts": data.get("total_alerts", len(alerts)),
                        "critical_count": data.get("critical_count", 0),
                        "high_count": data.get("high_count", 0),
                        "yara_matches": len(data.get("yara_matches", [])),
                        "beaconing_alerts": len(data.get("beaconing_alerts", [])),
                        "ioc_matches": len(data.get("ioc_matches", [])),
                        "ai_provider": data.get("ai_provider_used", ""),
                        "scan_mode": data.get("scan_mode", ""),
                        "started_at": data.get("started_at", ""),
                        "completed_at": data.get("completed_at", ""),
                        "duration_seconds": data.get("duration_seconds", 0),
                    },
                    "tags": ["bluesentinel", "scan-summary"],
                }
                fh.write(json.dumps(summary_doc, ensure_ascii=False) + "\n")

            log.info(f"ELK JSON export: {lines_written} alerts → {output_path}")
        except IOError as exc:
            log.error(f"Failed to write ELK JSON export: {exc}")
            raise

        return output_path

    # ------------------------------------------------------------------ #
    # CEF export                                                           #
    # ------------------------------------------------------------------ #

    def _build_cef_header(
        self,
        signature_id: str,
        name: str,
        severity: int,
    ) -> str:
        """Build CEF header string: CEF:version|vendor|product|version|sig|name|severity|"""
        parts = [
            f"CEF:{self.CEF_VERSION}",
            _escape_cef_value(self.CEF_DEVICE_VENDOR),
            _escape_cef_value(self.CEF_DEVICE_PRODUCT),
            _escape_cef_value(self.CEF_DEVICE_VERSION),
            _escape_cef_value(signature_id),
            _escape_cef_value(name),
            str(severity),
        ]
        return "|".join(parts) + "|"

    def _alert_to_cef(self, alert: Dict[str, Any], hostname: str, scan_id: str) -> str:
        """Convert a single alert dict to a CEF event string."""
        severity = _severity_to_cef_severity(alert.get("severity", "Medium"))
        alert_type = alert.get("type", alert.get("alert_type", "UNKNOWN"))
        alert_id = alert.get("alert_id", "")
        message = alert.get("message", "")
        mitre = alert.get("mitre_technique", "")
        tactic = alert.get("mitre_tactic", "")
        source_module = alert.get("source_module", "bluesentinel")

        header = self._build_cef_header(
            signature_id=alert_id or f"BS-{alert_type}",
            name=f"{alert_type}: {message[:80]}",
            severity=severity,
        )

        # Build extension key=value pairs
        ext_parts = []

        # Standard CEF fields
        ext_parts.append(f"dvc={_escape_cef_value(hostname)}")
        ext_parts.append(f"deviceExternalId={_escape_cef_value(scan_id)}")

        # Timestamp
        timestamp = alert.get("timestamp", _utc_now_iso())
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            # CEF uses milliseconds since epoch
            epoch_ms = int(dt.timestamp() * 1000)
            ext_parts.append(f"rt={epoch_ms}")
        except (ValueError, AttributeError):
            ext_parts.append(f"rt={int(time.time() * 1000)}")

        # Message
        ext_parts.append(f"msg={_escape_cef_value(message[:512])}")

        # BlueSentinel custom fields
        if mitre:
            ext_parts.append(f"cs1={_escape_cef_value(mitre)}")
            ext_parts.append("cs1Label=MITRETechnique")
        if tactic:
            ext_parts.append(f"cs2={_escape_cef_value(tactic)}")
            ext_parts.append("cs2Label=MITRETactic")
        if source_module:
            ext_parts.append(f"cs3={_escape_cef_value(source_module)}")
            ext_parts.append("cs3Label=SourceModule")
        if alert.get("severity"):
            ext_parts.append(f"cs4={_escape_cef_value(alert['severity'])}")
            ext_parts.append("cs4Label=BlueSentinelSeverity")

        # Acknowledged status
        ack = "true" if alert.get("acknowledged") else "false"
        ext_parts.append(f"cs5={ack}")
        ext_parts.append("cs5Label=Acknowledged")

        extension = " ".join(ext_parts)
        return header + extension

    def export_cef(self, scan_result: Union[Dict[str, Any], Any]) -> Path:
        """
        Export scan result as CEF (Common Event Format) flat text file.
        Returns path to the generated file.
        """
        if hasattr(scan_result, "to_dict"):
            data = scan_result.to_dict()
        else:
            data = dict(scan_result)

        scan_id = data.get("scan_id", "UNKNOWN")
        hostname = data.get("hostname", socket.gethostname())
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"siem_cef_{scan_id}_{timestamp_str}.cef"

        alerts = data.get("alerts", [])
        lines_written = 0

        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                for alert in alerts:
                    cef_line = self._alert_to_cef(alert, hostname, scan_id)
                    fh.write(cef_line + "\n")
                    lines_written += 1

            log.info(f"CEF export: {lines_written} events → {output_path}")
        except IOError as exc:
            log.error(f"Failed to write CEF export: {exc}")
            raise

        return output_path

    # ------------------------------------------------------------------ #
    # Syslog UDP export                                                    #
    # ------------------------------------------------------------------ #

    def _build_syslog_header(self, severity_cef: int) -> str:
        """
        Build RFC 3164 syslog header.
        Maps CEF severity to syslog priority (facility=1 [user-level], severity varies).
        """
        # Facility 1 = user-level messages
        facility = 1
        # Map CEF severity (0-10) to syslog severity (0-7, lower = more severe)
        if severity_cef >= 9:
            syslog_sev = 2  # Critical
        elif severity_cef >= 7:
            syslog_sev = 3  # Error
        elif severity_cef >= 5:
            syslog_sev = 4  # Warning
        elif severity_cef >= 3:
            syslog_sev = 6  # Informational
        else:
            syslog_sev = 7  # Debug

        priority = (facility * 8) + syslog_sev
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        hostname = socket.gethostname()
        return f"<{priority}>{timestamp} {hostname} bluesentinel:"

    def send_syslog(self, scan_result: Union[Dict[str, Any], Any]) -> int:
        """
        Send scan alerts via UDP syslog (RFC 3164) to configured SIEM host.
        Returns number of messages successfully sent.
        """
        if not self.siem_host:
            log.warning("SIEM_HOST not configured. Syslog export skipped.")
            return 0

        if hasattr(scan_result, "to_dict"):
            data = scan_result.to_dict()
        else:
            data = dict(scan_result)

        scan_id = data.get("scan_id", "UNKNOWN")
        hostname = data.get("hostname", socket.gethostname())
        alerts = data.get("alerts", [])

        sent = 0
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            for alert in alerts:
                severity_cef = _severity_to_cef_severity(alert.get("severity", "Medium"))
                syslog_header = self._build_syslog_header(severity_cef)
                cef_payload = self._alert_to_cef(alert, hostname, scan_id)

                message = f"{syslog_header} {cef_payload}"
                # Syslog UDP max message size is 1024 bytes per RFC 3164
                message_bytes = message.encode("utf-8", errors="replace")
                if len(message_bytes) > 1024:
                    message_bytes = message_bytes[:1021] + b"..."

                sock.sendto(message_bytes, (self.siem_host, self.siem_port))
                sent += 1

                # Small delay to avoid overwhelming the SIEM
                time.sleep(0.01)

            sock.close()
            log.info(f"Syslog UDP: sent {sent} events to {self.siem_host}:{self.siem_port}")

        except socket.timeout:
            log.error(f"Syslog UDP timeout sending to {self.siem_host}:{self.siem_port}")
        except OSError as exc:
            log.error(f"Syslog UDP send failed: {exc}")

        return sent

    # ------------------------------------------------------------------ #
    # Combined export                                                      #
    # ------------------------------------------------------------------ #

    def export_all(self, scan_result: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """
        Run all export formats. Syslog is only sent if SIEM_HOST is configured.
        Returns dict with paths/status for each format.
        """
        results: Dict[str, Any] = {}

        # ELK JSON
        try:
            json_path = self.export_json(scan_result)
            results["json"] = {"status": "ok", "path": str(json_path)}
        except Exception as exc:
            log.error(f"JSON export failed: {exc}")
            results["json"] = {"status": "error", "error": str(exc)}

        # CEF
        try:
            cef_path = self.export_cef(scan_result)
            results["cef"] = {"status": "ok", "path": str(cef_path)}
        except Exception as exc:
            log.error(f"CEF export failed: {exc}")
            results["cef"] = {"status": "error", "error": str(exc)}

        # Syslog UDP (only if host configured)
        if self.siem_host:
            try:
                sent = self.send_syslog(scan_result)
                results["syslog"] = {
                    "status": "ok",
                    "events_sent": sent,
                    "target": f"{self.siem_host}:{self.siem_port}",
                }
            except Exception as exc:
                log.error(f"Syslog export failed: {exc}")
                results["syslog"] = {"status": "error", "error": str(exc)}
        else:
            results["syslog"] = {"status": "skipped", "reason": "SIEM_HOST not configured"}

        return results
