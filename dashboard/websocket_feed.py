"""
dashboard/websocket_feed.py
Socket.IO event broadcasting module for BlueSentinel v2.0.
Provides typed helper functions to emit standardised events to connected dashboard clients.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event name constants
# ---------------------------------------------------------------------------

EVENT_SCAN_STARTED = "scan_started"
EVENT_NEW_ALERT = "new_alert"
EVENT_SCAN_PROGRESS = "scan_progress"
EVENT_RISK_SCORE_UPDATE = "risk_score_update"
EVENT_SCAN_COMPLETE = "scan_complete"
EVENT_NEWS_FEED = "news_feed"
EVENT_AI_ANALYSIS_READY = "ai_analysis_ready"
EVENT_METRICS_UPDATE = "metrics_update"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_socketio(app=None):
    """
    Retrieve the SocketIO instance from the Flask app extensions,
    or from the module-level singleton if app is not provided.
    """
    if app is not None:
        return app.extensions.get("socketio")
    # Try to import from dashboard.app as a fallback
    try:
        from dashboard.app import create_app  # noqa: F401
        import flask
        current_app = flask.current_app._get_current_object()
        return current_app.extensions.get("socketio")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Broadcast helpers
# ---------------------------------------------------------------------------

def emit_scan_started(
    socketio,
    scan_id: str,
    mode: str,
    hostname: str,
    ai_provider: str,
) -> None:
    """
    Broadcast scan_started event to all connected dashboard clients.

    Payload:
        scan_id     : Unique scan identifier (e.g. "AB12CD34")
        mode        : Scan mode ("full-scan", "quick-scan", "network-only", "file-only")
        hostname    : Target host
        ai_provider : Active AI provider name ("openai" | "claude")
        timestamp   : UTC ISO timestamp
    """
    if socketio is None:
        log.warning("emit_scan_started: SocketIO instance is None")
        return
    payload: Dict[str, Any] = {
        "scan_id": scan_id,
        "mode": mode,
        "hostname": hostname,
        "ai_provider": ai_provider,
        "timestamp": _utc_now(),
    }
    try:
        socketio.emit(EVENT_SCAN_STARTED, payload)
        log.debug(f"Emitted {EVENT_SCAN_STARTED}: scan_id={scan_id} mode={mode}")
    except Exception as exc:
        log.error(f"Failed to emit {EVENT_SCAN_STARTED}: {exc}")


def emit_new_alert(
    socketio,
    alert_id: str,
    severity: str,
    alert_type: str,
    message: str,
    mitre_technique: str = "",
    mitre_tactic: str = "",
    source_module: str = "",
    timestamp: Optional[str] = None,
    ai_analysis: Optional[Dict] = None,
) -> None:
    """
    Broadcast new_alert event when a threat alert is generated during a scan.

    Payload fields map directly to the Alert dataclass from core/orchestrator.py.
    """
    if socketio is None:
        log.warning("emit_new_alert: SocketIO instance is None")
        return
    payload: Dict[str, Any] = {
        "alert_id": alert_id,
        "severity": severity,
        "alert_type": alert_type,
        "message": message,
        "mitre_technique": mitre_technique,
        "mitre_tactic": mitre_tactic,
        "source_module": source_module,
        "timestamp": timestamp or _utc_now(),
        "ai_analysis": ai_analysis,
    }
    try:
        socketio.emit(EVENT_NEW_ALERT, payload)
        log.debug(f"Emitted {EVENT_NEW_ALERT}: {alert_id} [{severity}]")
    except Exception as exc:
        log.error(f"Failed to emit {EVENT_NEW_ALERT}: {exc}")


def emit_scan_progress(
    socketio,
    phase: str,
    module: str,
    percent: int,
    message: str = "",
    scan_id: str = "",
) -> None:
    """
    Broadcast scan_progress event for dashboard progress bar updates.

    Args:
        phase   : Current scan phase name ("COLLECTION", "ANALYSIS", "AI", "REPORTING")
        module  : Current module name (e.g. "yara_engine")
        percent : Overall completion percentage 0-100
        message : Optional human-readable status message
        scan_id : Active scan ID
    """
    if socketio is None:
        return
    payload: Dict[str, Any] = {
        "phase": phase,
        "module": module,
        "percent": max(0, min(100, percent)),
        "message": message,
        "scan_id": scan_id,
        "timestamp": _utc_now(),
    }
    try:
        socketio.emit(EVENT_SCAN_PROGRESS, payload)
        log.debug(f"Emitted {EVENT_SCAN_PROGRESS}: {phase}/{module} {percent}%")
    except Exception as exc:
        log.error(f"Failed to emit {EVENT_SCAN_PROGRESS}: {exc}")


def emit_risk_score_update(
    socketio,
    score: int,
    previous_score: int = 0,
    scan_id: str = "",
) -> None:
    """
    Broadcast risk_score_update event to animate the risk gauge on the dashboard.

    Args:
        score          : New risk score 0-100
        previous_score : Previous risk score (used to calculate delta/trend)
        scan_id        : Associated scan ID
    """
    if socketio is None:
        return
    delta = score - previous_score
    risk_level_map = {
        (86, 100): "Critical",
        (61, 85): "High",
        (31, 60): "Medium",
        (1, 30): "Low",
        (0, 0): "Clean",
    }
    risk_level = next(
        (label for (low, high), label in risk_level_map.items() if low <= score <= high),
        "Low",
    )
    payload: Dict[str, Any] = {
        "score": max(0, min(100, score)),
        "previous_score": previous_score,
        "delta": delta,
        "risk_level": risk_level,
        "scan_id": scan_id,
        "timestamp": _utc_now(),
    }
    try:
        socketio.emit(EVENT_RISK_SCORE_UPDATE, payload)
        log.debug(f"Emitted {EVENT_RISK_SCORE_UPDATE}: score={score} delta={delta:+d}")
    except Exception as exc:
        log.error(f"Failed to emit {EVENT_RISK_SCORE_UPDATE}: {exc}")


def emit_scan_complete(
    socketio,
    scan_id: str,
    threat_score: int,
    total_alerts: int,
    critical_count: int,
    high_count: int,
    duration_seconds: float,
    ai_provider: str = "",
    error: Optional[str] = None,
) -> None:
    """
    Broadcast scan_complete event when the full scan pipeline finishes.
    Triggers a full chart refresh on the dashboard.
    """
    if socketio is None:
        return
    payload: Dict[str, Any] = {
        "scan_id": scan_id,
        "threat_score": threat_score,
        "total_alerts": total_alerts,
        "critical_count": critical_count,
        "high_count": high_count,
        "duration_seconds": round(duration_seconds, 1),
        "ai_provider": ai_provider,
        "timestamp": _utc_now(),
        "error": error,
    }
    try:
        socketio.emit(EVENT_SCAN_COMPLETE, payload)
        log.info(f"Emitted {EVENT_SCAN_COMPLETE}: scan_id={scan_id} score={threat_score} alerts={total_alerts}")
    except Exception as exc:
        log.error(f"Failed to emit {EVENT_SCAN_COMPLETE}: {exc}")


def emit_news_feed(
    socketio,
    items: List[Dict[str, str]],
) -> None:
    """
    Broadcast news_feed event to update the news ticker at the bottom of the dashboard.

    Each item in `items` should be a dict with:
        - title   : News headline
        - source  : Source name (e.g. "OTX", "MISP", "NVD")
        - url     : Optional link
        - severity: Optional severity classification
    """
    if socketio is None:
        return
    payload: Dict[str, Any] = {
        "items": items,
        "count": len(items),
        "timestamp": _utc_now(),
    }
    try:
        socketio.emit(EVENT_NEWS_FEED, payload)
        log.debug(f"Emitted {EVENT_NEWS_FEED}: {len(items)} items")
    except Exception as exc:
        log.error(f"Failed to emit {EVENT_NEWS_FEED}: {exc}")


def emit_ai_analysis_ready(
    socketio,
    alert_id: str,
    analysis: Dict[str, Any],
    scan_id: str = "",
) -> None:
    """
    Broadcast ai_analysis_ready event when AI has finished analysing a specific alert.
    Dashboard uses this to update the expandable row with AI explanation.

    Args:
        alert_id : The alert that was analysed
        analysis : AI analysis dict (from ThreatExplainer.explain())
        scan_id  : Associated scan ID
    """
    if socketio is None:
        return
    payload: Dict[str, Any] = {
        "alert_id": alert_id,
        "analysis": analysis,
        "scan_id": scan_id,
        "timestamp": _utc_now(),
    }
    try:
        socketio.emit(EVENT_AI_ANALYSIS_READY, payload)
        log.debug(f"Emitted {EVENT_AI_ANALYSIS_READY}: alert_id={alert_id}")
    except Exception as exc:
        log.error(f"Failed to emit {EVENT_AI_ANALYSIS_READY}: {exc}")


def emit_metrics_update(
    socketio,
    metrics: Dict[str, Any],
) -> None:
    """
    Broadcast a general metrics update (KPI counts, provider status, etc).
    Used by the dashboard to refresh counters without a full page reload.
    """
    if socketio is None:
        return
    payload = {**metrics, "timestamp": _utc_now()}
    try:
        socketio.emit(EVENT_METRICS_UPDATE, payload)
    except Exception as exc:
        log.error(f"Failed to emit {EVENT_METRICS_UPDATE}: {exc}")


# ---------------------------------------------------------------------------
# Convenience: broadcast a full ScanResult-like dict as a sequence of events
# ---------------------------------------------------------------------------

def broadcast_scan_result(socketio, result_dict: Dict[str, Any]) -> None:
    """
    Emit all relevant events from a completed scan result dict.
    This is called after a background scan completes to push all data to clients.
    """
    if socketio is None:
        log.warning("broadcast_scan_result: SocketIO is None — skipping broadcast")
        return

    scan_id = result_dict.get("scan_id", "")
    score = result_dict.get("threat_score", 0)
    alerts = result_dict.get("alerts", [])
    critical = sum(1 for a in alerts if a.get("severity") == "Critical")
    high = sum(1 for a in alerts if a.get("severity") == "High")

    # Push risk score update
    emit_risk_score_update(socketio, score=score, scan_id=scan_id)

    # Push each alert (up to 50 most recent to avoid flooding)
    for alert in alerts[-50:]:
        emit_new_alert(
            socketio,
            alert_id=alert.get("alert_id", ""),
            severity=alert.get("severity", ""),
            alert_type=alert.get("type", alert.get("alert_type", "")),
            message=alert.get("message", ""),
            mitre_technique=alert.get("mitre_technique", ""),
            mitre_tactic=alert.get("mitre_tactic", ""),
            source_module=alert.get("source_module", ""),
            timestamp=alert.get("timestamp"),
            ai_analysis=alert.get("ai_analysis"),
        )

    # Push completion event
    emit_scan_complete(
        socketio,
        scan_id=scan_id,
        threat_score=score,
        total_alerts=len(alerts),
        critical_count=critical,
        high_count=high,
        duration_seconds=result_dict.get("duration_seconds", 0),
        ai_provider=result_dict.get("ai_provider_used", ""),
    )
