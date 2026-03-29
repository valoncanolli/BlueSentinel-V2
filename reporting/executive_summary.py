"""
reporting/executive_summary.py
AI-powered executive summary generator for BlueSentinel v2.0.
Uses the configured AI provider to produce structured, non-technical summaries
suitable for C-suite / management consumption.
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ThreatOverview:
    """High-level threat landscape snapshot."""
    risk_level: str          # Critical / High / Medium / Low / Clean
    risk_score: int          # 0-100
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    affected_systems: List[str] = field(default_factory=list)
    primary_threats: List[str] = field(default_factory=list)


@dataclass
class KeyFinding:
    """A single key finding with business impact context."""
    title: str
    description: str
    severity: str
    mitre_technique: Optional[str] = None
    recommended_action: str = ""


@dataclass
class ExecutiveSummary:
    """Structured executive summary returned by generate_executive_summary()."""
    scan_id: str
    generated_at: str
    hostname: str
    ai_provider: str
    ai_model: str
    threat_overview: ThreatOverview
    key_findings: List[KeyFinding]
    business_impact: str
    immediate_recommendations: List[str]
    strategic_recommendations: List[str]
    narrative: str          # Free-form AI-generated paragraph
    confidence_note: str    # Disclaimer / confidence statement
    ai_tokens_used: int = 0
    ai_success: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "generated_at": self.generated_at,
            "hostname": self.hostname,
            "ai_provider": self.ai_provider,
            "ai_model": self.ai_model,
            "threat_overview": {
                "risk_level": self.threat_overview.risk_level,
                "risk_score": self.threat_overview.risk_score,
                "total_alerts": self.threat_overview.total_alerts,
                "critical_alerts": self.threat_overview.critical_alerts,
                "high_alerts": self.threat_overview.high_alerts,
                "affected_systems": self.threat_overview.affected_systems,
                "primary_threats": self.threat_overview.primary_threats,
            },
            "key_findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "mitre_technique": f.mitre_technique,
                    "recommended_action": f.recommended_action,
                }
                for f in self.key_findings
            ],
            "business_impact": self.business_impact,
            "immediate_recommendations": self.immediate_recommendations,
            "strategic_recommendations": self.strategic_recommendations,
            "narrative": self.narrative,
            "confidence_note": self.confidence_note,
            "ai_tokens_used": self.ai_tokens_used,
            "ai_success": self.ai_success,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_RISK_LABELS = {
    (86, 100): "Critical",
    (61, 85):  "High",
    (31, 60):  "Medium",
    (1, 30):   "Low",
    (0, 0):    "Clean",
}


def _score_to_risk_level(score: int) -> str:
    for (low, high), label in _RISK_LABELS.items():
        if low <= score <= high:
            return label
    return "Low"


def _extract_threat_categories(alerts: List[Dict]) -> List[str]:
    """Derive primary threat categories from alert types."""
    categories: Dict[str, int] = {}
    category_map = {
        "YARA_MATCH": "Malware Detection",
        "BEACONING": "Command & Control Beaconing",
        "IOC_MATCH": "Known Malicious Indicator",
        "PROCESS_HOLLOW": "Process Injection / Hollowing",
        "ENCODED_POWERSHELL": "Obfuscated PowerShell Execution",
        "DOWNLOAD_CRADLE": "Remote Code Download",
        "OFFICE_SPAWN": "Office Macro Execution",
        "REGISTRY": "Persistence via Registry",
        "PREFETCH": "Suspicious Binary Execution",
    }
    for alert in alerts:
        atype = alert.get("type", alert.get("alert_type", "")).upper()
        for key, label in category_map.items():
            if key in atype:
                categories[label] = categories.get(label, 0) + 1
                break
        else:
            if atype:
                categories[atype] = categories.get(atype, 0) + 1
    return sorted(categories, key=lambda k: categories[k], reverse=True)[:5]


def _build_system_prompt() -> str:
    return """You are a senior cybersecurity analyst generating an executive summary for a C-suite audience.
Your summary must be:
1. Non-technical — no jargon, no acronyms without explanation
2. Business-focused — emphasize operational and financial risk
3. Concise — 3-5 sentences per section
4. Actionable — concrete next steps with clear ownership
5. Honest — do not minimize real risks, but avoid alarmism for low-risk findings

You will receive a JSON object with scan results. Return a JSON object with this exact schema:
{
  "narrative": "<3-5 sentence executive summary paragraph>",
  "business_impact": "<description of potential business impact>",
  "immediate_recommendations": ["<action 1>", "<action 2>", ...],
  "strategic_recommendations": ["<recommendation 1>", ...],
  "key_findings_summaries": [
    {"title": "...", "description": "...", "recommended_action": "..."}
  ],
  "confidence_note": "<caveat about automated analysis limitations>"
}

Return ONLY valid JSON, no markdown, no extra text."""


def _build_user_prompt(data: Dict[str, Any]) -> str:
    """Build a condensed scan summary for the AI prompt."""
    alerts = data.get("alerts", [])
    critical = sum(1 for a in alerts if a.get("severity") == "Critical")
    high = sum(1 for a in alerts if a.get("severity") == "High")
    medium = sum(1 for a in alerts if a.get("severity") == "Medium")
    threat_categories = _extract_threat_categories(alerts)

    # Top 5 most severe alerts for context
    sorted_alerts = sorted(
        alerts,
        key=lambda a: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(a.get("severity", "Low"), 0),
        reverse=True,
    )
    top_alerts = [
        {
            "message": a.get("message", ""),
            "severity": a.get("severity", ""),
            "type": a.get("type", a.get("alert_type", "")),
            "mitre_technique": a.get("mitre_technique", ""),
        }
        for a in sorted_alerts[:5]
    ]

    summary = {
        "scan_id": data.get("scan_id", ""),
        "hostname": data.get("hostname", ""),
        "scan_time": data.get("started_at", ""),
        "duration_seconds": data.get("duration_seconds", 0),
        "threat_score": data.get("threat_score", 0),
        "risk_level": _score_to_risk_level(data.get("threat_score", 0)),
        "alert_counts": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": sum(1 for a in alerts if a.get("severity") == "Low"),
            "total": len(alerts),
        },
        "threat_categories": threat_categories,
        "top_alerts": top_alerts,
        "yara_matches": len(data.get("yara_matches", [])),
        "beaconing_detections": len(data.get("beaconing_alerts", [])),
        "ioc_matches": len(data.get("ioc_matches", [])),
        "ai_summary_from_scan": data.get("ai_summary", ""),
    }
    return json.dumps(summary, indent=2, default=str)


def _fallback_narrative(data: Dict[str, Any]) -> str:
    """Generate a basic narrative when AI is unavailable."""
    score = data.get("threat_score", 0)
    risk = _score_to_risk_level(score)
    alerts = data.get("alerts", [])
    critical = sum(1 for a in alerts if a.get("severity") == "Critical")
    high = sum(1 for a in alerts if a.get("severity") == "High")
    hostname = data.get("hostname", "the monitored host")

    if score == 0:
        return (
            f"The BlueSentinel security scan of {hostname} completed with no threat indicators detected. "
            "All monitored systems appear to be operating within normal parameters. "
            "Continued monitoring is recommended as part of routine security hygiene."
        )

    return (
        f"The BlueSentinel security scan of {hostname} identified a {risk.upper()} risk posture "
        f"with a composite threat score of {score}/100. "
        f"The scan detected {critical} critical and {high} high severity alerts requiring immediate attention. "
        "Security operations personnel should review the full technical report and initiate incident response "
        "procedures as appropriate for the identified threat level."
    )


# ---------------------------------------------------------------------------
# Main generator function
# ---------------------------------------------------------------------------

def generate_executive_summary(
    scan_result: Union[Dict[str, Any], Any],
    use_ai: bool = True,
) -> ExecutiveSummary:
    """
    Generate a structured executive summary from a BlueSentinel scan result.

    Args:
        scan_result: ScanResult object or dict from scan_result.to_dict()
        use_ai: If True, use the configured AI provider for narrative generation.
                If False (or AI unavailable), uses rule-based fallback.

    Returns:
        ExecutiveSummary dataclass instance with all fields populated.
    """
    if hasattr(scan_result, "to_dict"):
        data = scan_result.to_dict()
    else:
        data = dict(scan_result)

    scan_id = data.get("scan_id", "UNKNOWN")
    hostname = data.get("hostname", "unknown")
    alerts = data.get("alerts", [])
    score = data.get("threat_score", 0)
    risk_level = _score_to_risk_level(score)
    critical_count = sum(1 for a in alerts if a.get("severity") == "Critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "High")
    threat_categories = _extract_threat_categories(alerts)

    # Build threat overview
    overview = ThreatOverview(
        risk_level=risk_level,
        risk_score=score,
        total_alerts=len(alerts),
        critical_alerts=critical_count,
        high_alerts=high_count,
        affected_systems=[hostname],
        primary_threats=threat_categories,
    )

    # Build key findings from top alerts
    sorted_alerts = sorted(
        alerts,
        key=lambda a: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(a.get("severity", "Low"), 0),
        reverse=True,
    )
    key_findings: List[KeyFinding] = []
    for alert in sorted_alerts[:5]:
        severity = alert.get("severity", "Medium")
        atype = alert.get("type", alert.get("alert_type", ""))
        message = alert.get("message", "")
        mitre = alert.get("mitre_technique")

        action_map = {
            "YARA_MATCH": "Quarantine the affected file and perform full disk forensics.",
            "BEACONING": "Block outbound traffic to the identified destination and investigate the source process.",
            "IOC_MATCH": "Isolate affected system and initiate threat hunting for lateral movement.",
            "ENCODED_POWERSHELL": "Review PowerShell execution logs and disable execution if not required.",
            "DOWNLOAD_CRADLE": "Block the download source and review execution chain.",
            "PROCESS_HOLLOW": "Terminate suspicious processes and capture memory dump for forensic analysis.",
        }
        recommended_action = next(
            (v for k, v in action_map.items() if k in atype.upper()),
            "Investigate the alert and consult the technical report for remediation steps.",
        )

        key_findings.append(KeyFinding(
            title=f"{severity} — {atype.replace('_', ' ').title()}",
            description=message[:300] if message else f"A {severity.lower()} severity indicator was detected.",
            severity=severity,
            mitre_technique=mitre,
            recommended_action=recommended_action,
        ))

    # Default values (will be overridden by AI if available)
    narrative = _fallback_narrative(data)
    business_impact = (
        "Potential data breach, ransomware deployment, or unauthorized access to sensitive systems. "
        "Estimated containment and recovery costs depend on threat scope."
        if score >= 61
        else "Low immediate business risk. Continue monitoring and apply security patches promptly."
    )
    immediate_recs = [
        "Review all Critical and High severity alerts in the BlueSentinel dashboard.",
        "Isolate affected systems from the network pending investigation.",
        "Engage incident response team if beaconing or C2 activity is confirmed.",
        "Preserve system logs and memory dumps for forensic analysis.",
    ] if score >= 31 else [
        "No immediate action required.",
        "Review Medium alerts during next maintenance window.",
        "Ensure endpoint protection signatures are up to date.",
    ]
    strategic_recs = [
        "Deploy endpoint detection and response (EDR) tooling on all endpoints.",
        "Implement network segmentation to limit lateral movement opportunities.",
        "Establish a formal incident response plan and test it quarterly.",
        "Conduct regular purple team exercises to validate detection capabilities.",
        "Enforce least-privilege access and privileged access management (PAM).",
    ]
    confidence_note = (
        "This summary was generated by BlueSentinel v2.0 automated analysis. "
        "All findings should be validated by a qualified cybersecurity professional. "
        "Automated analysis may produce false positives; human review is essential before taking disruptive action."
    )

    ai_provider_name = "none"
    ai_model_name = "none"
    ai_tokens = 0
    ai_success = False

    if use_ai:
        try:
            from ai_engine.ai_provider import get_ai_provider
            provider = get_ai_provider()
            ai_provider_name = provider.__class__.__name__.replace("Provider", "").lower()

            system_prompt = _build_system_prompt()
            user_prompt = _build_user_prompt(data)

            response = provider.complete(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.2,
                max_tokens=2000,
            )

            ai_tokens = response.tokens_used
            ai_model_name = response.model

            if response.success and response.content:
                # Parse the JSON response
                content = response.content.strip()
                # Strip markdown code blocks if present
                if content.startswith("```"):
                    lines = content.split("\n")
                    content = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

                ai_data = json.loads(content)

                narrative = ai_data.get("narrative", narrative)
                business_impact = ai_data.get("business_impact", business_impact)
                immediate_recs = ai_data.get("immediate_recommendations", immediate_recs)
                strategic_recs = ai_data.get("strategic_recommendations", strategic_recs)
                confidence_note = ai_data.get("confidence_note", confidence_note)
                ai_success = True

                # Override key findings summaries if AI provided them
                ai_findings = ai_data.get("key_findings_summaries", [])
                for i, ai_finding in enumerate(ai_findings[:5]):
                    if i < len(key_findings):
                        key_findings[i].description = ai_finding.get("description", key_findings[i].description)
                        key_findings[i].recommended_action = ai_finding.get(
                            "recommended_action", key_findings[i].recommended_action
                        )
                    else:
                        key_findings.append(KeyFinding(
                            title=ai_finding.get("title", f"Finding {i+1}"),
                            description=ai_finding.get("description", ""),
                            severity="Medium",
                            recommended_action=ai_finding.get("recommended_action", ""),
                        ))

                log.info(f"Executive summary AI generation successful ({ai_tokens} tokens)")

            else:
                log.warning(f"AI provider returned error: {response.error}. Using fallback narrative.")

        except json.JSONDecodeError as exc:
            log.warning(f"AI response was not valid JSON: {exc}. Using fallback narrative.")
        except Exception as exc:
            log.error(f"Executive summary AI generation failed: {exc}")

    return ExecutiveSummary(
        scan_id=scan_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        hostname=hostname,
        ai_provider=ai_provider_name,
        ai_model=ai_model_name,
        threat_overview=overview,
        key_findings=key_findings,
        business_impact=business_impact,
        immediate_recommendations=immediate_recs,
        strategic_recommendations=strategic_recs,
        narrative=narrative,
        confidence_note=confidence_note,
        ai_tokens_used=ai_tokens,
        ai_success=ai_success,
    )
