"""
ai_engine/report_narrator.py
Generates executive narrative summaries for CISO-level briefings.
Uses the configured AI provider with temperature=0.3 for consistency.
"""
import logging
from typing import TYPE_CHECKING, Any

from ai_engine.ai_provider import get_ai_provider, AIResponse

if TYPE_CHECKING:
    from core.orchestrator import ScanResult

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a cybersecurity communications expert writing for C-suite executives.
Your audience is the CISO and CEO — non-technical leadership who need clear business impact analysis.
Write in plain English. No jargon. No bullet points. Use 2-3 cohesive paragraphs.
Focus on: what happened, business risk, what is being done about it."""


class ReportNarrator:
    """Generates executive-level narrative from scan results."""

    def narrate(self, result: Any) -> str:
        """
        Generate a plain-English executive summary from a ScanResult.
        Returns a 2-3 paragraph narrative suitable for CISO briefing.
        """
        try:
            provider = get_ai_provider()
        except Exception as exc:
            log.warning(f"AI provider init failed for narrator: {exc}")
            return self._fallback_narrative(result)

        # Build summary context
        context = (
            f"Security Scan Results Summary:\n"
            f"- Host: {getattr(result, 'hostname', 'Unknown')}\n"
            f"- Risk Score: {getattr(result, 'threat_score', 0)}/100\n"
            f"- Critical Alerts: {getattr(result, 'critical_count', 0)}\n"
            f"- High Alerts: {getattr(result, 'high_count', 0)}\n"
            f"- Total Alerts: {getattr(result, 'total_alerts', 0)}\n"
            f"- YARA Matches: {len(getattr(result, 'yara_matches', []))}\n"
            f"- Beaconing Detected: {len(getattr(result, 'beaconing_alerts', []))}\n"
            f"- IOC Matches: {len(getattr(result, 'ioc_matches', []))}\n"
            f"- Scan Duration: {getattr(result, 'duration_seconds', 0):.1f}s\n\n"
        )

        alerts = getattr(result, 'alerts', [])
        if alerts:
            context += "Top Findings:\n"
            for alert in sorted(
                alerts,
                key=lambda a: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(
                    getattr(a, 'severity', 'Low'), 4
                ),
            )[:5]:
                context += f"- [{getattr(alert, 'severity', '')}] {getattr(alert, 'message', '')}\n"

        user_prompt = (
            f"Write an executive summary for this security scan:\n\n{context}\n"
            f"Write 2-3 paragraphs for a CISO briefing. Be clear about business risk and recommended actions."
        )

        response: AIResponse = provider.complete(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.3,
            max_tokens=600,
        )

        if response.success and response.content:
            return response.content.strip()

        log.warning(f"Narrator AI call failed: {response.error}")
        return self._fallback_narrative(result)

    def _fallback_narrative(self, result: Any) -> str:
        score = getattr(result, 'threat_score', 0)
        critical = getattr(result, 'critical_count', 0)
        high = getattr(result, 'high_count', 0)
        host = getattr(result, 'hostname', 'the monitored system')
        return (
            f"BlueSentinel v2.0 completed a security assessment of {host} with a risk score of "
            f"{score}/100. The scan identified {critical} critical and {high} high severity findings "
            f"that require immediate attention from the security team.\n\n"
            f"AI narrative generation was unavailable during this scan. Please review the detailed "
            f"findings in the technical sections of this report and prioritize remediation of "
            f"critical and high severity items.\n\n"
            f"The security team should conduct a full review of identified threats and implement "
            f"the recommended remediation actions as soon as possible to reduce organizational risk."
        )
