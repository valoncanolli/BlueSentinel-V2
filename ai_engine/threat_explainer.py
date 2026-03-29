"""
ai_engine/threat_explainer.py
AI-powered threat explanation for individual security findings.
Uses the configured AI provider to produce structured SOC analysis.
"""
import json
import logging
from typing import Any, Dict

from ai_engine.ai_provider import get_ai_provider, AIResponse

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior SOC analyst with 15 years of experience in incident response and \
malware analysis. Provide precise, actionable analysis. No fluff. No disclaimers.

Analyze the security finding and respond ONLY in this exact JSON structure:
{
  "summary": "2-3 sentence technical summary",
  "attack_stage": "MITRE tactic name",
  "severity": "Critical|High|Medium|Low",
  "confidence": 0,
  "immediate_actions": ["action1", "action2", "action3"],
  "evidence_to_collect": ["evidence1", "evidence2"],
  "false_positive_likelihood": "Low|Medium|High",
  "false_positive_reason": "explanation"
}

Respond with valid JSON only. No markdown, no preamble."""

_UNAVAILABLE_RESPONSE = {
    "summary": "AI_UNAVAILABLE",
    "attack_stage": "AI_UNAVAILABLE",
    "severity": "AI_UNAVAILABLE",
    "confidence": 0,
    "immediate_actions": ["AI_UNAVAILABLE"],
    "evidence_to_collect": ["AI_UNAVAILABLE"],
    "false_positive_likelihood": "AI_UNAVAILABLE",
    "false_positive_reason": "AI_UNAVAILABLE",
}


class ThreatExplainer:
    """Generates structured AI analysis for individual security alerts."""

    def explain(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse a single finding dict and return structured JSON analysis.
        Returns _UNAVAILABLE_RESPONSE if AI is unavailable.
        """
        try:
            provider = get_ai_provider()
        except Exception as exc:
            log.warning(f"AI provider init failed: {exc}")
            return dict(_UNAVAILABLE_RESPONSE)

        user_prompt = (
            f"Analyze this security finding:\n\n"
            f"Type: {finding.get('alert_type', finding.get('type', 'Unknown'))}\n"
            f"Severity: {finding.get('severity', 'Unknown')}\n"
            f"Message: {finding.get('message', '')}\n"
            f"MITRE Technique: {finding.get('mitre_technique', 'Unknown')}\n"
            f"Raw Data: {json.dumps(finding.get('raw_data', {}), indent=2)[:2000]}"
        )

        response: AIResponse = provider.complete(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.1,
            max_tokens=800,
        )

        if not response.success or not response.content:
            log.warning(f"AI explain failed: {response.error}")
            return dict(_UNAVAILABLE_RESPONSE)

        try:
            # Strip markdown code blocks if present
            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                content = content.rsplit("```", 1)[0]
            return json.loads(content)
        except json.JSONDecodeError as exc:
            log.error(f"Failed to parse AI JSON response: {exc}\nContent: {response.content[:200]}")
            return dict(_UNAVAILABLE_RESPONSE)
