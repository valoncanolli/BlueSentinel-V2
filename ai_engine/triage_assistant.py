"""
ai_engine/triage_assistant.py
Batch alert triage via AI. Groups attack chains, ranks by risk, identifies false positives.
"""
import json
import logging
from typing import Any, Dict, List

from ai_engine.ai_provider import get_ai_provider, AIResponse

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a SOC Tier-2 analyst doing alert triage. Analyze the alert list and:
1. Identify which alerts form the same attack chain
2. Rank by actual organizational risk (not just technical severity)
3. Identify likely false positives with reasoning
4. Provide the first 3 concrete investigation steps

Return ONLY valid JSON. No markdown, no preamble:
{
  "ranked_alerts": [{"alert_id": "...", "rank": 1, "reason": "..."}],
  "attack_chains": [{"chain_id": "...", "alerts": ["id1", "id2"], "description": "..."}],
  "false_positives": [{"alert_id": "...", "reason": "..."}],
  "investigation_steps": ["step1", "step2", "step3"]
}"""

_UNAVAILABLE = {
    "ranked_alerts": [],
    "attack_chains": [],
    "false_positives": [],
    "investigation_steps": ["AI triage unavailable — manually review alerts by severity"],
}


class TriageAssistant:
    """Performs batch AI-powered triage on a list of alerts."""

    def triage(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Triage a list of alert dicts. Returns structured triage result.
        Only calls AI if alert count > 5.
        """
        if len(alerts) <= 5:
            return {
                "ranked_alerts": [
                    {"alert_id": a.get("alert_id", str(i)), "rank": i + 1, "reason": "Auto-ranked by severity"}
                    for i, a in enumerate(
                        sorted(alerts, key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x.get("severity", "Low"), 4))
                    )
                ],
                "attack_chains": [],
                "false_positives": [],
                "investigation_steps": ["Review critical and high severity alerts first"],
            }

        try:
            provider = get_ai_provider()
        except Exception as exc:
            log.warning(f"AI provider init failed: {exc}")
            return dict(_UNAVAILABLE)

        # Summarize alerts for prompt (avoid huge payloads)
        alert_summaries = []
        for a in alerts[:50]:  # cap at 50
            alert_summaries.append({
                "alert_id": a.get("alert_id", ""),
                "severity": a.get("severity", ""),
                "type": a.get("alert_type", a.get("type", "")),
                "message": a.get("message", "")[:200],
                "mitre_technique": a.get("mitre_technique", ""),
                "timestamp": a.get("timestamp", ""),
            })

        user_prompt = (
            f"Triage these {len(alerts)} security alerts:\n\n"
            f"{json.dumps(alert_summaries, indent=2)}"
        )

        response: AIResponse = provider.complete(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.1,
            max_tokens=2000,
        )

        if not response.success or not response.content:
            log.warning(f"AI triage failed: {response.error}")
            return dict(_UNAVAILABLE)

        try:
            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                content = content.rsplit("```", 1)[0]
            return json.loads(content)
        except json.JSONDecodeError as exc:
            log.error(f"Triage JSON parse error: {exc}")
            return dict(_UNAVAILABLE)
