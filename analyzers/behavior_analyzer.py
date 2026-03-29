"""
analyzers/behavior_analyzer.py
Behavioral analysis engine combining process, network, registry, and event log signals.
Correlates indicators across data sources to detect attack patterns.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


@dataclass
class BehaviorFinding:
    finding_id: str
    category: str
    severity: str
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    mitre_technique: str = ""
    mitre_tactic: str = ""
    confidence: int = 50
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


class BehaviorAnalyzer:
    """Analyzes behavioral patterns from combined data sources."""

    def __init__(self) -> None:
        self._finding_counter = 0

    def _next_id(self, prefix: str) -> str:
        self._finding_counter += 1
        return f"{prefix}-{self._finding_counter:04d}"

    def analyze_process_behavior(self, processes: List[Dict[str, Any]]) -> List[BehaviorFinding]:
        findings = []
        for proc in processes:
            flags = proc.get("suspicious_flags", [])
            if not flags:
                continue

            for flag in flags:
                if "OFFICE_SPAWNING_SHELL" in flag:
                    findings.append(BehaviorFinding(
                        finding_id=self._next_id("BEH"),
                        category="ProcessExecution",
                        severity="High",
                        title="Office Application Spawning Shell",
                        description=f"Suspicious parent-child: {flag}",
                        evidence=[f"PID={proc.get('pid')}", f"Name={proc.get('name')}", flag],
                        mitre_technique="T1566.001",
                        mitre_tactic="Initial Access",
                        confidence=75,
                    ))
                elif "ENCODED_POWERSHELL" in flag:
                    findings.append(BehaviorFinding(
                        finding_id=self._next_id("BEH"),
                        category="DefenseEvasion",
                        severity="High",
                        title="Encoded PowerShell Command Detected",
                        description="PowerShell executed with -EncodedCommand flag",
                        evidence=[f"PID={proc.get('pid')}", flag],
                        mitre_technique="T1059.001",
                        mitre_tactic="Execution",
                        confidence=85,
                    ))
                elif "DOWNLOAD_CRADLE" in flag:
                    findings.append(BehaviorFinding(
                        finding_id=self._next_id("BEH"),
                        category="Execution",
                        severity="Critical",
                        title="PowerShell Download Cradle",
                        description="PowerShell downloading and executing remote content",
                        evidence=[f"PID={proc.get('pid')}", flag],
                        mitre_technique="T1059.001",
                        mitre_tactic="Execution",
                        confidence=90,
                    ))
                elif "EXECUTING_FROM_SUSPICIOUS_PATH" in flag:
                    findings.append(BehaviorFinding(
                        finding_id=self._next_id("BEH"),
                        category="Execution",
                        severity="High",
                        title="Process Executing from Suspicious Path",
                        description=f"Process running from temp/appdata: {proc.get('exe', '')}",
                        evidence=[f"PID={proc.get('pid')}", f"EXE={proc.get('exe')}"],
                        mitre_technique="T1059",
                        mitre_tactic="Execution",
                        confidence=70,
                    ))
        return findings

    def analyze_registry_behavior(self, registry_data: Dict[str, Any]) -> List[BehaviorFinding]:
        findings = []
        changes = registry_data.get("changes", {})
        new_entries = changes.get("new", [])
        modified_entries = changes.get("modified", [])

        for entry in new_entries:
            key_path = entry.get("key_path", "")
            if "Run" in key_path or "RunOnce" in key_path:
                findings.append(BehaviorFinding(
                    finding_id=self._next_id("REG"),
                    category="Persistence",
                    severity="High",
                    title="New Registry Run Key Added",
                    description=f"New autorun entry: {entry.get('name')} = {entry.get('data', '')[:100]}",
                    evidence=[key_path, entry.get("name", ""), entry.get("data", "")[:200]],
                    mitre_technique="T1547.001",
                    mitre_tactic="Persistence",
                    confidence=80,
                ))

        for entry in modified_entries:
            key_path = entry.get("key_path", "")
            if "Winlogon" in key_path:
                findings.append(BehaviorFinding(
                    finding_id=self._next_id("REG"),
                    category="Persistence",
                    severity="Critical",
                    title="Winlogon Registry Key Modified",
                    description=f"Winlogon key modified: {entry.get('name')} changed from '{entry.get('previous_data', '')}' to '{entry.get('data', '')}'",
                    evidence=[key_path, entry.get("name", "")],
                    mitre_technique="T1547.004",
                    mitre_tactic="Persistence",
                    confidence=90,
                ))

        return findings

    def analyze_all(
        self,
        processes: Optional[List[Dict]] = None,
        registry_data: Optional[Dict] = None,
        event_data: Optional[Dict] = None,
    ) -> List[BehaviorFinding]:
        all_findings = []
        if processes:
            all_findings.extend(self.analyze_process_behavior(processes))
        if registry_data:
            all_findings.extend(self.analyze_registry_behavior(registry_data))
        return all_findings
