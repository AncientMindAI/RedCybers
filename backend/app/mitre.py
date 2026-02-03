from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from .models import Event


@dataclass
class MitreMatch:
    tactic: str
    technique: str
    technique_id: str
    confidence: int
    rationale: str


_PROC_RULES = [
    (re.compile(r"powershell|pwsh|cmd\.exe|wscript|cscript", re.I), "Execution", "Command and Scripting Interpreter", "T1059", 70),
    (re.compile(r"wmic\.exe|wmic", re.I), "Execution", "Windows Management Instrumentation", "T1047", 70),
    (re.compile(r"rundll32|regsvr32|mshta", re.I), "Defense Evasion", "Signed Binary Proxy Execution", "T1218", 65),
    (re.compile(r"psexec", re.I), "Execution", "Service Execution", "T1569.002", 75),
    (re.compile(r"mimikatz", re.I), "Credential Access", "OS Credential Dumping", "T1003", 80),
    (re.compile(r"certutil", re.I), "Command and Control", "Ingress Tool Transfer", "T1105", 60),
    (re.compile(r"bitsadmin", re.I), "Command and Control", "BITS Jobs", "T1197", 60),
    (re.compile(r"rclone", re.I), "Exfiltration", "Exfiltration Over Web Service", "T1567.002", 70),
]

_PORT_RULES = [
    (3389, "Lateral Movement", "Remote Services: RDP", "T1021.001", 60),
    (22, "Lateral Movement", "Remote Services: SSH", "T1021.004", 60),
    (445, "Lateral Movement", "Remote Services: SMB/Windows Admin Shares", "T1021.002", 55),
    (5985, "Lateral Movement", "Remote Services: WinRM", "T1021.006", 55),
    (5986, "Lateral Movement", "Remote Services: WinRM", "T1021.006", 55),
    (53, "Command and Control", "Application Layer Protocol: DNS", "T1071.004", 55),
    (80, "Command and Control", "Application Layer Protocol: Web", "T1071.001", 50),
    (443, "Command and Control", "Application Layer Protocol: Web", "T1071.001", 50),
]


def map_event(event: Event) -> List[MitreMatch]:
    matches: List[MitreMatch] = []
    proc = event.process_name or ""
    for pattern, tactic, technique, tid, conf in _PROC_RULES:
        if pattern.search(proc):
            matches.append(MitreMatch(tactic, technique, tid, conf, f"process:{pattern.pattern}"))
    for port, tactic, technique, tid, conf in _PORT_RULES:
        if event.remote_port == port:
            matches.append(MitreMatch(tactic, technique, tid, conf, f"port:{port}"))
    return matches


def best_match(matches: List[MitreMatch]) -> MitreMatch | None:
    if not matches:
        return None
    return sorted(matches, key=lambda m: m.confidence, reverse=True)[0]
