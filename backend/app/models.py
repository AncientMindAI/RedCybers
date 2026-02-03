from __future__ import annotations

from datetime import datetime
from typing import List

from pydantic import BaseModel, Field


class Event(BaseModel):
    ts: str
    pid: int
    process_name: str
    process_path: str
    user: str
    direction: str
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    bytes_sent: int = 0
    bytes_recv: int = 0

    is_public: bool = False
    remote_country: str = ""
    remote_region: str = ""
    remote_city: str = ""
    remote_org: str = ""
    remote_asn: str = ""
    remote_hostname: str = ""
    remote_loc: str = ""
    remote_timezone: str = ""
    threat_sources: List[str] = Field(default_factory=list)
    threat_score: int = 0
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_technique_id: str = ""
    mitre_confidence: int = 0
    relevance_score: int = 0
    suppressed: bool = False
    suppression_reason: str = ""

    @staticmethod
    def now_iso() -> str:
        return datetime.utcnow().isoformat() + "Z"
