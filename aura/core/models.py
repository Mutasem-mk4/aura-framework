from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class TargetStatus(str, Enum):
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class Target(BaseModel):
    id: Optional[int] = None
    value: str
    type: str = "domain"
    source: str = "manual"
    risk_score: int = 0
    priority: str = "LOW"
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    status: TargetStatus = TargetStatus.ACTIVE

    class Config:
        from_attributes = True

class Finding(BaseModel):
    id: Optional[int] = None
    target_id: Optional[int] = None
    target_value: Optional[str] = None
    content: str
    finding_type: str = "Vulnerability"
    severity: Severity = Severity.MEDIUM
    created_at: datetime = Field(default_factory=datetime.now)
    owasp: str = "A00:2021-Unknown"
    mitre: str = "T1592"
    campaign_id: Optional[int] = None
    proof: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True

class Campaign(BaseModel):
    id: Optional[int] = None
    name: str
    target_config: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    status: str = "ACTIVE"

    class Config:
        from_attributes = True

class AuditLog(BaseModel):
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    action: str
    target: str
    details: str = ""
    campaign_id: Optional[int] = None

    class Config:
        from_attributes = True
