from sqlalchemy import Column, Integer, String, DateTime, Float, Text, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from datetime import datetime
from typing import List, Optional, Any, Dict
import os

from aura.core.models import Target as DomainTarget
from aura.core.models import Finding as DomainFinding
from aura.core.models import Campaign as DomainCampaign
from aura.core.models import AuditLog as DomainAuditLog
from aura.core.repository import ITargetRepository, IFindingRepository, ICampaignRepository, IAuditRepository

Base = declarative_base()

class DBTarget(Base):
    __tablename__ = 'targets'
    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String, unique=True, index=True)
    type = Column(String, default="domain")
    source = Column(String, default="manual")
    risk_score = Column(Integer, default=0)
    priority = Column(String, default="LOW")
    first_seen = Column(DateTime, default=datetime.now)
    last_seen = Column(DateTime, default=datetime.now)
    status = Column(String, default="ACTIVE")
    
    findings = relationship("DBFinding", back_populates="target")

class DBFinding(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey('targets.id'))
    content = Column(Text)
    finding_type = Column(String, default="Vulnerability")
    created_at = Column(DateTime, default=datetime.now)
    owasp = Column(String)
    mitre = Column(String)
    severity = Column(String, default="MEDIUM")
    status = Column(String, default="UNREVIEWED")
    campaign_id = Column(Integer, ForeignKey('campaigns.id'))
    proof = Column(Text)
    cvss_score = Column(Float)
    cvss_vector = Column(String)
    remediation_fix = Column(Text)
    impact_desc = Column(Text)
    patch_priority = Column(String)
    evidence_url = Column(Text)
    secret_type = Column(String)
    secret_value = Column(Text)
    poc_link = Column(Text)
    raw_request = Column(Text)
    raw_response = Column(Text)
    
    __table_args__ = (UniqueConstraint("target_id", "content", "finding_type", name="uq_finding"),)
    
    target = relationship("DBTarget", back_populates="findings")
    campaign = relationship("DBCampaign", back_populates="findings")

class DBCampaign(Base):
    __tablename__ = 'campaigns'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    target_config = Column(JSON)
    created_at = Column(DateTime, default=datetime.now)
    status = Column(String, default="ACTIVE")
    
    findings = relationship("DBFinding", back_populates="campaign")

class DBAuditLog(Base):
    __tablename__ = 'audit_log'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.now)
    action = Column(String)
    target = Column(String)
    details = Column(Text)
    campaign_id = Column(Integer, ForeignKey('campaigns.id'))

class DBSovereignIntel(Base):
    __tablename__ = 'sovereign_intelligence'
    id = Column(Integer, primary_key=True, autoincrement=True)
    tech_stack = Column(String)
    vulnerability_type = Column(String)
    successful_payload = Column(Text)
    success_rate = Column(Float, default=1.0)
    first_discovery = Column(DateTime, default=datetime.now)
    last_applied = Column(DateTime, default=datetime.now)

class DBMissionState(Base):
    __tablename__ = 'mission_states'
    target_value = Column(String, primary_key=True)
    current_step = Column(String)
    findings_count = Column(Integer, default=0)
    urls_discovered = Column(Integer, default=0)
    last_update = Column(DateTime, default=datetime.now)
    state_json = Column(JSON)

# Repository Implementations
class TargetRepository(ITargetRepository):
    def __init__(self, session_factory):
        self.session_factory = session_factory
    
    def save(self, target: DomainTarget) -> int:
        with self.session_factory() as session:
            db_target = session.query(DBTarget).filter_by(value=target.value).first()
            if db_target:
                db_target.last_seen = datetime.now()
                db_target.risk_score = max(db_target.risk_score, target.risk_score)
                db_target.status = target.status
            else:
                db_target = DBTarget(**target.dict(exclude={'id'}))
                session.add(db_target)
            session.commit()
            return db_target.id

    def get_by_id(self, target_id: int) -> Optional[DomainTarget]:
        with self.session_factory() as session:
            db_target = session.query(DBTarget).get(target_id)
            return DomainTarget.from_attributes(db_target) if db_target else None

    def get_by_value(self, value: str) -> Optional[DomainTarget]:
        with self.session_factory() as session:
            db_target = session.query(DBTarget).filter_by(value=value).first()
            return DomainTarget.from_attributes(db_target) if db_target else None

    def get_all_active(self) -> List[DomainTarget]:
        with self.session_factory() as session:
            targets = session.query(DBTarget).filter_by(status="ACTIVE").all()
            return [DomainTarget.from_attributes(t) for t in targets]

class FindingRepository(IFindingRepository):
    def __init__(self, session_factory):
        self.session_factory = session_factory
    
    def add(self, finding: DomainFinding) -> None:
        with self.session_factory() as session:
            db_finding = DBFinding(**finding.dict(exclude={'id', 'target_value', 'meta'}))
            session.add(db_finding)
            session.commit()

    def get_by_target(self, target_id: int) -> List[DomainFinding]:
        with self.session_factory() as session:
            findings = session.query(DBFinding).filter_by(target_id=target_id).all()
            return [DomainFinding.from_attributes(f) for f in findings]

    def get_all(self) -> List[DomainFinding]:
        with self.session_factory() as session:
            findings = session.query(DBFinding).all()
            return [DomainFinding.from_attributes(f) for f in findings]

class CampaignRepository(ICampaignRepository):
    def __init__(self, session_factory):
        self.session_factory = session_factory
    
    def create(self, campaign: DomainCampaign) -> int:
        with self.session_factory() as session:
            db_campaign = DBCampaign(**campaign.dict(exclude={'id'}))
            session.add(db_campaign)
            session.commit()
            return db_campaign.id

    def get_by_id(self, campaign_id: int) -> Optional[DomainCampaign]:
        with self.session_factory() as session:
            db_campaign = session.query(DBCampaign).get(campaign_id)
            return DomainCampaign.from_attributes(db_campaign) if db_campaign else None

class AuditRepository(IAuditRepository):
    def __init__(self, session_factory):
        self.session_factory = session_factory
    
    def log(self, entry: DomainAuditLog) -> None:
        with self.session_factory() as session:
            db_log = DBAuditLog(**entry.dict(exclude={'id'}))
            session.add(db_log)
            session.commit()

    def get_logs(self, campaign_id: Optional[int] = None) -> List[DomainAuditLog]:
        with self.session_factory() as session:
            query = session.query(DBAuditLog)
            if campaign_id:
                query = query.filter_by(campaign_id=campaign_id)
            logs = query.order_by(DBAuditLog.timestamp.desc()).all()
            return [DomainAuditLog.from_attributes(l) for l in logs]

class SovereignIntelRepository:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    def save(self, tech_stack: str, vuln_type: str, payload: str):
        with self.session_factory() as session:
            intel = session.query(DBSovereignIntel).filter_by(
                tech_stack=tech_stack, 
                vulnerability_type=vuln_type, 
                successful_payload=payload
            ).first()
            if intel:
                intel.success_rate += 0.1
                intel.last_applied = datetime.now()
            else:
                intel = DBSovereignIntel(
                    tech_stack=tech_stack, 
                    vulnerability_type=vuln_type, 
                    successful_payload=payload
                )
                session.add(intel)
            session.commit()

    def get_by_tech(self, tech_stack: str) -> List[DBSovereignIntel]:
        with self.session_factory() as session:
            return session.query(DBSovereignIntel).filter(
                DBSovereignIntel.tech_stack.contains(tech_stack)
            ).order_by(DBSovereignIntel.success_rate.desc()).limit(20).all()

class MissionStateRepository:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    def save(self, target: str, step: str, state_json: Dict[str, Any]):
        with self.session_factory() as session:
            state = session.query(DBMissionState).get(target)
            if state:
                state.current_step = step
                state.state_json = state_json
                state.last_update = datetime.now()
            else:
                state = DBMissionState(
                    target_value=target,
                    current_step=step,
                    state_json=state_json
                )
                session.add(state)
            session.commit()

    def get(self, target: str) -> Optional[DBMissionState]:
        with self.session_factory() as session:
            return session.query(DBMissionState).get(target)

# Database Hub for DI
class PersistenceHub:
    def __init__(self, db_url: Optional[str] = None):
        if not db_url:
            db_path = os.path.join(os.getcwd(), "aura_intel.db")
            db_url = f"sqlite:///{db_path}"
        
        connect_args = {'check_same_thread': False} if "sqlite" in db_url else {}
        self.engine = create_engine(db_url, connect_args=connect_args)
        
        # Auto-migration: Create tables if they don't exist
        try:
            Base.metadata.create_all(self.engine)
        except Exception as e:
            # Handle existing tables missing columns
            self._migrate_schema()
        
        self.session_factory = sessionmaker(bind=self.engine)
        
        self.targets = TargetRepository(self.session_factory)
        self.findings = FindingRepository(self.session_factory)
        self.campaigns = CampaignRepository(self.session_factory)
        self.audit = AuditRepository(self.session_factory)
        self.intel = SovereignIntelRepository(self.session_factory)
        self.state = MissionStateRepository(self.session_factory)
    
    def _migrate_schema(self):
        """Auto-migration to add missing columns to existing tables."""
        import sqlite3
        from sqlalchemy import inspect
        from sqlalchemy import text
        
        inspector = inspect(self.engine)
        
        # Check targets table for status column
        if 'targets' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('targets')]
            if 'status' not in columns:
                try:
                    with self.engine.connect() as conn:
                        conn.execute(text("ALTER TABLE targets ADD COLUMN status VARCHAR DEFAULT 'ACTIVE'"))
                        conn.commit()
                except Exception:
                    pass  # Column might already exist (race condition)

    def normalize_target(self, target: str) -> str:
        """Strips protocol and trailing slashes to extract clean FQDN."""
        import urllib.parse
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
            
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc or parsed.path
        
        # Remove any port if present
        if ":" in domain:
            domain = domain.split(":")[0]
            
        # Clean up any trailing paths or slashes
        domain = domain.strip().strip("/")
        return domain

    def save_target(self, target_data):
        """
        Save target data to the database.
        Handles dictionary inputs containing scan results.
        """
        from aura.core.models import Target
        
        # Extract target value from dict or use directly
        if isinstance(target_data, dict):
            target_value = target_data.get("value") or target_data.get("target") or target_data.get("domain")
            risk_score = target_data.get("risk_score", 0)
            priority = target_data.get("priority", "LOW")
            source = target_data.get("source", "scan")
            target_type = target_data.get("type", "domain")
        else:
            target_value = str(target_data)
            risk_score = 0
            priority = "LOW"
            source = "manual"
            target_type = "domain"
        
        if not target_value:
            return None
        
        # Normalize the target
        target_value = self.normalize_target(target_value)
        
        # Create domain target and save
        domain_target = Target(
            value=target_value,
            type=target_type,
            source=source,
            risk_score=risk_score,
            priority=priority,
            status="ACTIVE"
        )
        
        return self.targets.save(domain_target)

    # Legacy Compatibility Layer
    def add_finding(self, target, content_obj, finding_type="Vulnerability", severity="HIGH", campaign_id=None):
        """Bridge for legacy AuraStorage.add_finding calls."""
        from aura.core.models import Finding, Severity
        
        # Resolve target ID
        target_record = self.targets.get_by_value(target)
        target_id = target_record.id if target_record else None
        
        finding = Finding(
            target_id=target_id,
            target_value=target,
            content=str(content_obj),
            finding_type=finding_type,
            severity=Severity(severity.upper()) if hasattr(Severity, severity.upper()) else Severity.MEDIUM,
            campaign_id=campaign_id
        )
        self.findings.add(finding)

    def log_audit(self, action, target, details="", campaign_id=None):
        """Bridge for legacy AuraStorage.log_audit calls."""
        from aura.core.models import AuditLog
        entry = AuditLog(action=action, target=target, details=details, campaign_id=campaign_id)
        self.audit.log(entry)
