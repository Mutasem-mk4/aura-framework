from abc import ABC, abstractmethod
from typing import List, Optional, Any
from aura.core.models import Target, Finding, Campaign, AuditLog

class ITargetRepository(ABC):
    @abstractmethod
    def save(self, target: Target) -> int: ...
    
    @abstractmethod
    def get_by_id(self, target_id: int) -> Optional[Target]: ...
    
    @abstractmethod
    def get_by_value(self, value: str) -> Optional[Target]: ...
    
    @abstractmethod
    def get_all_active(self) -> List[Target]: ...

class IFindingRepository(ABC):
    @abstractmethod
    def add(self, finding: Finding) -> None: ...
    
    @abstractmethod
    def get_by_target(self, target_id: int) -> List[Finding]: ...
    
    @abstractmethod
    def get_all(self) -> List[Finding]: ...

class ICampaignRepository(ABC):
    @abstractmethod
    def create(self, campaign: Campaign) -> int: ...
    
    @abstractmethod
    def get_by_id(self, campaign_id: int) -> Optional[Campaign]: ...

class IAuditRepository(ABC):
    @abstractmethod
    def log(self, entry: AuditLog) -> None: ...
    
    @abstractmethod
    def get_logs(self, campaign_id: Optional[int] = None) -> List[AuditLog]: ...
