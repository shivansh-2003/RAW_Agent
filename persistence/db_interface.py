from abc import ABC, abstractmethod
import datetime
from typing import Dict, List, Optional, Any, Set, Union, Tuple

from persistence.db_models import Agent, Rule, AuditTrail, NeuralSignature, ClearanceLevel, AccessStatus


class DatabaseInterface(ABC):
    """Abstract base class for database interfaces in the persistence layer"""
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the database connection and create necessary structures"""
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Close database connection and perform cleanup"""
        pass


class AgentDatabase(DatabaseInterface):
    """Interface for Agent Profile & Clearance Database operations"""
    
    @abstractmethod
    def get_agent(self, agent_id: str) -> Optional[Agent]:
        """Retrieve an agent by ID"""
        pass
    
    @abstractmethod
    def create_agent(self, agent: Agent) -> bool:
        """Create a new agent record"""
        pass
    
    @abstractmethod
    def update_agent(self, agent: Agent) -> bool:
        """Update an existing agent record"""
        pass
    
    @abstractmethod
    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent record"""
        pass
    
    @abstractmethod
    def list_agents(
        self, 
        clearance_level: Optional[ClearanceLevel] = None,
        access_status: Optional[AccessStatus] = None,
        specialty: Optional[str] = None,
        limit: int = 100, 
        offset: int = 0
    ) -> List[Agent]:
        """List agents with optional filtering"""
        pass
    
    @abstractmethod
    def update_agent_clearance(
        self, 
        agent_id: str, 
        new_clearance: ClearanceLevel,
        reason: str,
        updated_by: str
    ) -> bool:
        """Update an agent's clearance level with audit information"""
        pass
    
    @abstractmethod
    def update_agent_status(
        self, 
        agent_id: str, 
        new_status: AccessStatus,
        reason: str,
        updated_by: str
    ) -> bool:
        """Update an agent's access status with audit information"""
        pass
    
    @abstractmethod
    def add_access_history_entry(
        self, 
        agent_id: str, 
        action: str,
        details: Dict[str, Any],
        performed_by: str
    ) -> bool:
        """Add an entry to an agent's access history"""
        pass
    
    @abstractmethod
    def verify_agent_clearance(
        self, 
        agent_id: str, 
        required_level: ClearanceLevel
    ) -> Tuple[bool, str]:
        """Verify if an agent has sufficient clearance for an operation"""
        pass


class RulesDatabase(DatabaseInterface):
    """Interface for Rules Data Store operations"""
    
    @abstractmethod
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Retrieve a rule by ID"""
        pass
    
    @abstractmethod
    def create_rule(self, rule: Rule) -> bool:
        """Create a new rule"""
        pass
    
    @abstractmethod
    def update_rule(self, rule: Rule) -> bool:
        """Update an existing rule"""
        pass
    
    @abstractmethod
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule"""
        pass
    
    @abstractmethod
    def list_rules(
        self,
        rule_type: Optional[str] = None,
        clearance_level: Optional[ClearanceLevel] = None,
        limit: int = 100, 
        offset: int = 0
    ) -> List[Rule]:
        """List rules with optional filtering"""
        pass
    
    @abstractmethod
    def search_rules(
        self, 
        query: str, 
        max_clearance: ClearanceLevel
    ) -> List[Rule]:
        """Search for rules matching a query string, constrained by max clearance"""
        pass
    
    @abstractmethod
    def get_rules_by_clearance(
        self, 
        clearance_level: ClearanceLevel,
        include_lower: bool = True
    ) -> List[Rule]:
        """Get rules applicable to a specific clearance level"""
        pass
    
    @abstractmethod
    def export_rules_to_json(self, file_path: str) -> bool:
        """Export all rules to a JSON file"""
        pass
    
    @abstractmethod
    def import_rules_from_json(self, file_path: str) -> Tuple[int, int]:
        """Import rules from a JSON file, returns (success_count, error_count)"""
        pass


class AuditTrailDatabase(DatabaseInterface):
    """Interface for Encrypted Audit Trail Database operations"""
    
    @abstractmethod
    def log_event(self, audit_entry: AuditTrail) -> bool:
        """Log an audit event to the database"""
        pass
    
    @abstractmethod
    def get_event(
        self, 
        entry_id: str, 
        requestor_clearance: ClearanceLevel
    ) -> Optional[AuditTrail]:
        """Retrieve an audit event by ID if requestor has sufficient clearance"""
        pass
    
    @abstractmethod
    def query_events(
        self,
        agent_id: Optional[str] = None,
        action_type: Optional[str] = None,
        start_time: Optional[datetime.datetime] = None,
        end_time: Optional[datetime.datetime] = None,
        requestor_clearance: ClearanceLevel = ClearanceLevel.LEVEL_5,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditTrail]:
        """Query audit events with filtering, constrained by requestor's clearance"""
        pass
    
    @abstractmethod
    def purge_old_events(
        self, 
        older_than: datetime.datetime,
        requestor_id: str,
        requestor_clearance: ClearanceLevel
    ) -> Tuple[int, bool]:
        """
        Purge events older than the specified date
        Returns (count of purged events, success status)
        """
        pass
    
    @abstractmethod
    def export_encrypted_backup(
        self, 
        file_path: str,
        requestor_id: str,
        requestor_clearance: ClearanceLevel
    ) -> bool:
        """Export encrypted backup of audit trail"""
        pass


class NeuralSignatureDatabase(DatabaseInterface):
    """Interface for Neural Signatures Database operations"""
    
    @abstractmethod
    def get_signature(
        self, 
        signature_id: str
    ) -> Optional[NeuralSignature]:
        """Retrieve a neural signature by ID"""
        pass
    
    @abstractmethod
    def get_agent_signature(
        self, 
        agent_id: str
    ) -> Optional[NeuralSignature]:
        """Retrieve a neural signature by agent ID"""
        pass
    
    @abstractmethod
    def create_signature(
        self, 
        signature: NeuralSignature
    ) -> bool:
        """Create a new neural signature"""
        pass
    
    @abstractmethod
    def update_signature(
        self, 
        signature: NeuralSignature
    ) -> bool:
        """Update an existing neural signature"""
        pass
    
    @abstractmethod
    def delete_signature(
        self, 
        signature_id: str,
        requestor_id: str,
        requestor_clearance: ClearanceLevel
    ) -> bool:
        """Delete a neural signature (requires high clearance)"""
        pass
    
    @abstractmethod
    def record_verification_attempt(
        self,
        signature_id: str,
        success: bool,
        verification_score: float,
        verification_data: Dict[str, Any]
    ) -> bool:
        """Record an attempt to verify a neural signature"""
        pass
    
    @abstractmethod
    def list_signatures(
        self,
        version: Optional[str] = None,
        min_threshold: Optional[float] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[NeuralSignature]:
        """List neural signatures with optional filtering"""
        pass 