from enum import Enum
import datetime
from typing import Dict, List, Optional, Any, Set, Union


class ClearanceLevel(Enum):
    """Agent clearance levels in the SHADOW system"""
    LEVEL_1 = 1  # Basic access
    LEVEL_2 = 2  # Intermediate access
    LEVEL_3 = 3  # Advanced access
    LEVEL_4 = 4  # Expert access
    LEVEL_5 = 5  # Root access


class AccessStatus(Enum):
    """Status of an agent's access to the system"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    PROBATIONARY = "probationary"
    PENDING_REVIEW = "pending_review"


class Agent:
    """
    Model for agent profiles in the SHADOW system
    """
    def __init__(
        self,
        agent_id: str,
        name: str,
        clearance_level: ClearanceLevel,
        neural_signature_id: str,
        access_status: AccessStatus = AccessStatus.ACTIVE,
        specialties: Optional[List[str]] = None,
        access_history: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.agent_id = agent_id
        self.name = name
        self.clearance_level = clearance_level
        self.neural_signature_id = neural_signature_id
        self.access_status = access_status
        self.specialties = specialties or []
        self.access_history = access_history or []
        self.metadata = metadata or {}
        self.created_at = datetime.datetime.utcnow()
        self.last_updated = self.created_at
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert agent object to dictionary for storage"""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "clearance_level": self.clearance_level.value,
            "neural_signature_id": self.neural_signature_id,
            "access_status": self.access_status.value,
            "specialties": self.specialties,
            "access_history": self.access_history,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Agent':
        """Create an agent object from dictionary data"""
        agent = cls(
            agent_id=data["agent_id"],
            name=data["name"],
            clearance_level=ClearanceLevel(data["clearance_level"]),
            neural_signature_id=data["neural_signature_id"],
            access_status=AccessStatus(data["access_status"]),
            specialties=data.get("specialties", []),
            access_history=data.get("access_history", []),
            metadata=data.get("metadata", {})
        )
        
        agent.created_at = datetime.datetime.fromisoformat(data["created_at"])
        agent.last_updated = datetime.datetime.fromisoformat(data["last_updated"])
        
        return agent


class Rule:
    """
    Model for security rules in the SHADOW system
    """
    def __init__(
        self,
        rule_id: str,
        description: str,
        pattern: str,
        clearance_required: ClearanceLevel,
        rule_type: str,
        exceptions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.rule_id = rule_id
        self.description = description
        self.pattern = pattern
        self.clearance_required = clearance_required
        self.rule_type = rule_type
        self.exceptions = exceptions or []
        self.metadata = metadata or {}
        self.created_at = datetime.datetime.utcnow()
        self.last_updated = self.created_at
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule object to dictionary for storage"""
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "pattern": self.pattern,
            "clearance_required": self.clearance_required.value,
            "rule_type": self.rule_type,
            "exceptions": self.exceptions,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Rule':
        """Create a rule object from dictionary data"""
        rule = cls(
            rule_id=data["rule_id"],
            description=data["description"],
            pattern=data["pattern"],
            clearance_required=ClearanceLevel(data["clearance_required"]),
            rule_type=data["rule_type"],
            exceptions=data.get("exceptions", []),
            metadata=data.get("metadata", {})
        )
        
        rule.created_at = datetime.datetime.fromisoformat(data["created_at"])
        rule.last_updated = datetime.datetime.fromisoformat(data["last_updated"])
        
        return rule


class AuditTrail:
    """
    Model for encrypted audit trail entries in the SHADOW system
    """
    def __init__(
        self,
        entry_id: str,
        agent_id: str,
        action_type: str,
        timestamp: datetime.datetime,
        encrypted_details: str,
        encryption_metadata: Dict[str, Any],
        clearance_level: ClearanceLevel,
        related_resources: Optional[List[str]] = None
    ):
        self.entry_id = entry_id
        self.agent_id = agent_id
        self.action_type = action_type
        self.timestamp = timestamp
        self.encrypted_details = encrypted_details
        self.encryption_metadata = encryption_metadata
        self.clearance_level = clearance_level
        self.related_resources = related_resources or []
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit trail entry to dictionary for storage"""
        return {
            "entry_id": self.entry_id,
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "timestamp": self.timestamp.isoformat(),
            "encrypted_details": self.encrypted_details,
            "encryption_metadata": self.encryption_metadata,
            "clearance_level": self.clearance_level.value,
            "related_resources": self.related_resources
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditTrail':
        """Create an audit trail entry from dictionary data"""
        return cls(
            entry_id=data["entry_id"],
            agent_id=data["agent_id"],
            action_type=data["action_type"],
            timestamp=datetime.datetime.fromisoformat(data["timestamp"]),
            encrypted_details=data["encrypted_details"],
            encryption_metadata=data["encryption_metadata"],
            clearance_level=ClearanceLevel(data["clearance_level"]),
            related_resources=data.get("related_resources", [])
        )


class NeuralSignature:
    """
    Model for neural signatures in the SHADOW system
    """
    def __init__(
        self,
        signature_id: str,
        agent_id: str,
        signature_data: Dict[str, Any],
        verification_threshold: float,
        signature_version: str,
        created_at: Optional[datetime.datetime] = None,
        last_verified: Optional[datetime.datetime] = None,
        verification_stats: Optional[Dict[str, Any]] = None
    ):
        self.signature_id = signature_id
        self.agent_id = agent_id
        self.signature_data = signature_data
        self.verification_threshold = verification_threshold
        self.signature_version = signature_version
        self.created_at = created_at or datetime.datetime.utcnow()
        self.last_verified = last_verified
        self.verification_stats = verification_stats or {"success_count": 0, "failure_count": 0}
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert neural signature to dictionary for storage"""
        result = {
            "signature_id": self.signature_id,
            "agent_id": self.agent_id,
            "signature_data": self.signature_data,
            "verification_threshold": self.verification_threshold,
            "signature_version": self.signature_version,
            "created_at": self.created_at.isoformat(),
            "verification_stats": self.verification_stats
        }
        
        if self.last_verified:
            result["last_verified"] = self.last_verified.isoformat()
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NeuralSignature':
        """Create a neural signature from dictionary data"""
        last_verified = None
        if "last_verified" in data and data["last_verified"]:
            last_verified = datetime.datetime.fromisoformat(data["last_verified"])
            
        return cls(
            signature_id=data["signature_id"],
            agent_id=data["agent_id"],
            signature_data=data["signature_data"],
            verification_threshold=data["verification_threshold"],
            signature_version=data["signature_version"],
            created_at=datetime.datetime.fromisoformat(data["created_at"]),
            last_verified=last_verified,
            verification_stats=data.get("verification_stats", {"success_count": 0, "failure_count": 0})
        ) 