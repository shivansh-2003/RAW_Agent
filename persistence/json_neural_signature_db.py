import os
import json
import uuid
import datetime
import logging
from typing import Dict, List, Optional, Any

from persistence.db_models import NeuralSignature, ClearanceLevel
from persistence.db_interface import NeuralSignatureDatabase
from persistence.json_storage import JsonStorage

# Set up logging
logger = logging.getLogger("shadow_persistence.neural_signature")


class JsonNeuralSignatureDatabase(NeuralSignatureDatabase):
    """
    JSON implementation of the Neural Signatures Database interface
    """
    
    def __init__(self, file_path: str = "data/neural_signatures.json"):
        """Initialize the neural signature database with the specified file path"""
        self.storage = JsonStorage(file_path)
    
    def initialize(self) -> bool:
        """Initialize the database"""
        return self.storage.initialize()
    
    def close(self) -> None:
        """Close the database"""
        self.storage.close()
    
    def get_signature(
        self, 
        signature_id: str
    ) -> Optional[NeuralSignature]:
        """Retrieve a neural signature by ID"""
        with self.storage.lock:
            if not signature_id or not self.storage.initialized:
                return None
                
            signature_data = self.storage.data.get("items", {}).get(signature_id)
            if not signature_data:
                return None
                
            return NeuralSignature.from_dict(signature_data)
    
    def get_agent_signature(
        self, 
        agent_id: str
    ) -> Optional[NeuralSignature]:
        """Retrieve a neural signature by agent ID"""
        with self.storage.lock:
            if not agent_id or not self.storage.initialized:
                return None
            
            # Search for signature with matching agent_id
            for signature_data in self.storage.data.get("items", {}).values():
                if signature_data.get("agent_id") == agent_id:
                    return NeuralSignature.from_dict(signature_data)
            
            return None
    
    def create_signature(
        self, 
        signature: NeuralSignature
    ) -> bool:
        """Create a new neural signature"""
        with self.storage.lock:
            if not signature or not self.storage.initialized:
                return False
                
            # Check if signature already exists
            if signature.signature_id in self.storage.data.get("items", {}):
                logger.warning(f"Signature with ID {signature.signature_id} already exists")
                return False
            
            # Check if agent already has a signature
            if self.get_agent_signature(signature.agent_id):
                logger.warning(f"Agent {signature.agent_id} already has a neural signature")
                return False
            
            # Ensure items dict exists
            if "items" not in self.storage.data:
                self.storage.data["items"] = {}
            
            # Store signature data
            self.storage.data["items"][signature.signature_id] = signature.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def update_signature(
        self, 
        signature: NeuralSignature
    ) -> bool:
        """Update an existing neural signature"""
        with self.storage.lock:
            if not signature or not self.storage.initialized:
                return False
                
            # Check if signature exists
            if signature.signature_id not in self.storage.data.get("items", {}):
                logger.warning(f"Signature with ID {signature.signature_id} does not exist")
                return False
            
            # Store updated signature data
            self.storage.data["items"][signature.signature_id] = signature.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def delete_signature(
        self, 
        signature_id: str,
        requestor_id: str,
        requestor_clearance: ClearanceLevel
    ) -> bool:
        """Delete a neural signature (requires high clearance)"""
        with self.storage.lock:
            if not signature_id or not self.storage.initialized:
                return False
            
            # Check clearance level
            if requestor_clearance.value < ClearanceLevel.LEVEL_4.value:
                logger.warning(
                    f"Delete denied: requestor {requestor_id} has insufficient clearance "
                    f"(level {requestor_clearance.value})"
                )
                return False
                
            # Check if signature exists
            if signature_id not in self.storage.data.get("items", {}):
                logger.warning(f"Signature with ID {signature_id} does not exist")
                return False
            
            # Get signature data for logging
            signature_data = self.storage.data["items"][signature_id]
            
            # Delete signature data
            del self.storage.data["items"][signature_id]
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
            
            # Log deletion (using a simple dictionary since we don't have direct access to AuditTrail)
            logger.info(
                f"Neural signature {signature_id} for agent {signature_data.get('agent_id')} "
                f"deleted by {requestor_id}"
            )
                
            return True
    
    def record_verification_attempt(
        self,
        signature_id: str,
        success: bool,
        verification_score: float,
        verification_data: Dict[str, Any]
    ) -> bool:
        """Record an attempt to verify a neural signature"""
        with self.storage.lock:
            if not signature_id or not self.storage.initialized:
                return False
                
            # Check if signature exists
            signature_data = self.storage.data.get("items", {}).get(signature_id)
            if not signature_data:
                logger.warning(f"Signature with ID {signature_id} does not exist")
                return False
            
            # Create signature object to update
            signature = NeuralSignature.from_dict(signature_data)
            
            # Update verification stats
            if success:
                signature.verification_stats["success_count"] += 1
            else:
                signature.verification_stats["failure_count"] += 1
            
            # Add this verification attempt to history
            if "verification_history" not in signature.verification_stats:
                signature.verification_stats["verification_history"] = []
                
            # Limit history to last 50 entries
            max_history = 50
            if len(signature.verification_stats["verification_history"]) >= max_history:
                signature.verification_stats["verification_history"] = signature.verification_stats["verification_history"][-max_history+1:]
            
            # Add new entry
            signature.verification_stats["verification_history"].append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "success": success,
                "score": verification_score,
                "data": verification_data
            })
            
            # Update last_verified timestamp
            signature.last_verified = datetime.datetime.utcnow()
            
            # Update signature in storage
            self.storage.data["items"][signature_id] = signature.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def list_signatures(
        self,
        version: Optional[str] = None,
        min_threshold: Optional[float] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[NeuralSignature]:
        """List neural signatures with optional filtering"""
        with self.storage.lock:
            if not self.storage.initialized:
                return []
            
            # Get all signatures
            all_signatures = []
            for signature_data in self.storage.data.get("items", {}).values():
                try:
                    signature = NeuralSignature.from_dict(signature_data)
                    
                    # Apply filters
                    if version and signature.signature_version != version:
                        continue
                        
                    if min_threshold and signature.verification_threshold < min_threshold:
                        continue
                    
                    all_signatures.append(signature)
                except Exception as e:
                    logger.error(f"Error parsing neural signature data: {e}")
                    continue
            
            # Sort by agent_id for consistent results
            all_signatures.sort(key=lambda s: s.agent_id)
            
            # Apply pagination
            return all_signatures[offset:offset+limit] 