import os
import json
import uuid
import datetime
import logging
import threading
from typing import Dict, List, Optional, Any, Tuple

from persistence.db_models import AuditTrail, ClearanceLevel
from persistence.db_interface import AuditTrailDatabase
from persistence.json_storage import JsonStorage

# Set up logging
logger = logging.getLogger("shadow_persistence.audit_trail")


class JsonAuditTrailDatabase(AuditTrailDatabase):
    """
    JSON implementation of the Encrypted Audit Trail Database interface
    """
    
    def __init__(self, file_path: str = "data/audit_trail.json"):
        """Initialize the audit trail database with the specified file path"""
        self.storage = JsonStorage(file_path)
    
    def initialize(self) -> bool:
        """Initialize the database"""
        return self.storage.initialize()
    
    def close(self) -> None:
        """Close the database"""
        self.storage.close()
    
    def log_event(self, audit_entry: AuditTrail) -> bool:
        """Log an audit event to the database"""
        with self.storage.lock:
            if not audit_entry or not self.storage.initialized:
                return False
                
            # Ensure items dict exists
            if "items" not in self.storage.data:
                self.storage.data["items"] = {}
            
            # Store audit entry data
            self.storage.data["items"][audit_entry.entry_id] = audit_entry.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def get_event(
        self, 
        entry_id: str, 
        requestor_clearance: ClearanceLevel
    ) -> Optional[AuditTrail]:
        """Retrieve an audit event by ID if requestor has sufficient clearance"""
        with self.storage.lock:
            if not entry_id or not self.storage.initialized:
                return None
                
            entry_data = self.storage.data.get("items", {}).get(entry_id)
            if not entry_data:
                return None
                
            # Check clearance level - requestor must have equal or higher clearance
            entry_clearance = ClearanceLevel(entry_data.get("clearance_level", 1))
            if requestor_clearance.value < entry_clearance.value:
                logger.warning(
                    f"Access denied: requestor has clearance level {requestor_clearance.value}, "
                    f"but entry has level {entry_clearance.value}"
                )
                return None
                
            return AuditTrail.from_dict(entry_data)
    
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
        with self.storage.lock:
            if not self.storage.initialized:
                return []
            
            # Convert start and end times to ISO format strings for comparison
            start_time_iso = start_time.isoformat() if start_time else None
            end_time_iso = end_time.isoformat() if end_time else None
            
            # Filter events
            results = []
            
            for entry_data in self.storage.data.get("items", {}).values():
                try:
                    # Check clearance level first
                    entry_clearance = ClearanceLevel(entry_data.get("clearance_level", 1))
                    if requestor_clearance.value < entry_clearance.value:
                        continue
                    
                    # Apply agent_id filter
                    if agent_id and entry_data.get("agent_id") != agent_id:
                        continue
                    
                    # Apply action_type filter
                    if action_type and entry_data.get("action_type") != action_type:
                        continue
                    
                    # Apply time range filters
                    timestamp = entry_data.get("timestamp")
                    if start_time_iso and timestamp < start_time_iso:
                        continue
                    if end_time_iso and timestamp > end_time_iso:
                        continue
                    
                    # Add to results
                    results.append(AuditTrail.from_dict(entry_data))
                except Exception as e:
                    logger.error(f"Error parsing audit entry data: {e}")
                    continue
            
            # Sort by timestamp (newest first) for consistent results
            results.sort(key=lambda a: a.timestamp, reverse=True)
            
            # Apply pagination
            return results[offset:offset+limit]
    
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
        with self.storage.lock:
            if not self.storage.initialized:
                return (0, False)
            
            # Only allow purging if requestor has highest clearance
            if requestor_clearance.value < ClearanceLevel.LEVEL_5.value:
                logger.warning(
                    f"Purge denied: requestor {requestor_id} has insufficient clearance "
                    f"(level {requestor_clearance.value})"
                )
                return (0, False)
            
            # Convert threshold to ISO format for comparison
            older_than_iso = older_than.isoformat()
            
            # Find entries to purge
            entries_to_purge = []
            
            for entry_id, entry_data in self.storage.data.get("items", {}).items():
                try:
                    timestamp = entry_data.get("timestamp")
                    if timestamp < older_than_iso:
                        entries_to_purge.append(entry_id)
                except Exception as e:
                    logger.error(f"Error checking audit entry for purging: {e}")
                    continue
            
            # Purge entries
            purge_count = 0
            for entry_id in entries_to_purge:
                try:
                    del self.storage.data["items"][entry_id]
                    purge_count += 1
                except Exception as e:
                    logger.error(f"Error purging audit entry {entry_id}: {e}")
            
            # Save if auto-save is enabled and at least one entry was purged
            if self.storage.auto_save and purge_count > 0:
                self.storage.save()
            
            # Log the purge operation itself
            purge_log = AuditTrail(
                entry_id=str(uuid.uuid4()),
                agent_id=requestor_id,
                action_type="audit_trail_purge",
                timestamp=datetime.datetime.utcnow(),
                encrypted_details="{}",  # No encryption for this implementation
                encryption_metadata={
                    "purged_count": purge_count,
                    "purge_threshold": older_than.isoformat()
                },
                clearance_level=ClearanceLevel.LEVEL_5
            )
            self.log_event(purge_log)
            
            return (purge_count, True)
    
    def export_encrypted_backup(
        self, 
        file_path: str,
        requestor_id: str,
        requestor_clearance: ClearanceLevel
    ) -> bool:
        """Export encrypted backup of audit trail"""
        with self.storage.lock:
            if not self.storage.initialized:
                return False
            
            # Only allow export if requestor has high clearance
            if requestor_clearance.value < ClearanceLevel.LEVEL_4.value:
                logger.warning(
                    f"Export denied: requestor {requestor_id} has insufficient clearance "
                    f"(level {requestor_clearance.value})"
                )
                return False
            
            try:
                # Ensure directory exists
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # Create export data (filtered by clearance)
                export_items = {}
                for entry_id, entry_data in self.storage.data.get("items", {}).items():
                    entry_clearance = ClearanceLevel(entry_data.get("clearance_level", 1))
                    if requestor_clearance.value >= entry_clearance.value:
                        export_items[entry_id] = entry_data
                
                export_data = {
                    "metadata": {
                        "exported_at": datetime.datetime.utcnow().isoformat(),
                        "exported_by": requestor_id,
                        "entry_count": len(export_items)
                    },
                    "items": export_items
                }
                
                # In a real implementation, this data would be encrypted
                # For this demonstration, we'll just write the JSON
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                # Log the export operation
                export_log = AuditTrail(
                    entry_id=str(uuid.uuid4()),
                    agent_id=requestor_id,
                    action_type="audit_trail_export",
                    timestamp=datetime.datetime.utcnow(),
                    encrypted_details="{}",  # No encryption for this implementation
                    encryption_metadata={
                        "exported_count": len(export_items),
                        "export_file": file_path
                    },
                    clearance_level=ClearanceLevel.LEVEL_4
                )
                self.log_event(export_log)
                
                return True
            except Exception as e:
                logger.error(f"Failed to export audit trail to {file_path}: {e}")
                return False 