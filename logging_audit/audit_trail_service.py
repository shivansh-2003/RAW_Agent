import os
import json
import uuid
import shutil
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union

from .secure_logger import SecureLogger

class AuditTrailService:
    """
    Service for maintaining a secure, tamper-proof audit trail of system events
    """
    
    def __init__(self, 
                 log_dir: str, 
                 retention_days: int = 365, 
                 secret_key: Optional[str] = None):
        """
        Initialize the Audit Trail Service
        
        Args:
            log_dir: Directory to store audit logs
            retention_days: Number of days to retain audit logs
            secret_key: Secret key for HMAC verification (if None, a random key will be generated)
        """
        self.log_dir = log_dir
        self.retention_days = retention_days
        
        # Initialize secure logger
        self.secure_logger = SecureLogger(log_dir, secret_key)
        
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Perform cleanup of old logs on initialization
        self._cleanup_old_logs()
    
    def _generate_event_id(self) -> str:
        """Generate a unique event ID for each audit event"""
        return str(uuid.uuid4())
    
    def _cleanup_old_logs(self):
        """Remove logs older than the retention period"""
        if self.retention_days <= 0:
            return  # No cleanup needed for unlimited retention
            
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
        cutoff_date_str = cutoff_date.strftime("%Y-%m-%d")
        
        for filename in os.listdir(self.log_dir):
            if filename.startswith("audit_log_") and filename.endswith(".jsonl"):
                file_date = filename.replace("audit_log_", "").replace(".jsonl", "")
                
                if file_date < cutoff_date_str:
                    # Archive the file before deletion (in production)
                    # In this implementation, we'll just delete it
                    file_path = os.path.join(self.log_dir, filename)
                    try:
                        os.remove(file_path)
                        print(f"Removed old audit log: {filename}")
                    except Exception as e:
                        print(f"Failed to remove old audit log {filename}: {e}")
    
    def log_auth_event(self, 
                      user_id: str, 
                      success: bool, 
                      details: Dict[str, Any] = None) -> str:
        """
        Log an authentication event
        
        Args:
            user_id: User identifier
            success: Whether authentication was successful
            details: Additional details about the authentication

        Returns:
            event_id: The ID of the logged event
        """
        event_data = {
            "event_id": self._generate_event_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "authentication",
            "user_id": user_id,
            "action": "login_success" if success else "login_failure",
            "status": "success" if success else "failure",
            "details": details or {}
        }
        
        return self.secure_logger.log_event(event_data)
    
    def log_data_access(self, 
                        user_id: str, 
                        resource_id: str, 
                        action: str, 
                        success: bool,
                        details: Dict[str, Any] = None) -> str:
        """
        Log a data access event
        
        Args:
            user_id: User identifier
            resource_id: Identifier of the accessed resource
            action: Type of access (read, write, delete)
            success: Whether access was successful
            details: Additional details about the access

        Returns:
            event_id: The ID of the logged event
        """
        event_data = {
            "event_id": self._generate_event_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "data_access",
            "user_id": user_id,
            "resource_id": resource_id,
            "action": action,
            "status": "success" if success else "failure",
            "details": details or {}
        }
        
        return self.secure_logger.log_event(event_data)
    
    def log_admin_action(self, 
                         admin_id: str, 
                         action: str, 
                         target: str,
                         details: Dict[str, Any] = None) -> str:
        """
        Log an administrative action
        
        Args:
            admin_id: Administrator identifier
            action: Type of administrative action
            target: Target of the action (user, system component, etc.)
            details: Additional details about the action

        Returns:
            event_id: The ID of the logged event
        """
        event_data = {
            "event_id": self._generate_event_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "admin_action",
            "user_id": admin_id,
            "action": action,
            "target": target,
            "details": details or {}
        }
        
        return self.secure_logger.log_event(event_data)
    
    def log_system_event(self, 
                        component: str, 
                        action: str, 
                        status: str,
                        details: Dict[str, Any] = None) -> str:
        """
        Log a system event
        
        Args:
            component: System component that triggered the event
            action: Type of system action
            status: Status of the action (success, failure, warning)
            details: Additional details about the event

        Returns:
            event_id: The ID of the logged event
        """
        event_data = {
            "event_id": self._generate_event_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "system_event",
            "component": component,
            "action": action,
            "status": status,
            "details": details or {}
        }
        
        return self.secure_logger.log_event(event_data)
    
    def search_logs(self, 
                   criteria: Dict[str, Any], 
                   start_date: Optional[str] = None, 
                   end_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search audit logs based on criteria
        
        Args:
            criteria: Dictionary of search criteria (e.g., event_type, user_id)
            start_date: Start date for search range (YYYY-MM-DD)
            end_date: End date for search range (YYYY-MM-DD)
            
        Returns:
            List of matching log entries
        """
        logs = self.secure_logger.get_logs(start_date, end_date)
        
        # Filter logs based on criteria
        results = []
        for log in logs:
            matches = True
            for key, value in criteria.items():
                # Handle nested keys with dot notation (e.g., "details.ip_address")
                if "." in key:
                    parts = key.split(".")
                    current = log
                    for part in parts:
                        if part in current:
                            current = current[part]
                        else:
                            matches = False
                            break
                    
                    if matches and current != value:
                        matches = False
                else:
                    # Handle direct keys
                    if key not in log or log[key] != value:
                        matches = False
            
            if matches:
                results.append(log)
        
        return results
    
    def export_logs(self, 
                   output_file: str, 
                   start_date: Optional[str] = None, 
                   end_date: Optional[str] = None,
                   criteria: Optional[Dict[str, Any]] = None) -> int:
        """
        Export logs to a JSON file
        
        Args:
            output_file: Path to the output file
            start_date: Start date for export range (YYYY-MM-DD)
            end_date: End date for export range (YYYY-MM-DD)
            criteria: Optional filtering criteria
            
        Returns:
            Number of exported log entries
        """
        if criteria:
            logs = self.search_logs(criteria, start_date, end_date)
        else:
            logs = self.secure_logger.get_logs(start_date, end_date)
        
        with open(output_file, 'w') as f:
            json.dump(logs, f, indent=2)
        
        return len(logs)
    
    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify the integrity of the audit trail
        
        Returns:
            Verification results
        """
        return self.secure_logger.verify_log_integrity()
    
    def get_recent_events(self, 
                         limit: int = 100, 
                         event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent events, optionally filtered by type
        
        Args:
            limit: Maximum number of events to return
            event_type: Optional filter for event type
            
        Returns:
            List of recent events
        """
        today = datetime.utcnow().strftime("%Y-%m-%d")
        
        # Get logs from the last 7 days
        seven_days_ago = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
        logs = self.secure_logger.get_logs(seven_days_ago, today)
        
        # Sort by timestamp (most recent first)
        logs.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # Filter by event type if specified
        if event_type:
            logs = [log for log in logs if log.get("event_type") == event_type]
        
        # Return limited number of events
        return logs[:limit] 