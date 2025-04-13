import os
import json
from datetime import datetime, timedelta
from logging_audit.audit_trail_service import AuditTrailService, AuditEvent

def test_audit_trail_service():
    """
    Test the AuditTrailService functionality
    """
    # Create a test directory for audit logs
    test_dir = "test_audit_logs"
    os.makedirs(test_dir, exist_ok=True)
    
    # Initialize the service
    audit_service = AuditTrailService(
        log_dir=test_dir,
        retention_days=30
    )
    
    # Log various events
    
    # 1. Authentication events
    login_id = audit_service.log_auth_event(
        user_id="agent123",
        action="LOGIN",
        status="SUCCESS",
        ip_address="192.168.1.100",
        session_id="sess_12345",
        details={"auth_method": "2FA", "device": "workstation"}
    )
    
    # 2. Data access events
    data_access_id = audit_service.log_data_access(
        user_id="agent123",
        resource="classified_documents/file123.pdf",
        action="VIEW",
        status="SUCCESS",
        ip_address="192.168.1.100",
        session_id="sess_12345",
        details={"clearance_level": "L5", "reason": "Investigation"}
    )
    
    # 3. Admin action
    admin_action_id = audit_service.log_admin_action(
        user_id="admin007",
        action="UPDATE_USER_PRIVILEGES",
        resource="users/agent123",
        status="SUCCESS",
        ip_address="192.168.1.200",
        session_id="sess_admin_987",
        details={"old_level": "L4", "new_level": "L5", "reason": "Mission upgrade"}
    )
    
    # 4. System event
    system_event_id = audit_service.log_system_event(
        action="BACKUP",
        resource="database",
        status="SUCCESS",
        details={"duration_seconds": 120, "size_mb": 1500}
    )
    
    # Create a failed authentication attempt
    failed_login_id = audit_service.log_auth_event(
        user_id="agent123",
        action="LOGIN",
        status="FAILED",
        ip_address="10.0.0.15",
        details={"reason": "Invalid password", "attempt": 2}
    )
    
    # Wait a moment to ensure logs are written
    import time
    time.sleep(1)
    
    # Demonstrate log searching
    print("=== Authentication Events ===")
    auth_events = audit_service.search_logs(event_type="AUTH")
    for event in auth_events:
        print(f"{event.timestamp} - {event.user_id} - {event.action} - {event.status}")
    
    print("\n=== Failed Events ===")
    failed_events = audit_service.search_logs(status="FAILED")
    for event in failed_events:
        print(f"{event.event_type} - {event.user_id} - {event.action} - {event.resource}")
    
    print("\n=== Events for agent123 ===")
    agent_events = audit_service.search_logs(user_id="agent123")
    for event in agent_events:
        print(f"{event.event_type} - {event.action} - {event.status}")
    
    # Export audit trail to file
    export_path = os.path.join(test_dir, "audit_export.json")
    audit_service.export_audit_trail(
        output_path=export_path,
        start_time=(datetime.utcnow() - timedelta(hours=1)).isoformat(),
        end_time=datetime.utcnow().isoformat()
    )
    
    print(f"\nAudit trail exported to: {export_path}")
    
    # Verify logs
    verification_result = audit_service.verify_logs()
    print(f"\nLog verification result: {verification_result}")
    
    # Print exported content for demo
    with open(export_path, 'r') as f:
        export_data = json.load(f)
        print(f"\nExported {export_data['event_count']} events")

if __name__ == "__main__":
    test_audit_trail_service() 