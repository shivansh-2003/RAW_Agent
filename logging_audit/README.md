# Secure Logging and Audit Trail System

A robust and secure logging and audit trail system for tracking system events, user activities, and security incidents with tamper-proof verification.

## Core Components

### 1. SecureLogger (secure_logger.py)

The `SecureLogger` is a tamper-proof logging solution that provides:

- **Cryptographic Integrity**: Each log record is digitally signed and linked to previous records
- **Encryption**: Optional encryption of sensitive log data
- **Structured Logging**: JSON-based log records with rich metadata
- **Log Rotation**: Automatic rotation of log files based on size
- **Log Archiving**: Compression and retention of historical logs
- **Integrity Verification**: Tools to verify log chain hasn't been tampered with

Key features:
- HMAC-based log record signatures
- Chained signatures to detect log tampering
- Configurable log levels and retention policies
- Compatible with standard Python logging

### 2. AuditTrailService (audit_trail_service.py)

The `AuditTrailService` provides higher-level auditing capabilities:

- **Event Classification**: Categorize events by type (auth, data access, admin, system)
- **Searchable Logs**: Query and filter logs based on various criteria
- **Export Functionality**: Export audit logs to JSON for analysis
- **Retention Management**: Automatic cleanup of old logs based on policy

Supported event types:
- Authentication events (login success/failure)
- Data access events (read/write/delete)
- Administrative actions (user management, configuration)
- System events (startup, shutdown, errors)

## Usage

### Basic SecureLogger Usage

```python
from logging_audit.secure_logger import SecureLogger

# Initialize logger
logger = SecureLogger(
    name="app_server",
    log_level="INFO",
    log_dir="logs", 
    encryption_enabled=True
)

# Log messages at different levels
logger.info("Server started", extra={"version": "1.2.3"})
logger.warning("High memory usage detected", extra={"memory_usage": "85%"})
logger.error("Database connection failed", extra={"error_code": "DB_CONN_01"})

# Verify log integrity
results = logger.verify_log_integrity()
print(f"Logs verified: {results['verified']}")
```

### AuditTrailService Usage

```python
from logging_audit.audit_trail_service import AuditTrailService

# Initialize audit service
audit = AuditTrailService(log_dir="audit_logs", retention_days=365)

# Log authentication event
audit.log_auth_event(
    user_id="user123", 
    success=True, 
    details={"ip_address": "192.168.1.1", "auth_method": "password"}
)

# Log data access
audit.log_data_access(
    user_id="user123",
    resource_id="document_456",
    action="read",
    success=True,
    details={"access_reason": "Monthly report generation"}
)

# Search logs for specific criteria
results = audit.search_logs(
    criteria={"user_id": "user123"},
    start_date="2023-01-01",
    end_date="2023-01-31"
)

# Export audit trail
exported_count = audit.export_logs(
    output_file="monthly_audit.json",
    start_date="2023-01-01",
    end_date="2023-01-31"
)

# Verify audit trail integrity
verification = audit.verify_integrity()
```

## Security Features

- **Tamper Detection**: Cryptographically secured chain of log records
- **Non-repudiation**: Digital signatures on all log entries
- **Confidentiality**: Optional encryption of log content
- **Integrity Verification**: Tools to detect any tampering with logs
- **Log Rotation**: Automatic management of log files
- **Chain of Custody**: Complete and verifiable history of system events

## Installation

The logging and audit system requires Python 3.8+ and the following dependencies:

```
cryptography>=3.4.0
```

## Configuration

Sample configuration:

```python
# SecureLogger configuration
secure_logger_config = {
    "name": "application_name",
    "log_level": "INFO",  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    "log_dir": "/var/log/secure",
    "node_id": "node-01",  # Unique identifier for this server
    "max_log_size_mb": 10,
    "retention_days": 90,
    "encryption_enabled": True,
    "key_file": "/etc/secure_logger/keys.json"
}

# AuditTrailService configuration
audit_trail_config = {
    "log_dir": "/var/log/audit",
    "retention_days": 365,
    "secret_key": "your-secret-key-here"  # For HMAC verification
}
```

## Security Classification

**LEVEL 5 - TOP SECRET**

Last Updated: April 2025
Version: 3.1.4

## Components

The logging and audit layer consists of the following components:

### 1. Secure Logging System

Located in `secure_logger.py`, this component provides:

- Tamper-proof logging with cryptographic verification
- Multi-level log severity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Structured logging with metadata support
- Log rotation and archiving with integrity protection
- Distributed logging with node identification

### 2. Audit Trail Service

Located in `audit_service.py`, this service manages:

- Recording of all security-relevant events
- Agent action tracking with clearance verification
- Data access monitoring and recording
- Query pattern analysis for anomaly detection
- Administrative action verification

### 3. Forensic Analysis Tools

Located in `forensics/`, these tools provide:

- Timeline reconstruction of system events
- Pattern analysis for security incidents
- Agent behavioral analysis
- Query correlation and intent analysis
- Data access pattern visualization

### 4. Anomaly Detection

Located in `anomaly_detection.py`, this component:

- Monitors for unusual system activity
- Identifies potential security breaches
- Detects unusual query patterns
- Tracks access pattern deviations
- Identifies possible covert channel attempts

### 5. Integration Manager

Located in `integration_manager.py`, this manages:

- Integration with the persistence layer
- Real-time notification services
- Security incident response workflows
- Long-term audit storage and archiving
- Compliance reporting and verification

## Usage Examples

### Basic Secure Logging

```python
from logging_audit.secure_logger import SecureLogger

# Create a secure logger
logger = SecureLogger(
    name="shadow_api_service",
    log_level="INFO",
    encryption_enabled=True
)

# Log various events
logger.info("API service started", extra={"node_id": "api-01"})
logger.warning("Unusual query pattern detected", extra={
    "agent_id": "A-12345",
    "pattern_id": "P-789",
    "anomaly_score": 0.87
})
logger.error("Access denied", extra={
    "agent_id": "A-12345",
    "resource": "quantum_research_data",
    "reason": "insufficient_clearance"
})
```

### Recording Audit Events

```python
from logging_audit.audit_service import AuditService
from persistence.db_models import ClearanceLevel
import uuid

# Create audit service
audit_service = AuditService()

# Record an audit event
audit_service.record_event(
    agent_id="A-12345",
    action_type="data_access",
    details={
        "resource": "project_shadow_specs",
        "operation": "read",
        "sections_accessed": ["overview", "architecture"]
    },
    clearance_level=ClearanceLevel.LEVEL_3
)

# Query for related events
events = audit_service.query_events(
    agent_id="A-12345",
    action_types=["data_access", "authentication"],
    time_range_hours=24,
    requestor_clearance=ClearanceLevel.LEVEL_4
)
```

### Forensic Analysis

```python
from logging_audit.forensics.timeline import TimelineAnalyzer
from logging_audit.forensics.pattern_analyzer import PatternAnalyzer
from datetime import datetime, timedelta

# Create timeline analyzer
timeline = TimelineAnalyzer()

# Generate security incident timeline
incident_timeline = timeline.reconstruct(
    incident_id="INC-20251015-001",
    start_time=datetime.now() - timedelta(hours=48),
    end_time=datetime.now(),
    related_agents=["A-12345", "A-67890"]
)

# Analyze patterns
pattern_analyzer = PatternAnalyzer()
unusual_patterns = pattern_analyzer.identify_anomalies(
    agent_id="A-12345",
    time_period_days=30,
    significance_threshold=0.85
)
```

### Anomaly Detection

```python
from logging_audit.anomaly_detection import AnomalyDetector

# Create anomaly detector
detector = AnomalyDetector(sensitivity="medium")

# Configure detection criteria
detector.configure(
    baseline_days=30,
    update_frequency_hours=24,
    alert_threshold=0.75
)

# Analyze current activity for anomalies
anomalies = detector.analyze_current_activity(
    agent_id="A-12345",
    context={"operation_type": "information_retrieval"}
)

# Register for real-time alerts
detector.register_alert_handler(alert_handler_function)
```

## Data Storage

The logging and audit layer persists data in several formats:

- **Secure Log Files**: Stored in `logs/` with cryptographic signatures
- **Audit Trail Database**: Leverages the persistence layer's `AuditTrailDatabase`
- **Forensic Analysis Data**: Stored in `data/forensics/` with case-specific directories
- **Anomaly Models**: Stored in `data/models/` for baseline behavioral patterns
- **Archived Logs**: Compressed and encrypted in `logs/archive/` with retention policies

## Security Considerations

1. All log records include cryptographic signatures to prevent tampering
2. Distributed logging with secure synchronization between nodes
3. Access to audit data is strictly controlled by clearance level
4. Log rotation preserves integrity with unbroken signature chains
5. Sensitive log data is encrypted using separate key management
6. Forensic analysis tools maintain chain-of-custody documentation

## Integration with Persistence Layer

The Logging & Audit Layer integrates closely with the Persistence Layer:

1. Uses the `AuditTrailDatabase` interface for storing structured audit records
2. Maintains references to `Agent` objects for attribution of actions
3. Enforces clearance checks via `AgentDatabase.verify_agent_clearance()`
4. Records access to `Rule` objects for security policy compliance
5. Integrates with `NeuralSignature` verification for action attribution

## Future Extensions

The logging and audit layer is designed to be extensible with additional features:

- `AIEnhancedForensics`: Machine learning for advanced pattern recognition
- `BlockchainAuditTrail`: Immutable distributed ledger for critical operations
- `RealTimeAlertSystem`: Advanced notification system for security incidents
- `IntentAnalysis`: Deeper behavioral analysis of agent query patterns
- `ComplianceReporting`: Automated generation of security compliance reports

