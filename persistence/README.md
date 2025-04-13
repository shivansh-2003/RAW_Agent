# Project SHADOW Data Persistence Layer

## Overview

The Data Persistence Layer in Project SHADOW provides a secure and flexible storage system for agent profiles, clearance levels, security rules, audit trails, and neural signatures. It implements a modular design that allows for different storage backends while maintaining a consistent interface.

## Security Classification

**LEVEL 5 - TOP SECRET**

Last Updated: April 2025
Version: 3.2.1

## Components

The persistence layer consists of the following components:

### 1. Database Models

Located in `db_models.py`, these define the core data entities:

- `Agent`: Represents an agent profile with clearance level, access status, and history
- `Rule`: Defines security rules used for access control and information filtering
- `AuditTrail`: Stores encrypted records of system events and agent activities
- `NeuralSignature`: Stores neural patterns used for agent verification

### 2. Database Interfaces

Located in `db_interface.py`, these provide abstract interfaces for database operations:

- `AgentDatabase`: Interface for agent profile operations
- `RulesDatabase`: Interface for security rule operations
- `AuditTrailDatabase`: Interface for audit trail operations
- `NeuralSignatureDatabase`: Interface for neural signature operations

### 3. JSON Implementations

Located in separate files, these implement the database interfaces using JSON file storage:

- `JsonAgentDatabase`: Implementation of agent database using JSON files
- `JsonRulesDatabase`: Implementation of rules database using JSON files
- `JsonAuditTrailDatabase`: Implementation of audit trail database using JSON files
- `JsonNeuralSignatureDatabase`: Implementation of neural signature database using JSON files

### 4. Base Storage

Located in `json_storage.py`, this provides the foundation for JSON-based storage:

- `JsonStorage`: Base class for JSON file storage with locking, saving, and loading

### 5. Database Factory

Located in `db_factory.py`, this provides a factory for creating database instances:

- `DatabaseFactory`: Factory for creating and initializing database instances

## Usage Examples

### Initializing All Databases

```python
from persistence.db_factory import DatabaseFactory

# Initialize all databases with default settings
databases = DatabaseFactory.initialize_all_databases()

# Access individual databases
agent_db = databases["agent_db"]
rules_db = databases["rules_db"]
audit_trail_db = databases["audit_trail_db"]
neural_signature_db = databases["neural_signature_db"]
```

### Working with Agents

```python
from persistence.db_factory import DatabaseFactory
from persistence.db_models import Agent, ClearanceLevel, AccessStatus
import uuid

# Create agent database
agent_db = DatabaseFactory.create_agent_database()
agent_db.initialize()

# Create a new agent
agent = Agent(
    agent_id=f"A-{uuid.uuid4()}",
    name="Agent Smith",
    clearance_level=ClearanceLevel.LEVEL_3,
    neural_signature_id="NS-12345",
    access_status=AccessStatus.ACTIVE,
    specialties=["Infiltration", "Cyber"]
)
agent_db.create_agent(agent)

# Retrieve an agent
retrieved_agent = agent_db.get_agent(agent.agent_id)

# Update agent clearance
agent_db.update_agent_clearance(
    agent_id=agent.agent_id,
    new_clearance=ClearanceLevel.LEVEL_4,
    reason="Exceptional performance in Operation Blackout",
    updated_by="SYSTEM"
)

# Close database when done
agent_db.close()
```

### Working with Rules

```python
from persistence.db_factory import DatabaseFactory
from persistence.db_models import Rule, ClearanceLevel
import uuid

# Create rules database
rules_db = DatabaseFactory.create_rules_database()
rules_db.initialize()

# Create a new rule
rule = Rule(
    rule_id=f"R-{uuid.uuid4()}",
    description="Access to Project Quantum files",
    pattern="project_quantum_*",
    clearance_required=ClearanceLevel.LEVEL_4,
    rule_type="access_control"
)
rules_db.create_rule(rule)

# Get rules for a specific clearance level
level_3_rules = rules_db.get_rules_by_clearance(
    clearance_level=ClearanceLevel.LEVEL_3,
    include_lower=True
)

# Export rules to JSON file
rules_db.export_rules_to_json("backup/rules_export.json")

# Close database when done
rules_db.close()
```

### Logging Audit Events

```python
from persistence.db_factory import DatabaseFactory
from persistence.db_models import AuditTrail, ClearanceLevel
import uuid
import datetime

# Create audit trail database
audit_db = DatabaseFactory.create_audit_trail_database()
audit_db.initialize()

# Log an audit event
audit_entry = AuditTrail(
    entry_id=str(uuid.uuid4()),
    agent_id="A-12345",
    action_type="file_access",
    timestamp=datetime.datetime.utcnow(),
    encrypted_details="{\"file\": \"project_quantum_report.pdf\", \"operation\": \"read\"}",
    encryption_metadata={"algorithm": "AES-256-GCM", "key_id": "K-789"},
    clearance_level=ClearanceLevel.LEVEL_3
)
audit_db.log_event(audit_entry)

# Query events
recent_events = audit_db.query_events(
    agent_id="A-12345",
    start_time=datetime.datetime.utcnow() - datetime.timedelta(days=7),
    requestor_clearance=ClearanceLevel.LEVEL_5
)

# Close database when done
audit_db.close()
```

### Managing Neural Signatures

```python
from persistence.db_factory import DatabaseFactory
from persistence.db_models import NeuralSignature
import uuid

# Create neural signature database
signature_db = DatabaseFactory.create_neural_signature_database()
signature_db.initialize()

# Create a new neural signature
signature = NeuralSignature(
    signature_id=f"NS-{uuid.uuid4()}",
    agent_id="A-12345",
    signature_data={"neural_pattern": [0.2, 0.7, 0.1, 0.5, ...], "metadata": {...}},
    verification_threshold=0.85,
    signature_version="2.1"
)
signature_db.create_signature(signature)

# Record verification attempt
signature_db.record_verification_attempt(
    signature_id=signature.signature_id,
    success=True,
    verification_score=0.92,
    verification_data={"match_points": 12, "duration_ms": 245}
)

# Close database when done
signature_db.close()
```

## Data Storage

By default, all JSON data is stored in the `data/` directory with the following files:

- `agents.json`: Agent profiles and clearance data
- `rules.json`: Security rules for access control
- `audit_trail.json`: Encrypted audit trail records
- `neural_signatures.json`: Neural signature data for agent verification

## Security Considerations

1. All sensitive data should be encrypted before storage
2. Access to the persistence layer should be restricted to authorized processes
3. Regular backups of the data files should be maintained
4. Audit trail data should never be directly modified after creation
5. All database operations are thread-safe with proper locking mechanisms

## Future Extensions

The persistence layer is designed to be extensible with additional storage backends:

- `SQLiteDatabase`: Implementation using SQLite for improved query performance
- `EncryptedDatabase`: Implementation with full database encryption
- `RemoteDatabase`: Implementation for cloud-based storage with redundancy

## License

CLASSIFIED - For authorized use only within Project SHADOW.
All rights reserved. 