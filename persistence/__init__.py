"""
Project SHADOW Persistence Layer

This package provides data persistence for Project SHADOW, including:
- Agent profiles and clearance data
- Security rules
- Audit trail
- Neural signatures

The persistence layer is designed to be modular and extensible,
with a consistent interface for different storage backends.
"""

from persistence.db_models import (
    Agent, Rule, AuditTrail, NeuralSignature,
    ClearanceLevel, AccessStatus
)

from persistence.db_interface import (
    AgentDatabase, RulesDatabase,
    AuditTrailDatabase, NeuralSignatureDatabase
)

from persistence.db_factory import DatabaseFactory, DatabaseTypes

__version__ = "3.2.1"
__author__ = "Project SHADOW Development Team" 