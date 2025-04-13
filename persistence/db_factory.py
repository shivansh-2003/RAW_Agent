import os
import logging
from typing import Dict, Optional, Any, Type

from persistence.db_interface import (
    AgentDatabase, RulesDatabase,
    AuditTrailDatabase, NeuralSignatureDatabase
)
from persistence.json_storage import JsonStorage
from persistence.json_rules_db import JsonRulesDatabase
from persistence.json_audit_trail_db import JsonAuditTrailDatabase
from persistence.json_neural_signature_db import JsonNeuralSignatureDatabase

# Set up logging
logger = logging.getLogger("shadow_persistence.factory")


class DatabaseTypes:
    """Available database types"""
    JSON = "json"
    # Future implementations could include:
    # SQLITE = "sqlite"
    # POSTGRES = "postgres"
    # ENCRYPTED = "encrypted"


class DatabaseFactory:
    """
    Factory for creating database instances for the persistence layer
    """
    
    @staticmethod
    def create_agent_database(
        db_type: str = DatabaseTypes.JSON,
        config: Optional[Dict[str, Any]] = None
    ) -> AgentDatabase:
        """
        Create an agent database instance
        
        Args:
            db_type: Database type to create
            config: Optional configuration for the database
            
        Returns:
            An instance of AgentDatabase
        
        Raises:
            ValueError: If the database type is not supported
        """
        config = config or {}
        
        if db_type == DatabaseTypes.JSON:
            file_path = config.get("file_path", "data/agents.json")
            from persistence.json_agent_db import JsonAgentDatabase
            return JsonAgentDatabase(file_path=file_path)
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
    
    @staticmethod
    def create_rules_database(
        db_type: str = DatabaseTypes.JSON,
        config: Optional[Dict[str, Any]] = None
    ) -> RulesDatabase:
        """
        Create a rules database instance
        
        Args:
            db_type: Database type to create
            config: Optional configuration for the database
            
        Returns:
            An instance of RulesDatabase
        
        Raises:
            ValueError: If the database type is not supported
        """
        config = config or {}
        
        if db_type == DatabaseTypes.JSON:
            file_path = config.get("file_path", "data/rules.json")
            return JsonRulesDatabase(file_path=file_path)
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
    
    @staticmethod
    def create_audit_trail_database(
        db_type: str = DatabaseTypes.JSON,
        config: Optional[Dict[str, Any]] = None
    ) -> AuditTrailDatabase:
        """
        Create an audit trail database instance
        
        Args:
            db_type: Database type to create
            config: Optional configuration for the database
            
        Returns:
            An instance of AuditTrailDatabase
        
        Raises:
            ValueError: If the database type is not supported
        """
        config = config or {}
        
        if db_type == DatabaseTypes.JSON:
            file_path = config.get("file_path", "data/audit_trail.json")
            return JsonAuditTrailDatabase(file_path=file_path)
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
    
    @staticmethod
    def create_neural_signature_database(
        db_type: str = DatabaseTypes.JSON,
        config: Optional[Dict[str, Any]] = None
    ) -> NeuralSignatureDatabase:
        """
        Create a neural signature database instance
        
        Args:
            db_type: Database type to create
            config: Optional configuration for the database
            
        Returns:
            An instance of NeuralSignatureDatabase
        
        Raises:
            ValueError: If the database type is not supported
        """
        config = config or {}
        
        if db_type == DatabaseTypes.JSON:
            file_path = config.get("file_path", "data/neural_signatures.json")
            return JsonNeuralSignatureDatabase(file_path=file_path)
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
    
    @staticmethod
    def initialize_all_databases(
        db_type: str = DatabaseTypes.JSON,
        base_path: str = "data",
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Initialize all databases for the system
        
        Args:
            db_type: Database type to create
            base_path: Base path for database files
            config: Optional configuration for the databases
            
        Returns:
            Dictionary containing all initialized database instances
        """
        config = config or {}
        
        # Ensure data directory exists
        os.makedirs(base_path, exist_ok=True)
        
        # Create database instances
        agent_db = DatabaseFactory.create_agent_database(
            db_type=db_type,
            config={"file_path": os.path.join(base_path, "agents.json")}
        )
        
        rules_db = DatabaseFactory.create_rules_database(
            db_type=db_type,
            config={"file_path": os.path.join(base_path, "rules.json")}
        )
        
        audit_trail_db = DatabaseFactory.create_audit_trail_database(
            db_type=db_type,
            config={"file_path": os.path.join(base_path, "audit_trail.json")}
        )
        
        neural_signature_db = DatabaseFactory.create_neural_signature_database(
            db_type=db_type,
            config={"file_path": os.path.join(base_path, "neural_signatures.json")}
        )
        
        # Initialize all databases
        databases = {
            "agent_db": agent_db,
            "rules_db": rules_db,
            "audit_trail_db": audit_trail_db,
            "neural_signature_db": neural_signature_db
        }
        
        # Initialize each database
        for name, db in databases.items():
            success = db.initialize()
            if not success:
                logger.error(f"Failed to initialize {name}")
        
        return databases 