import os
import json
import datetime
import logging
from typing import Dict, List, Optional, Any, Tuple

from persistence.db_models import Agent, ClearanceLevel, AccessStatus
from persistence.db_interface import AgentDatabase
from persistence.json_storage import JsonStorage

# Set up logging
logger = logging.getLogger("shadow_persistence.agent")


class JsonAgentDatabase(AgentDatabase):
    """
    JSON implementation of the Agent Database interface
    """
    
    def __init__(self, file_path: str = "data/agents.json"):
        """Initialize the agent database with the specified file path"""
        self.storage = JsonStorage(file_path)
    
    def initialize(self) -> bool:
        """Initialize the database"""
        return self.storage.initialize()
    
    def close(self) -> None:
        """Close the database"""
        self.storage.close()
    
    def get_agent(self, agent_id: str) -> Optional[Agent]:
        """Retrieve an agent by ID"""
        with self.storage.lock:
            if not agent_id or not self.storage.initialized:
                return None
                
            agent_data = self.storage.data.get("items", {}).get(agent_id)
            if not agent_data:
                return None
                
            return Agent.from_dict(agent_data)
    
    def create_agent(self, agent: Agent) -> bool:
        """Create a new agent record"""
        with self.storage.lock:
            if not agent or not self.storage.initialized:
                return False
                
            # Check if agent already exists
            if agent.agent_id in self.storage.data.get("items", {}):
                logger.warning(f"Agent with ID {agent.agent_id} already exists")
                return False
            
            # Ensure items dict exists
            if "items" not in self.storage.data:
                self.storage.data["items"] = {}
            
            # Store agent data
            self.storage.data["items"][agent.agent_id] = agent.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def update_agent(self, agent: Agent) -> bool:
        """Update an existing agent record"""
        with self.storage.lock:
            if not agent or not self.storage.initialized:
                return False
                
            # Check if agent exists
            if agent.agent_id not in self.storage.data.get("items", {}):
                logger.warning(f"Agent with ID {agent.agent_id} does not exist")
                return False
            
            # Update last_updated timestamp
            agent.last_updated = datetime.datetime.utcnow()
            
            # Update agent data
            self.storage.data["items"][agent.agent_id] = agent.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent record"""
        with self.storage.lock:
            if not agent_id or not self.storage.initialized:
                return False
                
            # Check if agent exists
            if agent_id not in self.storage.data.get("items", {}):
                logger.warning(f"Agent with ID {agent_id} does not exist")
                return False
            
            # Delete agent data
            del self.storage.data["items"][agent_id]
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def list_agents(
        self, 
        clearance_level: Optional[ClearanceLevel] = None,
        access_status: Optional[AccessStatus] = None,
        specialty: Optional[str] = None,
        limit: int = 100, 
        offset: int = 0
    ) -> List[Agent]:
        """List agents with optional filtering"""
        with self.storage.lock:
            if not self.storage.initialized:
                return []
            
            # Get all agents
            all_agents = []
            for agent_data in self.storage.data.get("items", {}).values():
                agent = Agent.from_dict(agent_data)
                
                # Apply filters
                if clearance_level and agent.clearance_level != clearance_level:
                    continue
                    
                if access_status and agent.access_status != access_status:
                    continue
                    
                if specialty and specialty not in agent.specialties:
                    continue
                
                all_agents.append(agent)
            
            # Sort by agent_id for consistent results
            all_agents.sort(key=lambda a: a.agent_id)
            
            # Apply pagination
            return all_agents[offset:offset+limit]
    
    def update_agent_clearance(
        self, 
        agent_id: str, 
        new_clearance: ClearanceLevel,
        reason: str,
        updated_by: str
    ) -> bool:
        """Update an agent's clearance level with audit information"""
        with self.storage.lock:
            if not agent_id or not self.storage.initialized:
                return False
            
            # Get agent
            agent = self.get_agent(agent_id)
            if not agent:
                logger.warning(f"Agent with ID {agent_id} does not exist")
                return False
            
            # Log the change in access history
            old_clearance = agent.clearance_level
            agent.access_history.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "action": "clearance_update",
                "old_clearance": old_clearance.value,
                "new_clearance": new_clearance.value,
                "reason": reason,
                "updated_by": updated_by
            })
            
            # Update clearance
            agent.clearance_level = new_clearance
            agent.last_updated = datetime.datetime.utcnow()
            
            # Save agent
            self.storage.data["items"][agent_id] = agent.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def update_agent_status(
        self, 
        agent_id: str, 
        new_status: AccessStatus,
        reason: str,
        updated_by: str
    ) -> bool:
        """Update an agent's access status with audit information"""
        with self.storage.lock:
            if not agent_id or not self.storage.initialized:
                return False
            
            # Get agent
            agent = self.get_agent(agent_id)
            if not agent:
                logger.warning(f"Agent with ID {agent_id} does not exist")
                return False
            
            # Log the change in access history
            old_status = agent.access_status
            agent.access_history.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "action": "status_update",
                "old_status": old_status.value,
                "new_status": new_status.value,
                "reason": reason,
                "updated_by": updated_by
            })
            
            # Update status
            agent.access_status = new_status
            agent.last_updated = datetime.datetime.utcnow()
            
            # Save agent
            self.storage.data["items"][agent_id] = agent.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def add_access_history_entry(
        self, 
        agent_id: str, 
        action: str,
        details: Dict[str, Any],
        performed_by: str
    ) -> bool:
        """Add an entry to an agent's access history"""
        with self.storage.lock:
            if not agent_id or not self.storage.initialized:
                return False
            
            # Get agent
            agent = self.get_agent(agent_id)
            if not agent:
                logger.warning(f"Agent with ID {agent_id} does not exist")
                return False
            
            # Add entry to access history
            entry = {
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "action": action,
                "details": details,
                "performed_by": performed_by
            }
            agent.access_history.append(entry)
            agent.last_updated = datetime.datetime.utcnow()
            
            # Save agent
            self.storage.data["items"][agent_id] = agent.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def verify_agent_clearance(
        self, 
        agent_id: str, 
        required_level: ClearanceLevel
    ) -> Tuple[bool, str]:
        """Verify if an agent has sufficient clearance for an operation"""
        with self.storage.lock:
            if not agent_id or not self.storage.initialized:
                return False, "Database not initialized"
            
            # Get agent
            agent = self.get_agent(agent_id)
            if not agent:
                return False, f"Agent with ID {agent_id} does not exist"
            
            # Check if agent is active
            if agent.access_status != AccessStatus.ACTIVE:
                return False, f"Agent access status is {agent.access_status.value}"
            
            # Check clearance level
            if agent.clearance_level.value < required_level.value:
                return False, (
                    f"Insufficient clearance: agent has level {agent.clearance_level.value}, "
                    f"but level {required_level.value} is required"
                )
            
            return True, "Clearance verified" 