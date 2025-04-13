import os
import json
import datetime
import logging
import threading
import re
from typing import Dict, List, Optional, Any, Tuple

from persistence.db_models import Rule, ClearanceLevel
from persistence.db_interface import RulesDatabase
from persistence.json_storage import JsonStorage

# Set up logging
logger = logging.getLogger("shadow_persistence.rules")


class JsonRulesDatabase(RulesDatabase):
    """
    JSON implementation of the Rules Database interface
    """
    
    def __init__(self, file_path: str = "data/rules.json"):
        """Initialize the rules database with the specified file path"""
        self.storage = JsonStorage(file_path)
    
    def initialize(self) -> bool:
        """Initialize the database"""
        return self.storage.initialize()
    
    def close(self) -> None:
        """Close the database"""
        self.storage.close()
    
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Retrieve a rule by ID"""
        with self.storage.lock:
            if not rule_id or not self.storage.initialized:
                return None
                
            rule_data = self.storage.data.get("items", {}).get(rule_id)
            if not rule_data:
                return None
                
            return Rule.from_dict(rule_data)
    
    def create_rule(self, rule: Rule) -> bool:
        """Create a new rule"""
        with self.storage.lock:
            if not rule or not self.storage.initialized:
                return False
                
            # Check if rule already exists
            if rule.rule_id in self.storage.data.get("items", {}):
                logger.warning(f"Rule with ID {rule.rule_id} already exists")
                return False
            
            # Ensure items dict exists
            if "items" not in self.storage.data:
                self.storage.data["items"] = {}
            
            # Store rule data
            self.storage.data["items"][rule.rule_id] = rule.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def update_rule(self, rule: Rule) -> bool:
        """Update an existing rule"""
        with self.storage.lock:
            if not rule or not self.storage.initialized:
                return False
                
            # Check if rule exists
            if rule.rule_id not in self.storage.data.get("items", {}):
                logger.warning(f"Rule with ID {rule.rule_id} does not exist")
                return False
            
            # Update last_updated timestamp
            rule.last_updated = datetime.datetime.utcnow()
            
            # Update rule data
            self.storage.data["items"][rule.rule_id] = rule.to_dict()
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule"""
        with self.storage.lock:
            if not rule_id or not self.storage.initialized:
                return False
                
            # Check if rule exists
            if rule_id not in self.storage.data.get("items", {}):
                logger.warning(f"Rule with ID {rule_id} does not exist")
                return False
            
            # Delete rule data
            del self.storage.data["items"][rule_id]
            
            # Save if auto-save is enabled
            if self.storage.auto_save:
                self.storage.save()
                
            return True
    
    def list_rules(
        self,
        rule_type: Optional[str] = None,
        clearance_level: Optional[ClearanceLevel] = None,
        limit: int = 100, 
        offset: int = 0
    ) -> List[Rule]:
        """List rules with optional filtering"""
        with self.storage.lock:
            if not self.storage.initialized:
                return []
            
            # Get all rules
            all_rules = []
            for rule_data in self.storage.data.get("items", {}).values():
                try:
                    rule = Rule.from_dict(rule_data)
                    
                    # Apply filters
                    if rule_type and rule.rule_type != rule_type:
                        continue
                        
                    if clearance_level and rule.clearance_required.value != clearance_level.value:
                        continue
                    
                    all_rules.append(rule)
                except Exception as e:
                    logger.error(f"Error parsing rule data: {e}")
                    continue
            
            # Sort by rule_id for consistent results
            all_rules.sort(key=lambda r: r.rule_id)
            
            # Apply pagination
            return all_rules[offset:offset+limit]
    
    def search_rules(
        self, 
        query: str, 
        max_clearance: ClearanceLevel
    ) -> List[Rule]:
        """Search for rules matching a query string, constrained by max clearance"""
        with self.storage.lock:
            if not self.storage.initialized:
                return []
            
            query = query.lower()
            results = []
            
            for rule_data in self.storage.data.get("items", {}).values():
                try:
                    rule = Rule.from_dict(rule_data)
                    
                    # Skip rules above the max clearance level
                    if rule.clearance_required.value > max_clearance.value:
                        continue
                    
                    # Search in description, pattern, and rule_type
                    if (query in rule.description.lower() or 
                        query in rule.pattern.lower() or 
                        query in rule.rule_type.lower()):
                        results.append(rule)
                except Exception as e:
                    logger.error(f"Error parsing rule data: {e}")
                    continue
            
            # Sort by relevance (exact matches first, then by clearance level)
            def sort_key(rule):
                # Exact matches in description or pattern get highest priority
                exact_match = (
                    rule.description.lower() == query or 
                    rule.pattern.lower() == query
                )
                return (not exact_match, rule.clearance_required.value)
            
            results.sort(key=sort_key)
            
            return results
    
    def get_rules_by_clearance(
        self, 
        clearance_level: ClearanceLevel,
        include_lower: bool = True
    ) -> List[Rule]:
        """Get rules applicable to a specific clearance level"""
        with self.storage.lock:
            if not self.storage.initialized:
                return []
            
            results = []
            
            for rule_data in self.storage.data.get("items", {}).values():
                try:
                    rule = Rule.from_dict(rule_data)
                    
                    # Include rules at this clearance level
                    if rule.clearance_required.value == clearance_level.value:
                        results.append(rule)
                    # Include lower clearance rules if requested
                    elif include_lower and rule.clearance_required.value < clearance_level.value:
                        results.append(rule)
                except Exception as e:
                    logger.error(f"Error parsing rule data: {e}")
                    continue
            
            # Sort by clearance level (highest first) and then by rule_id
            results.sort(key=lambda r: (-r.clearance_required.value, r.rule_id))
            
            return results
    
    def export_rules_to_json(self, file_path: str) -> bool:
        """Export all rules to a JSON file"""
        with self.storage.lock:
            if not self.storage.initialized:
                return False
            
            try:
                # Ensure directory exists
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # Create export data
                export_data = {
                    "metadata": {
                        "exported_at": datetime.datetime.utcnow().isoformat(),
                        "rule_count": len(self.storage.data.get("items", {}))
                    },
                    "rules": list(self.storage.data.get("items", {}).values())
                }
                
                # Write to file
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                return True
            except Exception as e:
                logger.error(f"Failed to export rules to {file_path}: {e}")
                return False
    
    def import_rules_from_json(self, file_path: str) -> Tuple[int, int]:
        """Import rules from a JSON file, returns (success_count, error_count)"""
        with self.storage.lock:
            if not self.storage.initialized:
                return (0, 0)
            
            try:
                # Check if file exists
                if not os.path.exists(file_path):
                    logger.error(f"Import file {file_path} does not exist")
                    return (0, 0)
                
                # Read import data
                with open(file_path, 'r') as f:
                    import_data = json.load(f)
                
                rules = import_data.get("rules", [])
                success_count = 0
                error_count = 0
                
                # Ensure items dict exists
                if "items" not in self.storage.data:
                    self.storage.data["items"] = {}
                
                # Import rules
                for rule_data in rules:
                    try:
                        # Create rule object to validate data
                        rule = Rule.from_dict(rule_data)
                        
                        # Store rule data
                        self.storage.data["items"][rule.rule_id] = rule.to_dict()
                        success_count += 1
                    except Exception as e:
                        logger.error(f"Error importing rule: {e}")
                        error_count += 1
                
                # Save if auto-save is enabled and at least one rule was imported
                if self.storage.auto_save and success_count > 0:
                    self.storage.save()
                
                return (success_count, error_count)
            except Exception as e:
                logger.error(f"Failed to import rules from {file_path}: {e}")
                return (0, 1) 