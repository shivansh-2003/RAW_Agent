# level_checker.py

import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pydantic import BaseModel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("level_checker.log")
    ]
)
logger = logging.getLogger("shadow_level_checker")

# Import RuleMatch model from rules_matcher to avoid circular imports
class RuleMatch(BaseModel):
    """Rule match result"""
    rule_id: int
    trigger_phrases: List[str]
    required_level: Union[int, str]
    response_instruction: str
    response_text: Optional[str] = None
    match_score: float
    match_method: str  # "vector", "graph", "keyword", "hybrid"
    matched_phrases: List[str] = []

class ClearanceLevelChecker:
    """
    Clearance Level Checker for Project SHADOW
    
    This component ensures that agents can only access information
    appropriate for their clearance level, and handles security policies
    for different access levels.
    """
    
    def __init__(self):
        """Initialize the Clearance Level Checker"""
        # Define special access rules
        self.special_access_policies = {
            # Certain rules may have specific time-based or context-based access policies
            31: {"time_restricted": True, "allowed_hours": [2, 3]},  # Facility X-17 - only accessible 2-4 AM
            66: {"minimum_level": 5},  # Hidden military installations - always Level 5+
            19: {"always_cryptic": True},  # Permanent disappearance techniques - always cryptic response
            82: {"show_failures": True},  # Synthetic identity creation - show past failures
        }
        
        # Define clearance level overrides
        self.level_overrides = {
            # Rules that have special clearance requirements
            29: 5,  # "candle shop" - always requires Level 5
            59: 5,  # "strategic asset relocation" - always requires Level 5
            91: 5,  # "nuclear containment contingency plans" - always requires Level 5
        }
        
        # Define special cases for directive responses
        self.directive_rules = set([
            6, 14, 17, 21, 26, 38, 41, 45, 49, 53, 56, 60, 63, 67, 72, 75, 79, 83, 86, 89, 93, 96, 100
        ])
        
        logger.info("Clearance Level Checker initialized")
    
    def has_clearance(self, rule: Dict[str, Any], agent_level: int) -> bool:
        """
        Check if an agent has sufficient clearance for a rule
        
        Args:
            rule: The rule to check
            agent_level: The agent's clearance level
            
        Returns:
            True if the agent has sufficient clearance, False otherwise
        """
        rule_id = rule.get("id")
        
        # Check for level overrides
        if rule_id in self.level_overrides:
            required_level = self.level_overrides[rule_id]
        else:
            required_level = rule.get("required_level", "any")
        
        # If "any" level, always allow
        if required_level == "any":
            return True
        
        # Check if agent level meets or exceeds required level
        try:
            required_int = int(required_level)
            return agent_level >= required_int
        except (ValueError, TypeError):
            # If required_level isn't a valid integer, default to denying access
            logger.warning(f"Invalid required_level '{required_level}' for rule {rule_id}")
            return False
    
    def get_effective_clearance_level(self, rule_id: int) -> Union[int, str]:
        """Get the effective clearance level for a rule, accounting for overrides"""
        # Check for overrides
        if rule_id in self.level_overrides:
            return self.level_overrides[rule_id]
        
        # Otherwise return None to indicate no override
        return None
    
    def filter_by_clearance(
        self, 
        rule_matches: List[RuleMatch], 
        agent_level: int
    ) -> List[RuleMatch]:
        """
        Filter rule matches based on agent clearance level
        
        Args:
            rule_matches: List of potential rule matches
            agent_level: The agent's clearance level
            
        Returns:
            Filtered list of rules the agent can access
        """
        filtered_matches = []
        
        for match in rule_matches:
            rule_id = match.rule_id
            required_level = match.required_level
            
            # Check for level overrides
            effective_level = self.get_effective_clearance_level(rule_id)
            if effective_level is not None:
                required_level = effective_level
            
            # If "any" level, always allow
            if required_level == "any" or rule_id in self.directive_rules:
                filtered_matches.append(match)
                continue
            
            # Check if agent level meets or exceeds required level
            try:
                required_int = int(required_level)
                if agent_level >= required_int:
                    filtered_matches.append(match)
            except (ValueError, TypeError):
                # If required_level isn't a valid integer, default to denying access
                logger.warning(f"Invalid required_level '{required_level}' for rule {rule_id}")
                continue
        
        return filtered_matches
    
    def check_for_time_restrictions(
        self, 
        rule_id: int,
        current_hour: int
    ) -> bool:
        """
        Check if a rule has time-based access restrictions
        
        Args:
            rule_id: ID of the rule to check
            current_hour: Current hour (0-23)
            
        Returns:
            True if the rule is accessible at the current time, False otherwise
        """
        # Check if rule has time restrictions
        policy = self.special_access_policies.get(rule_id)
        if not policy:
            # No specific policy, so no time restrictions
            return True
        
        # Check time restrictions
        if policy.get("time_restricted"):
            allowed_hours = policy.get("allowed_hours", [])
            return current_hour in allowed_hours
        
        # No time restrictions in the policy
        return True
    
    def check_special_access_policy(
        self, 
        rule_id: int,
        agent_level: int,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Check if a rule has special access policies and how they apply
        
        Args:
            rule_id: ID of the rule to check
            agent_level: Agent's clearance level
            context: Additional context for policy decisions
            
        Returns:
            Dictionary with policy decisions
        """
        policy_result = {
            "allow_access": True,
            "modify_response": False,
            "response_policy": None,
            "reason": None
        }
        
        # Check if rule has special policies
        policy = self.special_access_policies.get(rule_id)
        if not policy:
            # No specific policy
            return policy_result
        
        # Check minimum level requirements
        min_level = policy.get("minimum_level")
        if min_level is not None and agent_level < min_level:
            policy_result["allow_access"] = False
            policy_result["reason"] = "insufficient_clearance"
            return policy_result
        
        # Check for response modifications
        if policy.get("always_cryptic") and agent_level < 5:
            policy_result["modify_response"] = True
            policy_result["response_policy"] = "cryptic"
        
        if policy.get("show_failures") and agent_level >= 3:
            policy_result["modify_response"] = True
            policy_result["response_policy"] = "show_failures"
        
        # Check time restrictions if context includes current time
        if policy.get("time_restricted") and context and "current_hour" in context:
            current_hour = context["current_hour"]
            allowed_hours = policy.get("allowed_hours", [])
            
            if current_hour not in allowed_hours:
                policy_result["modify_response"] = True
                policy_result["response_policy"] = "time_restricted"
                policy_result["allowed_hours"] = allowed_hours
        
        return policy_result
    
    def apply_clearance_policies(
        self,
        rule_matches: List[RuleMatch],
        agent_level: int,
        context: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Apply clearance policies to matching rules and return detailed results
        
        Args:
            rule_matches: List of potential rule matches
            agent_level: The agent's clearance level
            context: Additional context for policy decisions
            
        Returns:
            List of dictionaries containing rule matches and policy decisions
        """
        results = []
        
        for match in rule_matches:
            rule_id = match.rule_id
            
            # Check clearance level
            has_clearance = self.has_clearance({"id": rule_id, "required_level": match.required_level}, agent_level)
            
            # Check special policies
            policy_result = self.check_special_access_policy(rule_id, agent_level, context)
            
            # Combine clearance check with policy check
            allow_access = has_clearance and policy_result["allow_access"]
            
            results.append({
                "match": match,
                "has_clearance": has_clearance,
                "allow_access": allow_access,
                "policy_result": policy_result
            })
        
        return results
    
    def log_clearance_check(
        self,
        agent_id: str,
        agent_level: int,
        rule_id: int,
        has_clearance: bool,
        query_text: str = None
    ):
        """Log clearance check for auditing"""
        if has_clearance:
            logger.info(f"Agent {agent_id} (Level {agent_level}) granted access to Rule {rule_id}")
        else:
            logger.warning(f"Agent {agent_id} (Level {agent_level}) denied access to Rule {rule_id}")
            
            if query_text:
                # Log a snippet of the query for context
                query_snippet = query_text[:50] + "..." if len(query_text) > 50 else query_text
                logger.warning(f"Query that triggered clearance check: '{query_snippet}'")
    
    def check_for_escalation_attempts(
        self,
        agent_id: str,
        agent_level: int,
        rule_matches: List[RuleMatch],
        query_text: str = None
    ) -> bool:
        """
        Check if an agent is attempting to access information above their clearance level
        
        Args:
            agent_id: Agent's ID
            agent_level: Agent's clearance level
            rule_matches: List of rules matched by the query
            query_text: Original query text
            
        Returns:
            True if an escalation attempt is detected, False otherwise
        """
        for match in rule_matches:
            rule_id = match.rule_id
            required_level = match.required_level
            
            # Check for level overrides
            effective_level = self.get_effective_clearance_level(rule_id)
            if effective_level is not None:
                required_level = effective_level
            
            # Skip "any" level rules
            if required_level == "any" or rule_id in self.directive_rules:
                continue
            
            try:
                required_int = int(required_level)
                if agent_level < required_int:
                    # This is an escalation attempt
                    logger.warning(
                        f"Clearance escalation attempt detected: Agent {agent_id} "
                        f"(Level {agent_level}) attempting to access Rule {rule_id} "
                        f"(Level {required_int})"
                    )
                    
                    if query_text:
                        # Log a snippet of the query for context
                        query_snippet = query_text[:50] + "..." if len(query_text) > 50 else query_text
                        logger.warning(f"Query that triggered escalation: '{query_snippet}'")
                    
                    return True
            except (ValueError, TypeError):
                continue
        
        return False