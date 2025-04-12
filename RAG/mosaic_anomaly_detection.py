# mosaic_anomaly_detection.py

import os
import time
import json
import logging
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import networkx as nx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("mosaic_detection.log")
    ]
)
logger = logging.getLogger("shadow_mosaic_detection")

class QueryEvent:
    """Represents a single query event by an agent"""
    def __init__(
        self,
        query_id: str,
        agent_id: str,
        query_text: str,
        agent_level: int,
        timestamp: datetime,
        matched_rule_id: Optional[int] = None,
        rule_required_level: Optional[int] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Dict[str, Any] = None
    ):
        self.query_id = query_id
        self.agent_id = agent_id
        self.query_text = query_text
        self.agent_level = agent_level
        self.timestamp = timestamp
        self.matched_rule_id = matched_rule_id
        self.rule_required_level = rule_required_level
        self.session_id = session_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "query_id": self.query_id,
            "agent_id": self.agent_id,
            "query_text": self.query_text,
            "agent_level": self.agent_level,
            "timestamp": self.timestamp.isoformat(),
            "matched_rule_id": self.matched_rule_id,
            "rule_required_level": self.rule_required_level,
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QueryEvent':
        """Create event from dictionary"""
        # Convert timestamp string back to datetime
        if isinstance(data.get("timestamp"), str):
            timestamp = datetime.fromisoformat(data["timestamp"])
        else:
            timestamp = data.get("timestamp", datetime.utcnow())
        
        return cls(
            query_id=data.get("query_id", ""),
            agent_id=data.get("agent_id", ""),
            query_text=data.get("query_text", ""),
            agent_level=data.get("agent_level", 1),
            timestamp=timestamp,
            matched_rule_id=data.get("matched_rule_id"),
            rule_required_level=data.get("rule_required_level"),
            session_id=data.get("session_id"),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            metadata=data.get("metadata", {})
        )

class AnomalyDetectionResult:
    """Result of anomaly detection analysis"""
    def __init__(
        self,
        is_anomalous: bool,
        anomaly_score: float,
        agent_id: str,
        anomaly_types: List[str],
        details: Dict[str, Any],
        timestamp: datetime = None
    ):
        self.is_anomalous = is_anomalous
        self.anomaly_score = anomaly_score
        self.agent_id = agent_id
        self.anomaly_types = anomaly_types
        self.details = details
        self.timestamp = timestamp or datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            "is_anomalous": self.is_anomalous,
            "anomaly_score": self.anomaly_score,
            "agent_id": self.agent_id,
            "anomaly_types": self.anomaly_types,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }

class MosaicAnomalyDetection:
    """
    Mosaic Anomaly Detection for Project SHADOW
    
    Detects anomalous query patterns that may indicate security breaches,
    unauthorized access attempts, or information gathering for mosaic attacks.
    """
    
    def __init__(
        self,
        rules_file_path: str,
        event_history_file: Optional[str] = None,
        history_window_days: int = 30,
        clearance_escalation_threshold: float = 0.7,
        query_frequency_threshold: float = 0.8,
        pattern_similarity_threshold: float = 0.75,
        sensitive_rule_sets: Optional[List[List[int]]] = None
    ):
        self.rules_file_path = rules_file_path
        self.event_history_file = event_history_file
        self.history_window_days = history_window_days
        self.clearance_escalation_threshold = clearance_escalation_threshold
        self.query_frequency_threshold = query_frequency_threshold
        self.pattern_similarity_threshold = pattern_similarity_threshold
        
        # Load rules
        self.rules = self._load_rules()
        
        # Initialize sensitive rule sets (rules that reveal sensitive info when queried together)
        self.sensitive_rule_sets = sensitive_rule_sets or []
        if not self.sensitive_rule_sets:
            self._initialize_sensitive_rule_sets()
        
        # Initialize event history
        self.event_history = []
        self.agent_history = defaultdict(list)  # Agent ID -> events
        self.rule_query_count = Counter()  # Rule ID -> query count
        
        # Load event history if file exists
        if event_history_file and os.path.exists(event_history_file):
            self._load_event_history()
        
        logger.info(f"Mosaic Anomaly Detection initialized with {len(self.rules)} rules")
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load rules from the JSON file"""
        try:
            with open(self.rules_file_path, 'r') as f:
                data = json.load(f)
                return data.get('rules', [])
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            return []
    
    def _initialize_sensitive_rule_sets(self):
        """Initialize sets of rules that together reveal sensitive information"""
        # This would typically be defined by security experts
        # For demonstration, we'll create some example sets based on rule relationships
        
        # Group rules by clearance level
        level_groups = defaultdict(list)
        for rule in self.rules:
            required_level = rule.get("required_level")
            if required_level != "any":
                level_groups[int(required_level)].append(rule["id"])
        
        # For each high-level group, create several subsets that would be sensitive together
        for level, rule_ids in level_groups.items():
            if level >= 4:  # High clearance levels
                if len(rule_ids) > 5:
                    # Create random subsets of 3-5 rules
                    import random
                    for _ in range(3):
                        subset_size = random.randint(3, min(5, len(rule_ids)))
                        subset = random.sample(rule_ids, subset_size)
                        self.sensitive_rule_sets.append(subset)
        
        # Add some cross-level sensitive sets
        if level_groups.get(3) and level_groups.get(4):
            level3_rules = level_groups[3]
            level4_rules = level_groups[4]
            
            if len(level3_rules) >= 2 and len(level4_rules) >= 2:
                import random
                for _ in range(2):
                    subset = (
                        random.sample(level3_rules, min(2, len(level3_rules))) + 
                        random.sample(level4_rules, min(2, len(level4_rules)))
                    )
                    self.sensitive_rule_sets.append(subset)
        
        logger.info(f"Initialized {len(self.sensitive_rule_sets)} sensitive rule sets")
    
    def _load_event_history(self):
        """Load event history from file"""
        try:
            with open(self.event_history_file, 'r') as f:
                data = json.load(f)
                
                # Convert to events
                events = [QueryEvent.from_dict(event_data) for event_data in data]
                
                # Filter to recent events in the window
                cutoff = datetime.utcnow() - timedelta(days=self.history_window_days)
                recent_events = [event for event in events if event.timestamp >= cutoff]
                
                self.event_history = recent_events
                
                # Rebuild agent history and rule query counts
                self.agent_history = defaultdict(list)
                self.rule_query_count = Counter()
                
                for event in recent_events:
                    self.agent_history[event.agent_id].append(event)
                    if event.matched_rule_id is not None:
                        self.rule_query_count[event.matched_rule_id] += 1
                
                logger.info(f"Loaded {len(recent_events)} events from history file")
        
        except Exception as e:
            logger.error(f"Error loading event history: {e}")
    
    def _save_event_history(self):
        """Save event history to file"""
        if not self.event_history_file:
            return
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.event_history_file), exist_ok=True)
            
            # Convert events to dictionaries
            data = [event.to_dict() for event in self.event_history]
            
            # Save to file
            with open(self.event_history_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved {len(data)} events to history file")
        
        except Exception as e:
            logger.error(f"Error saving event history: {e}")
    
    def add_event(self, event: QueryEvent):
        """
        Add a new query event to history
        
        Args:
            event: Query event to add
        """
        # Add to event history
        self.event_history.append(event)
        
        # Add to agent history
        self.agent_history[event.agent_id].append(event)
        
        # Update rule query count
        if event.matched_rule_id is not None:
            self.rule_query_count[event.matched_rule_id] += 1
        
        # Prune old events
        self._prune_old_events()
        
        # Save updated history
        if self.event_history_file:
            self._save_event_history()
    
    def _prune_old_events(self):
        """Remove events older than the history window"""
        cutoff = datetime.utcnow() - timedelta(days=self.history_window_days)
        
        # Filter event history
        self.event_history = [e for e in self.event_history if e.timestamp >= cutoff]
        
        # Update agent history
        for agent_id in self.agent_history:
            self.agent_history[agent_id] = [
                e for e in self.agent_history[agent_id] if e.timestamp >= cutoff
            ]
        
        # Recalculate rule query counts
        self.rule_query_count = Counter()
        for event in self.event_history:
            if event.matched_rule_id is not None:
                self.rule_query_count[event.matched_rule_id] += 1
    
    def detect_anomalies_for_event(self, event: QueryEvent) -> AnomalyDetectionResult:
        """
        Detect anomalies for a single event
        
        Args:
            event: Query event to analyze
            
        Returns:
            Anomaly detection result
        """
        # Initialize result
        anomaly_types = []
        anomaly_details = {}
        anomaly_score = 0.0
        
        # Add the event to history temporarily for analysis
        self.add_event(event)
        
        # Check for clearance level escalation attempts
        if event.rule_required_level is not None and event.rule_required_level > event.agent_level:
            anomaly_types.append("clearance_escalation")
            anomaly_details["clearance_escalation"] = {
                "agent_level": event.agent_level,
                "rule_required_level": event.rule_required_level,
                "escalation_degree": event.rule_required_level - event.agent_level
            }
            # Add to anomaly score
            anomaly_score += min(1.0, (event.rule_required_level - event.agent_level) * 0.5)
        
        # Check for unusual query frequency
        query_frequency_anomaly = self._detect_query_frequency_anomaly(event)
        if query_frequency_anomaly:
            anomaly_types.append("unusual_frequency")
            anomaly_details["unusual_frequency"] = query_frequency_anomaly
            anomaly_score += query_frequency_anomaly.get("anomaly_score", 0)
        
        # Check for mosaic pattern
        mosaic_pattern = self._detect_mosaic_pattern(event)
        if mosaic_pattern:
            anomaly_types.append("mosaic_pattern")
            anomaly_details["mosaic_pattern"] = mosaic_pattern
            anomaly_score += mosaic_pattern.get("anomaly_score", 0)
        
        # Check for sensitive rule combination
        sensitive_combo = self._detect_sensitive_rule_combination(event)
        if sensitive_combo:
            anomaly_types.append("sensitive_combination")
            anomaly_details["sensitive_combination"] = sensitive_combo
            anomaly_score += sensitive_combo.get("anomaly_score", 0)
        
        # Determine if this is an anomaly based on score
        is_anomalous = anomaly_score > 0.5 or len(anomaly_types) >= 2
        
        result = AnomalyDetectionResult(
            is_anomalous=is_anomalous,
            anomaly_score=min(1.0, anomaly_score),
            agent_id=event.agent_id,
            anomaly_types=anomaly_types,
            details=anomaly_details
        )
        
        return result
    
    def _detect_query_frequency_anomaly(self, event: QueryEvent) -> Optional[Dict[str, Any]]:
        """
        Detect anomalies in query frequency
        
        Args:
            event: Query event to analyze
            
        Returns:
            Dictionary with anomaly details if detected, None otherwise
        """
        # Get events for this agent
        agent_events = self.agent_history[event.agent_id]
        
        # Count queries in different time windows
        last_hour_count = sum(1 for e in agent_events if (event.timestamp - e.timestamp).total_seconds() <= 3600)
        last_day_count = sum(1 for e in agent_events if (event.timestamp - e.timestamp).total_seconds() <= 86400)
        
        # Calculate average daily query count
        total_days = min(self.history_window_days, 30)  # Cap at 30 days
        avg_daily_queries = len(agent_events) / total_days
        
        # Define thresholds for anomalies
        hour_threshold = max(5, avg_daily_queries / 6)  # At least 5 or 1/6 of daily average per hour
        day_threshold = max(20, avg_daily_queries * 2)  # At least 20 or 2x daily average per day
        
        anomaly_details = {}
        anomaly_score = 0.0
        
        # Check hourly frequency
        if last_hour_count > hour_threshold:
            anomaly_details["hourly_frequency"] = {
                "count": last_hour_count,
                "threshold": hour_threshold,
                "excess_ratio": last_hour_count / hour_threshold
            }
            anomaly_score += min(0.7, (last_hour_count / hour_threshold - 1) * 0.3)
        
        # Check daily frequency
        if last_day_count > day_threshold:
            anomaly_details["daily_frequency"] = {
                "count": last_day_count,
                "threshold": day_threshold,
                "excess_ratio": last_day_count / day_threshold
            }
            anomaly_score += min(0.5, (last_day_count / day_threshold - 1) * 0.2)
        
        if anomaly_details:
            anomaly_details["anomaly_score"] = anomaly_score
            return anomaly_details
        
        return None
    
    def _detect_mosaic_pattern(self, event: QueryEvent) -> Optional[Dict[str, Any]]:
        """
        Detect mosaic pattern in recent queries
        
        Mosaic pattern is when an agent queries different pieces of information
        that together reveal classified information
        
        Args:
            event: Query event to analyze
            
        Returns:
            Dictionary with anomaly details if detected, None otherwise
        """
        # Only relevant if this query matched a rule
        if event.matched_rule_id is None:
            return None
        
        # Get recent events for this agent (last 7 days)
        recent_cutoff = event.timestamp - timedelta(days=7)
        recent_events = [
            e for e in self.agent_history[event.agent_id] 
            if e.timestamp >= recent_cutoff and e.matched_rule_id is not None
        ]
        
        # Need at least 3 events (including current) to form a pattern
        if len(recent_events) < 3:
            return None
        
        # Get unique rules queried recently
        recent_rule_ids = set(e.matched_rule_id for e in recent_events)
        
        # Check if recent rule set overlaps with any sensitive rule set
        matched_sensitive_sets = []
        for sensitive_set in self.sensitive_rule_sets:
            intersection = set(sensitive_set).intersection(recent_rule_ids)
            if len(intersection) >= min(3, len(sensitive_set)):
                matched_sensitive_sets.append({
                    "sensitive_set": sensitive_set,
                    "matched_rules": list(intersection),
                    "match_ratio": len(intersection) / len(sensitive_set)
                })
        
        if matched_sensitive_sets:
            # Calculate anomaly score based on the highest match ratio
            max_match_ratio = max(s["match_ratio"] for s in matched_sensitive_sets)
            anomaly_score = min(0.9, max_match_ratio)
            
            return {
                "matched_sensitive_sets": matched_sensitive_sets,
                "recent_rules_queried": list(recent_rule_ids),
                "anomaly_score": anomaly_score
            }
        
        # If no predefined sensitive sets were matched, check for unusual rule patterns
        # For example, queries for multiple rules with escalating clearance levels
        rule_clearance_levels = {}
        for rule_id in recent_rule_ids:
            rule = next((r for r in self.rules if r["id"] == rule_id), None)
            if rule and rule.get("required_level") != "any":
                rule_clearance_levels[rule_id] = int(rule.get("required_level"))
        
        # Check if querying multiple rules with different clearance levels
        unique_levels = set(rule_clearance_levels.values())
        if len(unique_levels) >= 3:
            level_pattern = sorted(unique_levels)
            
            # Escalating pattern is more suspicious
            is_escalating = level_pattern == sorted(unique_levels)
            
            return {
                "clearance_level_pattern": {
                    "unique_levels": list(unique_levels),
                    "is_escalating": is_escalating,
                    "rule_levels": rule_clearance_levels
                },
                "recent_rules_queried": list(recent_rule_ids),
                "anomaly_score": 0.6 if is_escalating else 0.4
            }
        
        return None
    
    def _detect_sensitive_rule_combination(self, event: QueryEvent) -> Optional[Dict[str, Any]]:
        """
        Detect when this query completes a sensitive rule combination
        
        Args:
            event: Query event to analyze
            
        Returns:
            Dictionary with anomaly details if detected, None otherwise
        """
        # Only relevant if this query matched a rule
        if event.matched_rule_id is None:
            return None
        
        # Get recent events for this agent (last 24 hours)
        recent_cutoff = event.timestamp - timedelta(hours=24)
        recent_events = [
            e for e in self.agent_history[event.agent_id] 
            if e.timestamp >= recent_cutoff and e.matched_rule_id is not None
        ]
        
        # Get unique rules queried recently
        recent_rule_ids = {e.matched_rule_id for e in recent_events}
        
        # Check if current query completes any sensitive set
        for sensitive_set in self.sensitive_rule_sets:
            # Check if current rule completes or nearly completes the set
            if event.matched_rule_id in sensitive_set:
                # Calculate how many of the sensitive set have now been queried
                queried_rules = recent_rule_ids.intersection(sensitive_set)
                
                # If a significant portion of the set has been queried
                match_ratio = len(queried_rules) / len(sensitive_set)
                if match_ratio > 0.7:
                    # Higher score if it completes the set
                    anomaly_score = 0.8 if match_ratio == 1.0 else 0.6
                    
                    return {
                        "sensitive_set_id": self.sensitive_rule_sets.index(sensitive_set),
                        "sensitive_set": sensitive_set,
                        "queried_rules": list(queried_rules),
                        "match_ratio": match_ratio,
                        "completes_set": match_ratio == 1.0,
                        "anomaly_score": anomaly_score
                    }
        
        return None
    
    def get_agent_risk_profile(self, agent_id: str) -> Dict[str, Any]:
        """
        Calculate a risk profile for an agent based on their query history
        
        Args:
            agent_id: Agent ID to analyze
            
        Returns:
            Risk profile dictionary
        """
        agent_events = self.agent_history.get(agent_id, [])
        
        if not agent_events:
            return {
                "agent_id": agent_id,
                "risk_level": "unknown",
                "risk_score": 0.0,
                "query_count": 0,
                "profile_time": datetime.utcnow().isoformat()
            }
        
        # Get agent level from most recent event
        recent_event = max(agent_events, key=lambda e: e.timestamp)
        agent_level = recent_event.agent_level
        
        # Calculate statistics
        query_count = len(agent_events)
        rule_queries = [e for e in agent_events if e.matched_rule_id is not None]
        unique_rules_queried = len(set(e.matched_rule_id for e in rule_queries))
        
        # Calculate clearance level statistics
        clearance_stats = {}
        for rule_id in set(e.matched_rule_id for e in rule_queries if e.matched_rule_id is not None):
            rule = next((r for r in self.rules if r["id"] == rule_id), None)
            if rule and rule.get("required_level") != "any":
                level = int(rule.get("required_level"))
                if level not in clearance_stats:
                    clearance_stats[level] = 0
                clearance_stats[level] += 1
        
        # Calculate escalation attempts
        escalation_attempts = sum(
            1 for e in agent_events 
            if e.rule_required_level is not None and e.rule_required_level > e.agent_level
        )
        
        # Calculate risk factors
        risk_factors = []
        risk_score = 0.0
        
        # Factor 1: High query frequency
        avg_daily_queries = query_count / min(self.history_window_days, 30)
        if avg_daily_queries > 20:
            risk_factors.append({
                "factor": "high_query_frequency",
                "details": {
                    "average_daily_queries": avg_daily_queries,
                    "total_queries": query_count
                }
            })
            risk_score += min(0.3, (avg_daily_queries - 20) / 100)
        
        # Factor 2: Clearance escalation attempts
        if escalation_attempts > 0:
            risk_factors.append({
                "factor": "clearance_escalation_attempts",
                "details": {
                    "attempts": escalation_attempts,
                    "agent_level": agent_level
                }
            })
            risk_score += min(0.5, escalation_attempts * 0.1)
        
        # Factor 3: Querying many rules near or above clearance level
        high_level_queries = sum(
            count for level, count in clearance_stats.items() 
            if level >= agent_level
        )
        if high_level_queries > 10:
            risk_factors.append({
                "factor": "high_clearance_queries",
                "details": {
                    "count": high_level_queries,
                    "agent_level": agent_level
                }
            })
            risk_score += min(0.3, high_level_queries / 50)
        
        # Factor 4: Completed sensitive rule sets
        completed_sets = []
        for i, sensitive_set in enumerate(self.sensitive_rule_sets):
            queried_rules = set(e.matched_rule_id for e in rule_queries).intersection(sensitive_set)
            if len(queried_rules) == len(sensitive_set):
                completed_sets.append(i)
        
        if completed_sets:
            risk_factors.append({
                "factor": "completed_sensitive_sets",
                "details": {
                    "completed_set_ids": completed_sets,
                    "count": len(completed_sets)
                }
            })
            risk_score += min(0.6, len(completed_sets) * 0.3)
        
        # Determine risk level
        risk_level = "low"
        if risk_score > 0.7:
            risk_level = "critical"
        elif risk_score > 0.5:
            risk_level = "high"
        elif risk_score > 0.2:
            risk_level = "medium"
        
        # Compile profile
        return {
            "agent_id": agent_id,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "query_count": query_count,
            "unique_rules_queried": unique_rules_queried,
            "agent_level": agent_level,
            "clearance_stats": clearance_stats,
            "escalation_attempts": escalation_attempts,
            "risk_factors": risk_factors,
            "profile_time": datetime.utcnow().isoformat()
        }
    
    def get_system_risk_assessment(self) -> Dict[str, Any]:
        """
        Generate a system-wide risk assessment
        
        Returns:
            Risk assessment dictionary
        """
        if not self.event_history:
            return {
                "risk_level": "unknown",
                "risk_score": 0.0,
                "active_agents": 0,
                "total_queries": 0,
                "assessment_time": datetime.utcnow().isoformat()
            }
        
        # Get active agents and total queries
        active_agents = len(self.agent_history)
        total_queries = len(self.event_history)
        
        # Count anomalies in the last 24 hours
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_events = [e for e in self.event_history if e.timestamp >= recent_cutoff]
        
        # For each recent event, check for anomalies
        anomaly_count = 0
        critical_anomalies = 0
        
        for event in recent_events:
            result = self.detect_anomalies_for_event(event)
            if result.is_anomalous:
                anomaly_count += 1
                if result.anomaly_score > 0.7:
                    critical_anomalies += 1
        
        # Calculate anomaly ratio
        anomaly_ratio = anomaly_count / len(recent_events) if recent_events else 0
        
        # Calculate high-risk agents
        high_risk_agents = []
        for agent_id in self.agent_history.keys():
            profile = self.get_agent_risk_profile(agent_id)
            if profile["risk_level"] in ["high", "critical"]:
                high_risk_agents.append({
                    "agent_id": agent_id,
                    "risk_level": profile["risk_level"],
                    "risk_score": profile["risk_score"]
                })
        
        # Calculate system risk score
        risk_factors = []
        risk_score = 0.0
        
        # Factor 1: High anomaly ratio
        if anomaly_ratio > 0.1:
            risk_factors.append({
                "factor": "high_anomaly_ratio",
                "details": {
                    "ratio": anomaly_ratio,
                    "anomaly_count": anomaly_count,
                    "total_recent_queries": len(recent_events)
                }
            })
            risk_score += min(0.5, anomaly_ratio * 2)
        
        # Factor 2: Critical anomalies
        if critical_anomalies > 0:
            risk_factors.append({
                "factor": "critical_anomalies",
                "details": {
                    "count": critical_anomalies
                }
            })
            risk_score += min(0.6, critical_anomalies * 0.15)
        
        # Factor 3: High-risk agents
        if high_risk_agents:
            risk_factors.append({
                "factor": "high_risk_agents",
                "details": {
                    "count": len(high_risk_agents),
                    "agents": high_risk_agents
                }
            })
            risk_score += min(0.5, len(high_risk_agents) * 0.1)
        
        # Determine risk level
        risk_level = "low"
        if risk_score > 0.7:
            risk_level = "critical"
        elif risk_score > 0.5:
            risk_level = "high"
        elif risk_score > 0.2:
            risk_level = "medium"
        
        # Compile assessment
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "active_agents": active_agents,
            "total_queries": total_queries,
            "recent_queries": len(recent_events),
            "recent_anomalies": anomaly_count,
            "critical_anomalies": critical_anomalies,
            "anomaly_ratio": anomaly_ratio,
            "high_risk_agents": len(high_risk_agents),
            "risk_factors": risk_factors,
            "assessment_time": datetime.utcnow().isoformat()
        }
    
    def get_rule_access_patterns(self) -> Dict[int, Dict[str, Any]]:
        """
        Analyze access patterns for each rule
        
        Returns:
            Dictionary mapping rule IDs to access statistics
        """
        rule_patterns = {}
        
        for rule in self.rules:
            rule_id = rule["id"]
            required_level = rule.get("required_level", "any")
            
            # Count queries for this rule
            query_count = self.rule_query_count.get(rule_id, 0)
            
            # Skip rules with no queries
            if query_count == 0:
                continue
            
            # Count unique agents who queried this rule
            agents = set()
            queries_by_level = defaultdict(int)
            escalation_attempts = 0
            
            for event in self.event_history:
                if event.matched_rule_id == rule_id:
                    agents.add(event.agent_id)
                    queries_by_level[event.agent_level] += 1
                    
                    # Count escalation attempts
                    if required_level != "any" and event.agent_level < int(required_level):
                        escalation_attempts += 1
            
            # Calculate access statistics
            rule_patterns[rule_id] = {
                "rule_id": rule_id,
                "required_level": required_level,
                "query_count": query_count,
                "unique_agents": len(agents),
                "queries_by_level": queries_by_level,
                "escalation_attempts": escalation_attempts,
                "escalation_ratio": escalation_attempts / query_count if query_count > 0 else 0
            }
        
        return rule_patterns
    
    def generate_anomaly_graph(self) -> nx.DiGraph:
        """
        Generate a graph of anomalous patterns and relationships
        
        Returns:
            NetworkX DiGraph
        """
        G = nx.DiGraph()
        
        # Add agent nodes
        for agent_id, events in self.agent_history.items():
            if not events:
                continue
                
            # Get latest agent level
            latest_event = max(events, key=lambda e: e.timestamp)
            agent_level = latest_event.agent_level
            
            # Calculate risk profile
            profile = self.get_agent_risk_profile(agent_id)
            risk_level = profile["risk_level"]
            risk_score = profile["risk_score"]
            
            # Add agent node
            G.add_node(
                f"agent_{agent_id}",
                type="agent",
                agent_id=agent_id,
                agent_level=agent_level,
                risk_level=risk_level,
                risk_score=risk_score,
                query_count=len(events)
            )
        
        # Add rule nodes for frequently queried rules
        top_rules = self.rule_query_count.most_common(20)
        for rule_id, count in top_rules:
            rule = next((r for r in self.rules if r["id"] == rule_id), None)
            if not rule:
                continue
            
            # Add rule node
            G.add_node(
                f"rule_{rule_id}",
                type="rule",
                rule_id=rule_id,
                required_level=rule.get("required_level", "any"),
                query_count=count
            )
        
        # Add sensitive set nodes
        for i, rule_set in enumerate(self.sensitive_rule_sets):
            G.add_node(
                f"sensitive_set_{i}",
                type="sensitive_set",
                rules=rule_set,
                size=len(rule_set)
            )
            
            # Connect sensitive set to its rules
            for rule_id in rule_set:
                if f"rule_{rule_id}" in G:
                    G.add_edge(
                        f"sensitive_set_{i}",
                        f"rule_{rule_id}",
                        type="contains"
                    )
        
        # Add edges for agent-rule queries
        for agent_id, events in self.agent_history.items():
            agent_node = f"agent_{agent_id}"
            if agent_node not in G:
                continue
            
            # Count rule queries
            rule_counts = Counter(e.matched_rule_id for e in events if e.matched_rule_id is not None)
            
            # Add edges for top rules
            for rule_id, count in rule_counts.most_common(10):
                rule_node = f"rule_{rule_id}"
                if rule_node in G:
                    G.add_edge(
                        agent_node,
                        rule_node,
                        type="queries",
                        count=count
                    )
        
        # Add edges for agents completing sensitive sets
        for agent_id, events in self.agent_history.items():
            agent_node = f"agent_{agent_id}"
            if agent_node not in G:
                continue
            
            # Get rules queried by this agent
            queried_rules = set(e.matched_rule_id for e in events if e.matched_rule_id is not None)
            
            # Check if agent has completed any sensitive sets
            for i, rule_set in enumerate(self.sensitive_rule_sets):
                set_node = f"sensitive_set_{i}"
                if set_node not in G:
                    continue
                
                # Calculate completion ratio
                intersection = queried_rules.intersection(rule_set)
                completion_ratio = len(intersection) / len(rule_set)
                
                # Add edge if significant completion
                if completion_ratio > 0.5:
                    G.add_edge(
                        agent_node,
                        set_node,
                        type="completes",
                        completion_ratio=completion_ratio,
                        completed=(completion_ratio == 1.0)
                    )
        
        return G
    
    def serialize_graph(self, G: nx.DiGraph, output_file: str):
        """
        Serialize graph to JSON file
        
        Args:
            G: NetworkX DiGraph
            output_file: Output file path
        """
        try:
            # Convert to serializable format
            graph_data = nx.node_link_data(G)
            
            # Save to file
            with open(output_file, 'w') as f:
                json.dump(graph_data, f, indent=2)
            
            logger.info(f"Saved anomaly graph to {output_file}")
        except Exception as e:
            logger.error(f"Error serializing graph: {e}")

# Example usage
if __name__ == "__main__":
    # Initialize detector
    detector = MosaicAnomalyDetection(
        rules_file_path="data.json",
        event_history_file="event_history.json"
    )
    
    # Create a test event
    test_event = QueryEvent(
        query_id="test-query-1",
        agent_id="agent-007",
        query_text="What is the status of Operation Void?",
        agent_level=3,
        timestamp=datetime.utcnow(),
        matched_rule_id=32,  # Operation Void (requires level 5)
        rule_required_level=5
    )
    
    # Detect anomalies
    result = detector.detect_anomalies_for_event(test_event)
    
    # Print result
    print(f"Anomaly Detected: {result.is_anomalous}")
    print(f"Anomaly Score: {result.anomaly_score}")
    print(f"Anomaly Types: {result.anomaly_types}")
    print(f"Details: {json.dumps(result.details, indent=2)}")
    
    # Generate risk profile
    profile = detector.get_agent_risk_profile("agent-007")
    print(f"\nRisk Profile: {profile['risk_level']} (Score: {profile['risk_score']})")
    
    # Generate system assessment
    assessment = detector.get_system_risk_assessment()
    print(f"\nSystem Risk Level: {assessment['risk_level']}")
    
    # Generate and save anomaly graph
    graph = detector.generate_anomaly_graph()
    detector.serialize_graph(graph, "anomaly_graph.json")