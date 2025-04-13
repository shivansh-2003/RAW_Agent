#!/usr/bin/env python

"""
Test Data Generator for Project SHADOW Persistence Layer

This script generates test data for the persistence layer to help with
development and testing. It creates sample agents, rules, audit trails,
and neural signatures.

Usage:
  python test_data_generator.py [--data-dir DATA_DIR]

Options:
  --data-dir DATA_DIR  Directory to store the generated data files (default: data)
"""

import os
import json
import uuid
import random
import datetime
import argparse
from typing import Dict, List, Any

try:
    # Try importing from the package first
    from persistence.db_models import ClearanceLevel, AccessStatus
    from persistence.db_factory import DatabaseFactory
except ImportError:
    # If that fails, try importing assuming this script is run from the persistence directory
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from persistence.db_models import ClearanceLevel, AccessStatus
    from persistence.db_factory import DatabaseFactory


def generate_agent_id() -> str:
    """Generate a random agent ID"""
    prefix = random.choice(["A", "B", "C", "D", "E"])
    return f"{prefix}-{str(uuid.uuid4())[:8]}"


def generate_signature_id() -> str:
    """Generate a random neural signature ID"""
    return f"NS-{str(uuid.uuid4())[:8]}"


def generate_rule_id() -> str:
    """Generate a random rule ID"""
    return f"R-{str(uuid.uuid4())[:8]}"


def generate_test_agents(count: int = 10) -> List[Dict[str, Any]]:
    """Generate test agent data"""
    agent_names = [
        "Smith, John", "Johnson, Sarah", "Williams, Michael", "Brown, Emily",
        "Jones, David", "Miller, Jessica", "Davis, James", "Garcia, Maria",
        "Rodriguez, Carlos", "Wilson, Lisa", "Martinez, Jose", "Anderson, Thomas",
        "Taylor, Ashley", "Thomas, Daniel", "Hernandez, Sofia", "Moore, Ryan",
        "Martin, Jennifer", "Jackson, Brian", "Thompson, Nicole", "White, Kevin"
    ]
    
    specialties = [
        "Infiltration", "Cyber Security", "Explosives", "Surveillance",
        "Counter-Intelligence", "Data Analysis", "Field Operations", "Tactical",
        "Covert Ops", "Intelligence", "Communications", "Forensics",
        "Biometrics", "Chemical Analysis", "Linguistics", "Psychology"
    ]
    
    agents = []
    
    for i in range(count):
        # Pick random values
        agent_id = generate_agent_id()
        name = random.choice(agent_names)
        clearance_level = random.choice(list(ClearanceLevel))
        access_status = random.choice(list(AccessStatus))
        agent_specialties = random.sample(specialties, random.randint(1, 3))
        neural_signature_id = generate_signature_id()
        
        # Generate access history entries
        access_history = []
        for j in range(random.randint(0, 5)):
            timestamp = datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(0, 90))
            action = random.choice(["login", "logout", "clearance_update", "status_update"])
            performed_by = "SYSTEM" if random.random() < 0.7 else random.choice(["ADMIN", "SUPERVISOR", "DIRECTOR"])
            
            entry = {
                "timestamp": timestamp.isoformat(),
                "action": action,
                "details": {"note": f"Automated action {j+1}"},
                "performed_by": performed_by
            }
            access_history.append(entry)
        
        # Create agent dict
        agent = {
            "agent_id": agent_id,
            "name": name,
            "clearance_level": clearance_level.value,
            "neural_signature_id": neural_signature_id,
            "access_status": access_status.value,
            "specialties": agent_specialties,
            "access_history": access_history,
            "metadata": {
                "creation_note": "Generated for testing",
                "test_record": True
            },
            "created_at": (datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(10, 500))).isoformat(),
            "last_updated": datetime.datetime.utcnow().isoformat()
        }
        
        agents.append(agent)
    
    return agents


def generate_test_rules(count: int = 20) -> List[Dict[str, Any]]:
    """Generate test rule data"""
    descriptions = [
        "Access to Project Alpha files", "Access to Project Beta files",
        "Access to classified personnel records", "Access to financial records",
        "Access to operation logs", "Access to field agent locations",
        "Access to security systems", "Access to weapons inventory",
        "Access to intelligence database", "Access to mission briefings",
        "Modification of security protocols", "Modification of clearance levels",
        "Execution of remote commands", "System administration rights",
        "Network monitoring permissions", "Database administration rights"
    ]
    
    patterns = [
        "project_alpha_*", "project_beta_*", "personnel_record_*", "financial_*",
        "operation_log_*", "agent_location_*", "security_system_*", "weapons_*",
        "intelligence_*", "mission_*", "security_protocol_*", "clearance_*",
        "remote_command_*", "admin_*", "network_*", "database_*"
    ]
    
    rule_types = [
        "access_control", "modification_control", "execution_control",
        "view_control", "edit_control", "delete_control"
    ]
    
    rules = []
    
    for i in range(count):
        # Pick random values or pair matched values
        idx = random.randint(0, len(descriptions) - 1)
        rule_id = generate_rule_id()
        description = descriptions[random.randint(0, len(descriptions) - 1)]
        pattern = patterns[random.randint(0, len(patterns) - 1)]
        clearance_required = random.choice(list(ClearanceLevel))
        rule_type = random.choice(rule_types)
        
        # Create rule dict
        rule = {
            "rule_id": rule_id,
            "description": description,
            "pattern": pattern,
            "clearance_required": clearance_required.value,
            "rule_type": rule_type,
            "exceptions": [],
            "metadata": {
                "creation_note": "Generated for testing",
                "test_record": True
            },
            "created_at": (datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(1, 100))).isoformat(),
            "last_updated": datetime.datetime.utcnow().isoformat()
        }
        
        # 20% chance to add exceptions
        if random.random() < 0.2:
            rule["exceptions"] = [generate_agent_id() for _ in range(random.randint(1, 3))]
        
        rules.append(rule)
    
    return rules


def generate_test_audit_trail(agent_ids: List[str], count: int = 50) -> List[Dict[str, Any]]:
    """Generate test audit trail data"""
    action_types = [
        "login", "logout", "file_access", "database_query", "rule_modification",
        "agent_creation", "agent_modification", "clearance_update", "system_access",
        "report_generation", "data_export", "configuration_change"
    ]
    
    audit_entries = []
    
    for i in range(count):
        # Pick random values
        entry_id = str(uuid.uuid4())
        agent_id = random.choice(agent_ids) if agent_ids else generate_agent_id()
        action_type = random.choice(action_types)
        timestamp = datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(0, 30),
                                                                   hours=random.randint(0, 23),
                                                                   minutes=random.randint(0, 59))
        clearance_level = random.choice(list(ClearanceLevel))
        
        # Create simulated encrypted details (in a real system this would be encrypted)
        details = {
            "ip_address": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "session_id": f"S-{str(uuid.uuid4())[:8]}",
            "success": random.random() > 0.1,  # 90% success rate
            "duration_ms": random.randint(10, 5000)
        }
        
        # Add action-specific details
        if action_type == "file_access":
            details["file"] = f"project_{'alpha' if random.random() > 0.5 else 'beta'}_report_{random.randint(1, 100)}.pdf"
            details["operation"] = random.choice(["read", "write", "delete"])
        elif action_type == "database_query":
            details["query_type"] = random.choice(["select", "insert", "update", "delete"])
            details["table"] = random.choice(["agents", "rules", "operations", "missions"])
        
        # Create audit entry
        audit_entry = {
            "entry_id": entry_id,
            "agent_id": agent_id,
            "action_type": action_type,
            "timestamp": timestamp.isoformat(),
            "encrypted_details": json.dumps(details),  # In a real system, this would be encrypted
            "encryption_metadata": {
                "algorithm": "AES-256-GCM",
                "key_id": f"K-{random.randint(100, 999)}"
            },
            "clearance_level": clearance_level.value,
            "related_resources": []
        }
        
        # 30% chance to add related resources
        if random.random() < 0.3:
            audit_entry["related_resources"] = [
                f"{'R' if random.random() > 0.5 else 'A'}-{str(uuid.uuid4())[:8]}"
                for _ in range(random.randint(1, 3))
            ]
        
        audit_entries.append(audit_entry)
    
    # Sort by timestamp
    audit_entries.sort(key=lambda x: x["timestamp"])
    
    return audit_entries


def generate_test_neural_signatures(agent_ids: List[str]) -> List[Dict[str, Any]]:
    """Generate test neural signature data"""
    signatures = []
    
    for agent_id in agent_ids:
        # Create a unique signature ID
        signature_id = generate_signature_id()
        
        # Generate random neural pattern (simplified)
        pattern_length = random.randint(50, 200)
        neural_pattern = [random.random() for _ in range(pattern_length)]
        
        # Random verification threshold
        verification_threshold = round(random.uniform(0.75, 0.95), 2)
        
        # Random version string
        version = f"{random.randint(1, 3)}.{random.randint(0, 9)}"
        
        # Create creation timestamp
        created_at = datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(10, 500))
        
        # Maybe add last verification
        last_verified = None
        if random.random() > 0.3:  # 70% chance to have been verified
            last_verified = datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(0, 30))
        
        # Generate verification stats
        success_count = random.randint(5, 100)
        failure_count = random.randint(0, 5)
        
        # Create signature dict
        signature = {
            "signature_id": signature_id,
            "agent_id": agent_id,
            "signature_data": {
                "neural_pattern": neural_pattern,
                "feature_importance": [random.random() for _ in range(10)],
                "metadata": {
                    "algorithm": "Neural-Hash-v2",
                    "scan_quality": random.choice(["high", "medium", "low"]),
                    "scan_date": created_at.isoformat()
                }
            },
            "verification_threshold": verification_threshold,
            "signature_version": version,
            "created_at": created_at.isoformat(),
            "verification_stats": {
                "success_count": success_count,
                "failure_count": failure_count
            }
        }
        
        if last_verified:
            signature["last_verified"] = last_verified.isoformat()
            
            # Add verification history
            signature["verification_stats"]["verification_history"] = []
            history_count = random.randint(5, 20)
            
            for i in range(history_count):
                # Create a verification event
                hist_time = datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(0, 30))
                success = random.random() > 0.1  # 90% success rate
                score = round(random.uniform(0.7, 1.0), 2)
                
                event = {
                    "timestamp": hist_time.isoformat(),
                    "success": success,
                    "score": score,
                    "data": {
                        "match_points": random.randint(5, 20),
                        "duration_ms": random.randint(100, 500)
                    }
                }
                
                signature["verification_stats"]["verification_history"].append(event)
        
        signatures.append(signature)
    
    return signatures


def save_to_json_file(data: Dict[str, Any], filepath: str) -> None:
    """Save data to a JSON file"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Saved data to {filepath}")


def main():
    """Main function to generate test data"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Generate test data for the Project SHADOW persistence layer")
    parser.add_argument('--data-dir', type=str, default='data', help='Directory to store the generated data files')
    args = parser.parse_args()
    
    # Ensure data directory exists
    os.makedirs(args.data_dir, exist_ok=True)
    
    # Generate agent data
    agents = generate_test_agents(10)
    agent_data = {
        "metadata": {
            "created_at": datetime.datetime.utcnow().isoformat(),
            "description": "Test agent data for Project SHADOW"
        },
        "items": {agent["agent_id"]: agent for agent in agents}
    }
    save_to_json_file(agent_data, os.path.join(args.data_dir, "agents.json"))
    
    # Extract agent IDs for use in other data generation
    agent_ids = [agent["agent_id"] for agent in agents]
    
    # Generate rule data
    rules = generate_test_rules(20)
    rule_data = {
        "metadata": {
            "created_at": datetime.datetime.utcnow().isoformat(),
            "description": "Test rule data for Project SHADOW"
        },
        "items": {rule["rule_id"]: rule for rule in rules}
    }
    save_to_json_file(rule_data, os.path.join(args.data_dir, "rules.json"))
    
    # Generate audit trail data
    audit_entries = generate_test_audit_trail(agent_ids, 50)
    audit_data = {
        "metadata": {
            "created_at": datetime.datetime.utcnow().isoformat(),
            "description": "Test audit trail data for Project SHADOW"
        },
        "items": {entry["entry_id"]: entry for entry in audit_entries}
    }
    save_to_json_file(audit_data, os.path.join(args.data_dir, "audit_trail.json"))
    
    # Generate neural signature data
    signatures = generate_test_neural_signatures(agent_ids)
    signature_data = {
        "metadata": {
            "created_at": datetime.datetime.utcnow().isoformat(),
            "description": "Test neural signature data for Project SHADOW"
        },
        "items": {sig["signature_id"]: sig for sig in signatures}
    }
    save_to_json_file(signature_data, os.path.join(args.data_dir, "neural_signatures.json"))
    
    print("Test data generation complete.")
    print(f"Generated {len(agents)} agents, {len(rules)} rules, {len(audit_entries)} audit entries, and {len(signatures)} neural signatures.")


if __name__ == "__main__":
    main() 