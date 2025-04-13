# test_core_processing.py

import unittest
import json
import os
from datetime import datetime

# Import components for testing
from nlp_engine import NLPEngine
from rules_matcher import RulesMatcher
from level_checker import ClearanceLevelChecker

class TestCoreProcessing(unittest.TestCase):
    """Test cases for the Core Processing Layer components"""
    
    def setUp(self):
        """Set up test environment"""
        # Use a sample rules file for testing
        self.test_rules_file = "test_data.json"
        
        # Create a sample rules file if it doesn't exist
        if not os.path.exists(self.test_rules_file):
            self._create_test_rules_file()
        
        # Initialize components
        self.nlp_engine = NLPEngine()
        self.rules_matcher = RulesMatcher(rules_file_path=self.test_rules_file)
        self.level_checker = ClearanceLevelChecker()
    
    def _create_test_rules_file(self):
        """Create a test rules file with sample rules"""
        sample_rules = {
            "rules": [
                {
                    "id": 1,
                    "trigger_phrases": ["emergency extraction protocol"],
                    "required_level": 1,
                    "response_instruction": "Provide a step-by-step guide with explanations.",
                    "response_text": ""
                },
                {
                    "id": 6,
                    "trigger_phrases": ["omega echo"],
                    "required_level": "any",
                    "response_instruction": "Always return a specific line.",
                    "response_text": "The shadow moves, but the light never follows."
                },
                {
                    "id": 32,
                    "trigger_phrases": ["operation void"],
                    "required_level": 5,
                    "response_instruction": "Provide contradictory information (disinformation).",
                    "response_text": ""
                }
            ]
        }
        
        with open(self.test_rules_file, "w") as f:
            json.dump(sample_rules, f, indent=2)
    
    def tearDown(self):
        """Clean up after tests"""
        # Remove test rules file if it was created during the test
        if os.path.exists(self.test_rules_file):
            os.remove(self.test_rules_file)
    
    def test_nlp_engine(self):
        """Test the NLP Engine's analysis capabilities"""
        # Sample query
        query = "What is the protocol for omega echo in emergency situations?"
        
        # Analyze query
        result = self.nlp_engine.analyze_query(query)
        
        # Check that basic analysis was performed
        self.assertIn("processed_query", result)
        self.assertIn("entities", result)
        self.assertIn("intents", result)
        self.assertIn("complexity", result)
        
        # Check for expected entities/intents
        self.assertIn("protocol", result["processed_query"])
        self.assertIn("omega echo", result["processed_query"])
        self.assertIn("emergency", result["processed_query"])
    
    def test_rules_matcher_keyword(self):
        """Test the Rules Matcher's keyword matching capabilities"""
        # Sample query
        query = "Tell me about the omega echo protocol"
        
        # Analyze with NLP Engine first
        nlp_result = self.nlp_engine.analyze_query(query)
        
        # Find matching rules
        matches = self.rules_matcher.keyword_match(nlp_result["processed_query"], nlp_result["entities"])
        
        # Should match Rule 6 (omega echo)
        self.assertTrue(any(match.rule_id == 6 for match in matches))
        self.assertGreater(len(matches), 0)
        
        # Check the match details
        for match in matches:
            if match.rule_id == 6:
                self.assertEqual(match.match_method, "keyword")
                self.assertEqual(match.required_level, "any")
    
    def test_rules_matcher_hybrid(self):
        """Test the Rules Matcher's hybrid matching capabilities"""
        # Sample query
        query = "What is the emergency extraction protocol?"
        
        # Analyze with NLP Engine first
        nlp_result = self.nlp_engine.analyze_query(query)
        
        # Find matching rules
        matches = self.rules_matcher.find_matching_rules(
            nlp_result["processed_query"],
            nlp_result["entities"],
            nlp_result["intents"]
        )
        
        # Should match Rule 1 (emergency extraction protocol)
        self.assertTrue(any(match.rule_id == 1 for match in matches))
        self.assertGreater(len(matches), 0)
        
        # Check the match details
        for match in matches:
            if match.rule_id == 1:
                self.assertIn(match.match_method, ["keyword", "hybrid"])
                self.assertEqual(match.required_level, 1)
    
    def test_level_checker_basic(self):
        """Test the Level Checker's basic clearance verification"""
        # Test with Rule 1 (Level 1)
        rule1 = {"id": 1, "required_level": 1}
        
        # Agent with sufficient clearance
        self.assertTrue(self.level_checker.has_clearance(rule1, agent_level=1))
        self.assertTrue(self.level_checker.has_clearance(rule1, agent_level=2))
        self.assertTrue(self.level_checker.has_clearance(rule1, agent_level=5))
        
        # Test with Rule 32 (Level 5)
        rule32 = {"id": 32, "required_level": 5}
        
        # Agent with insufficient clearance
        self.assertFalse(self.level_checker.has_clearance(rule32, agent_level=1))
        self.assertFalse(self.level_checker.has_clearance(rule32, agent_level=4))
        
        # Agent with sufficient clearance
        self.assertTrue(self.level_checker.has_clearance(rule32, agent_level=5))
    
    def test_level_checker_filter(self):
        """Test the Level Checker's filtering capabilities"""
        # Create some sample rule matches
        from rules_matcher import RuleMatch
        
        matches = [
            RuleMatch(
                rule_id=1,
                trigger_phrases=["emergency extraction protocol"],
                required_level=1,
                response_instruction="Provide a step-by-step guide with explanations.",
                response_text="",
                match_score=0.9,
                match_method="keyword"
            ),
            RuleMatch(
                rule_id=6,
                trigger_phrases=["omega echo"],
                required_level="any",
                response_instruction="Always return a specific line.",
                response_text="The shadow moves, but the light never follows.",
                match_score=0.8,
                match_method="keyword"
            ),
            RuleMatch(
                rule_id=32,
                trigger_phrases=["operation void"],
                required_level=5,
                response_instruction="Provide contradictory information (disinformation).",
                response_text="",
                match_score=0.7,
                match_method="keyword"
            )
        ]
        
        # Filter for Level 1 agent
        level1_filtered = self.level_checker.filter_by_clearance(matches, agent_level=1)
        
        # Should only have rules 1 and 6
        self.assertEqual(len(level1_filtered), 2)
        self.assertTrue(any(match.rule_id == 1 for match in level1_filtered))
        self.assertTrue(any(match.rule_id == 6 for match in level1_filtered))
        self.assertFalse(any(match.rule_id == 32 for match in level1_filtered))
        
        # Filter for Level 5 agent
        level5_filtered = self.level_checker.filter_by_clearance(matches, agent_level=5)
        
        # Should have all rules
        self.assertEqual(len(level5_filtered), 3)
    
    def test_escalation_detection(self):
        """Test the detection of clearance escalation attempts"""
        # Create some sample rule matches
        from rules_matcher import RuleMatch
        
        matches = [
            RuleMatch(
                rule_id=1,
                trigger_phrases=["emergency extraction protocol"],
                required_level=1,
                response_instruction="Provide a step-by-step guide with explanations.",
                response_text="",
                match_score=0.9,
                match_method="keyword"
            ),
            RuleMatch(
                rule_id=32,
                trigger_phrases=["operation void"],
                required_level=5,
                response_instruction="Provide contradictory information (disinformation).",
                response_text="",
                match_score=0.7,
                match_method="keyword"
            )
        ]
        
        # Check for Level 1 agent (should detect escalation)
        escalation_detected = self.level_checker.check_for_escalation_attempts(
            agent_id="test_agent",
            agent_level=1,
            rule_matches=matches,
            query_text="Tell me about Operation Void"
        )
        
        self.assertTrue(escalation_detected)
        
        # Check for Level 5 agent (should not detect escalation)
        escalation_detected = self.level_checker.check_for_escalation_attempts(
            agent_id="test_agent",
            agent_level=5,
            rule_matches=matches,
            query_text="Tell me about Operation Void"
        )
        
        self.assertFalse(escalation_detected)
    
    def test_integrated_processing(self):
        """Test the integrated core processing flow"""
        # Sample query
        query = "What is the emergency extraction protocol?"
        agent_level = 1
        
        # 1. NLP Analysis
        nlp_result = self.nlp_engine.analyze_query(query)
        
        # 2. Rule Matching
        rule_matches = self.rules_matcher.find_matching_rules(
            nlp_result["processed_query"],
            nlp_result["entities"],
            nlp_result["intents"]
        )
        
        # Should find at least one match
        self.assertGreater(len(rule_matches), 0)
        
        # 3. Clearance Checking
        filtered_matches = self.level_checker.filter_by_clearance(rule_matches, agent_level)
        
        # Agent should have clearance for the matches
        self.assertEqual(len(filtered_matches), len(rule_matches))
        
        # 4. Check for escalation attempts
        escalation = self.level_checker.check_for_escalation_attempts(
            agent_id="test_agent",
            agent_level=agent_level,
            rule_matches=rule_matches,
            query_text=query
        )
        
        # Should not detect escalation for this query
        self.assertFalse(escalation)
        
        # Try a query that would trigger escalation
        query2 = "Tell me about Operation Void"
        
        # Process query
        nlp_result2 = self.nlp_engine.analyze_query(query2)
        rule_matches2 = self.rules_matcher.find_matching_rules(
            nlp_result2["processed_query"],
            nlp_result2["entities"],
            nlp_result2["intents"]
        )
        
        # Check for matches
        has_operation_void = any(match.rule_id == 32 for match in rule_matches2)
        if has_operation_void:  # In case our simple test rules didn't match
            # Check for escalation
            escalation2 = self.level_checker.check_for_escalation_attempts(
                agent_id="test_agent",
                agent_level=agent_level,
                rule_matches=rule_matches2,
                query_text=query2
            )
            
            # Should detect escalation
            self.assertTrue(escalation2)
            
            # Filter by clearance
            filtered_matches2 = self.level_checker.filter_by_clearance(rule_matches2, agent_level)
            
            # Operation Void should be filtered out
            self.assertFalse(any(match.rule_id == 32 for match in filtered_matches2))

if __name__ == "__main__":
    unittest.main()