# response_formatter.py

import os
import json
import time
import logging
import random
import asyncio
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime

# Try to import LLM libraries for advanced response formatting
try:
    import httpx
    from langchain_anthropic import ChatAnthropic
    from langchain.prompts import PromptTemplate
    from langchain.chains import LLMChain
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("response_formatter.log")
    ]
)
logger = logging.getLogger("shadow_response_formatter")

class ResponseFormatter:
    """
    Response Content Formatter for Project SHADOW
    
    This component formats responses based on rule instructions and agent
    clearance levels according to the RAG CASE RESPONSE FRAMEWORK.
    """
    
    def __init__(self, rules_file_path: str, use_llm: bool = False):
        """
        Initialize the Response Formatter
        
        Args:
            rules_file_path: Path to the rules JSON file
            use_llm: Whether to use LLM for advanced formatting
        """
        self.rules_file_path = rules_file_path
        self.use_llm = use_llm and LLM_AVAILABLE
        
        # Load rules
        self.rules = self._load_rules()
        
        # Initialize LLM components if requested and available
        if self.use_llm:
            self._init_llm()
        else:
            self.llm = None
            self.llm_chain = None
        
        # Initialize template patterns for different agent levels
        self._init_templates()
        
        logger.info(f"Response Formatter initialized with {len(self.rules)} rules")
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load rules from JSON file"""
        try:
            with open(self.rules_file_path, 'r') as f:
                data = json.load(f)
                return data.get('rules', [])
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            return []
    
    def _init_llm(self):
        """Initialize LangChain components with Anthropic or other LLM"""
        if not LLM_AVAILABLE:
            logger.warning("LangChain or Anthropic libraries not available")
            self.llm = None
            self.llm_chain = None
            return
        
        try:
            # Initialize Anthropic model
            anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
            if not anthropic_api_key:
                logger.warning("No ANTHROPIC_API_KEY found in environment variables")
                self.llm = None
                self.llm_chain = None
                return
            
            self.llm = ChatAnthropic(api_key=anthropic_api_key)
            
            # Define prompt template for response formatting
            prompt_template = """
            You are formatting responses for a secure intelligence system called Project SHADOW.
            
            Agent Clearance Level: {agent_level}
            Query: {query}
            Rule Instruction: {rule_instruction}
            
            Format the response according to the agent's clearance level:
            - Level 1 agents receive basic, instructional responses with clear explanations
            - Level 2 agents receive tactical, direct responses focused on efficiency
            - Level 3 agents receive analytical, multi-layered responses with strategic insights
            - Level 4 agents receive coded language with essential confirmations only
            - Level 5 agents receive vague, layered responses, sometimes as counter-questions
            
            Follow the rule instruction precisely while adapting to the appropriate style for the agent's level.
            Your response should be concise and focused on answering the query in the specified style.
            
            Response:
            """
            
            prompt = PromptTemplate(
                input_variables=["agent_level", "query", "rule_instruction"],
                template=prompt_template
            )
            
            self.llm_chain = LLMChain(llm=self.llm, prompt=prompt)
            logger.info("LLM integration initialized successfully")
        
        except Exception as e:
            logger.error(f"Error initializing LLM: {e}")
            self.llm = None
            self.llm_chain = None
    
    def _init_templates(self):
        """Initialize template patterns for different agent levels"""
        # Level 1 - Novice Operative (Shadow Footprint)
        # Basic and instructional, like a mentor guiding a trainee
        self.level1_templates = [
            "Here's a step-by-step guide for {topic}:\n{steps}",
            "Let me explain {topic} in detail:\n{explanation}",
            "For {topic}, follow these instructions:\n{instructions}",
            "The protocol for {topic} involves several key steps:\n{steps}",
            "Understanding {topic} requires knowledge of:\n{details}"
        ]
        
        # Level 2 - Tactical Specialist (Iron Claw)
        # Tactical and direct, focusing on execution and efficiency
        self.level2_templates = [
            "Tactical approach for {topic}:\n{approach}",
            "{topic} execution: {details}",
            "Direct implementation for {topic}:\n{implementation}",
            "Efficient method for {topic}: {method}",
            "{topic} protocol: {protocol}"
        ]
        
        # Level 3 - Covert Strategist (Phantom Mind)
        # Analytical and multi-layered, providing strategic insights
        self.level3_templates = [
            "Strategic analysis of {topic}:\n{analysis}",
            "{topic} presents multiple vectors:\n{vectors}",
            "Analyzing {topic} reveals:\n{revelations}",
            "Consider these perspectives on {topic}:\n{perspectives}",
            "Contextual assessment of {topic}:\n{assessment}"
        ]
        
        # Level 4 - Field Commander (Omega Hawk)
        # Coded language, hints, and only essential confirmations
        self.level4_templates = [
            "The path through {topic} lies hidden.",
            "{topic} reveals itself only to those who know where to look.",
            "What seems obvious about {topic} rarely is.",
            "Between the lines of {topic}, truth waits.",
            "Not all aspects of {topic} are meant to be seen."
        ]
        
        # Level 5 - Intelligence Overlord (Silent Whisper)
        # Vague, layered, sometimes answering with counter-questions
        self.level5_templates = [
            "Have you considered what {topic} truly means?",
            "The question about {topic} contains its own answer.",
            "{topic} is merely the surface of deeper waters.",
            "Those who understand {topic} rarely speak of it directly.",
            "What does {topic} mean to you? That's the real question."
        ]
    
    def get_rule_by_id(self, rule_id: int) -> Optional[Dict[str, Any]]:
        """Get a rule by ID"""
        return next((rule for rule in self.rules if rule["id"] == rule_id), None)
    
    def is_healthy(self) -> bool:
        """Check if the formatter is in a healthy state"""
        return len(self.rules) > 0
    
    def format_template_response(self, rule: Dict[str, Any], agent_level: int, query_text: str) -> str:
        """
        Format a response using templates based on agent level
        
        Args:
            rule: The rule to format response for
            agent_level: The agent's clearance level
            query_text: The original query text
            
        Returns:
            Formatted response text
        """
        # Get rule instruction
        instruction = rule.get("response_instruction", "")
        
        # Extract topic from query or use a fallback
        topic = query_text.strip().lower()
        for phrase in rule.get("trigger_phrases", []):
            if phrase.lower() in topic:
                topic = phrase
                break
        
        # Select template based on agent level
        templates = getattr(self, f"level{agent_level}_templates", self.level1_templates)
        template = random.choice(templates)
        
        # Create response content based on instruction
        if "step-by-step" in instruction.lower():
            steps = self._generate_steps(instruction, agent_level)
            response = template.format(topic=topic, steps=steps)
        elif "multiple" in instruction.lower() and "techniques" in instruction.lower():
            techniques = self._generate_techniques(instruction, agent_level)
            response = template.format(
                topic=topic, 
                vectors=techniques,
                analysis=techniques,
                details=techniques,
                explanation=techniques
            )
        elif "historical" in instruction.lower() or "case studies" in instruction.lower():
            case_studies = self._generate_case_studies(instruction, agent_level)
            response = template.format(
                topic=topic,
                details=case_studies,
                analysis=case_studies,
                perspectives=case_studies,
                explanation=case_studies
            )
        elif "direct" in instruction.lower() or "tactical" in instruction.lower():
            tactical = self._generate_tactical(instruction, agent_level)
            response = template.format(
                topic=topic,
                approach=tactical,
                details=tactical,
                implementation=tactical,
                method=tactical,
                protocol=tactical
            )
        else:
            # Generic response based on instruction
            generic = self._generate_generic(instruction, agent_level)
            response = template.format(
                topic=topic,
                explanation=generic,
                details=generic,
                approach=generic,
                analysis=generic,
                assessment=generic,
                method=generic,
                protocol=generic,
                implementation=generic
            )
        
        return response
    
    def _generate_steps(self, instruction: str, agent_level: int) -> str:
        """Generate step-by-step instructions"""
        # For Level 1, provide detailed steps
        if agent_level == 1:
            return "1. Initiate protocol with proper authorization\n2. Verify all security parameters\n3. Execute primary phase with caution\n4. Monitor for unexpected variables\n5. Complete operation with verification"
        # For Level 2, more tactical steps
        elif agent_level == 2:
            return "1. Secure perimeter\n2. Establish comm channel\n3. Execute primary action\n4. Verify outcome\n5. Withdraw systematically"
        # For Level 3, strategic steps
        elif agent_level == 3:
            return "1. Assess full operational context\n2. Engage primary and secondary protocols\n3. Adapt to emergent variables\n4. Maintain strategic positioning\n5. Conclude with minimal trace"
        # For Level 4, coded and minimal
        elif agent_level == 4:
            return "Sequence: Alpha, Delta, Mirror, Silence, Horizon."
        # For Level 5, cryptic
        else:
            return "The beginning is the end. The path reveals itself when you've already walked it."
    
    def _generate_techniques(self, instruction: str, agent_level: int) -> str:
        """Generate multiple techniques or approaches"""
        # For Level 1, clear techniques
        if agent_level == 1:
            return "Technique A: Direct approach with full visibility\nTechnique B: Indirect method with higher security\nTechnique C: Hybrid approach balancing efficiency and safety"
        # For Level 2, tactical techniques
        elif agent_level == 2:
            return "Approach 1: Rapid execution, higher exposure risk\nApproach 2: Slower execution, minimal exposure\nApproach 3: Staged execution with fallback options"
        # For Level 3, strategic techniques
        elif agent_level == 3:
            return "Vector Alpha: Information-based approach - lower risk, extended timeframe\nVector Beta: Direct intervention - higher risk, immediate results\nVector Gamma: Influence operation - moderate risk, delayed confirmation"
        # For Level 4, coded and minimal
        elif agent_level == 4:
            return "Echo pattern for minimal trace. Shadow method when observed. Mirror protocol when compromised."
        # For Level 5, cryptic
        else:
            return "Some paths disappear when observed directly. Others exist only when approached indirectly. The most valuable path is the one never taken."
    
    def _generate_case_studies(self, instruction: str, agent_level: int) -> str:
        """Generate historical case studies or examples"""
        # For Level 1, clear examples
        if agent_level == 1:
            return "Case 1 (2018): Successful implementation with standard protocol\nCase 2 (2020): Adaptation required due to unforeseen variables\nCase 3 (2022): Failed attempt highlighting importance of preparation"
        # For Level 2, tactical examples
        elif agent_level == 2:
            return "Berlin Incident (2017): Successful extraction using diversion tactics\nMilan Operation (2019): Tactical repositioning resulted in mission success\nCairo Scenario (2021): Asset security breach required protocol adaptation"
        # For Level 3, strategic examples
        elif agent_level == 3:
            return "Operation Blue Summit (2016): Multi-phase intelligence gathering revealed critical infrastructure vulnerabilities\nProject Whisper Lane (2018): Long-term strategic positioning enabled critical intelligence acquisition\nInitiative Dark Water (2020): Failure analysis showed strategic timing miscalculation"
        # For Level 4, coded and minimal
        elif agent_level == 4:
            return "Redacted operation in Southeast Asia (2018): Pattern match with current situation (63%). Vienna anomaly (2020): Similar parameters, unexpected resolution. Montevideo contingency: Relevant protocol adaptation." 