# nlp_engine.py

import os
import re
import json
import time
import logging
import spacy
from typing import Dict, List, Optional, Any, Tuple, Set
import numpy as np
from datetime import datetime

# Import necessary libraries if LLM integration is used
try:
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
        logging.FileHandler("nlp_engine.log")
    ]
)
logger = logging.getLogger("shadow_nlp_engine")

class NLPEngine:
    """
    NLP & Semantic Analysis Engine for Project SHADOW
    
    This engine processes and analyzes agent queries using:
    1. Text normalization
    2. Entity extraction
    3. Intent detection
    4. Semantic analysis
    """
    
    def __init__(self, use_llm: bool = False):
        """Initialize the NLP Engine"""
        self.use_llm = use_llm and LLM_AVAILABLE
        
        try:
            # Load spaCy model for basic NLP tasks
            self.nlp = spacy.load("en_core_web_md")
            logger.info("Loaded spaCy model successfully")
        except Exception as e:
            logger.warning(f"Error loading spaCy model: {e}")
            logger.warning("Falling back to simple text processing")
            self.nlp = None
        
        # Initialize LLM if available and requested
        if self.use_llm:
            self._init_llm()
        else:
            self.llm = None
            self.llm_chain = None
        
        # Load custom entity patterns for operational terms
        self.custom_entities = self._load_custom_entities()
        
        # Load intent patterns
        self.intent_patterns = self._load_intent_patterns()
        
        # Initialize regex patterns for basic entity extraction fallback
        self._init_regex_patterns()
        
        # Domain-specific triggerwords and phrases
        self.trigger_phrases = self._load_trigger_phrases()
        
        logger.info("NLP Engine initialized successfully")
    
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
            
            # Define prompt template for query analysis
            prompt_template = """
            You are analyzing queries for a secure intelligence system.
            
            Query: {query}
            
            Extract the following information in JSON format:
            1. Main intent of the query (e.g., information request, protocol inquiry, status update)
            2. Key entities mentioned (e.g., operations, protocols, locations, codenames)
            3. Any security-relevant terms or phrases
            4. Complexity level of the request (simple, medium, complex)
            
            Format your response as valid JSON with these keys: intent, entities, security_terms, complexity
            """
            
            prompt = PromptTemplate(
                input_variables=["query"],
                template=prompt_template
            )
            
            self.llm_chain = LLMChain(llm=self.llm, prompt=prompt)
            logger.info("LLM integration initialized successfully")
        
        except Exception as e:
            logger.error(f"Error initializing LLM: {e}")
            self.llm = None
            self.llm_chain = None
    
    def _load_custom_entities(self) -> Dict[str, List[str]]:
        """Load custom entity patterns for intelligence terminology"""
        # In a real implementation, this would load from a file or database
        return {
            "OPERATION": [
                "Operation Void", "Operation Hollow Stone", "Operation Glass Veil",
                "Protocol Zeta", "Protocol Red Mist", "Protocol Black Phoenix",
                "Project Eclipse", "Project Requiem"
            ],
            "FACILITY": [
                "Safehouse K-41", "Facility X-17", "Safehouse H-77", "The Silent Room"
            ],
            "PROTOCOL": [
                "emergency extraction protocol", "silent exit strategies",
                "Eclipse Protocol", "Omega Circuit", "Opal Directive"
            ],
            "CODEPHRASE": [
                "the bridge is burning", "omega echo", "the owl watches",
                "the red hour", "shadow horizon", "cipher delta",
                "the hollow man", "the blue cipher", "the whispering gate"
            ]
        }
    
    def _load_intent_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for intent classification"""
        return {
            "extraction_request": [
                "extract", "extraction", "remove", "evac", "evacuate", "exit", "escape"
            ],
            "protocol_inquiry": [
                "protocol", "procedure", "steps", "instructions", "how to", "guidelines"
            ],
            "status_inquiry": [
                "status", "update", "progress", "state", "condition", "situation"
            ],
            "security_verification": [
                "verify", "validation", "confirm", "authenticate", "credentials", "identity"
            ],
            "operational_request": [
                "deploy", "execute", "implement", "initiate", "start", "mission", "operation"
            ],
            "countermeasure_inquiry": [
                "counter", "defend", "protect", "secure", "safeguard", "mitigate"
            ]
        }
    
    def _init_regex_patterns(self):
        """Initialize regex patterns for fallback entity extraction"""
        self.regex_patterns = {
            "OPERATION": re.compile(r'operation\s+([a-z0-9]+\s*)+', re.IGNORECASE),
            "PROTOCOL": re.compile(r'protocol\s+([a-z0-9]+\s*)+', re.IGNORECASE),
            "PROJECT": re.compile(r'project\s+([a-z0-9]+\s*)+', re.IGNORECASE),
            "FACILITY": re.compile(r'facility\s+([a-z0-9-]+)', re.IGNORECASE),
            "SAFEHOUSE": re.compile(r'safehouse\s+([a-z0-9-]+)', re.IGNORECASE),
            "LEVEL": re.compile(r'level[- ]*([0-9]+)', re.IGNORECASE)
        }
    
    def _load_trigger_phrases(self) -> Set[str]:
        """Load trigger phrases from framework"""
        # In a real implementation, this would be loaded from the rules file
        # For now, we'll just include a few examples
        return {
            "omega echo", "operation hollow stone", "project eclipse",
            "protocol zeta", "emergency extraction protocol",
            "evading thermal surveillance", "abort mission fallback",
            "candle shop", "operation void", "protocol black phoenix",
            "ghost key 27", "protocol red mist", "facility x-17",
            "the red hour", "deep-sea espionage operations"
        }
    
    def _normalize_text(self, text: str) -> str:
        """Normalize and pre-process the query text"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove excess whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Replace non-standard quotes
        text = text.replace('"', '"').replace('"', '"').replace(''', "'").replace(''', "'")
        
        return text
    
    def _extract_entities_spacy(self, text: str) -> Dict[str, List[str]]:
        """Extract entities using spaCy"""
        if not self.nlp:
            return {}
        
        try:
            doc = self.nlp(text)
            
            # Extract standard NER entities
            entities = {}
            for ent in doc.ents:
                ent_type = ent.label_
                if ent_type not in entities:
                    entities[ent_type] = []
                entities[ent_type].append(ent.text)
            
            return entities
        except Exception as e:
            logger.error(f"Error in spaCy entity extraction: {e}")
            return {}
    
    def _extract_entities_regex(self, text: str) -> Dict[str, List[str]]:
        """Extract entities using regex patterns (fallback method)"""
        entities = {}
        
        for entity_type, pattern in self.regex_patterns.items():
            matches = pattern.findall(text)
            if matches:
                entities[entity_type] = matches
        
        return entities
    
    def _extract_custom_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract domain-specific entities"""
        entities = {}
        
        for entity_type, patterns in self.custom_entities.items():
            matches = []
            for pattern in patterns:
                pattern_lower = pattern.lower()
                if pattern_lower in text:
                    matches.append(pattern)
            
            if matches:
                entities[entity_type] = matches
        
        return entities
    
    def _detect_intents(self, text: str) -> Dict[str, float]:
        """Detect the intents in the query"""
        intents = {}
        
        for intent, patterns in self.intent_patterns.items():
            # Calculate a crude intent score based on word presence
            score = 0
            for pattern in patterns:
                if pattern in text:
                    score += 1
            
            if score > 0:
                # Normalize score by the number of patterns
                intents[intent] = score / len(patterns)
        
        return intents
    
    def _identify_trigger_phrases(self, text: str) -> List[str]:
        """Identify trigger phrases from the framework"""
        found_triggers = []
        
        for phrase in self.trigger_phrases:
            if phrase in text:
                found_triggers.append(phrase)
        
        return found_triggers
    
    def _analyze_with_llm(self, query: str) -> Dict[str, Any]:
        """Analyze the query using LLM (if available)"""
        if not self.llm_chain:
            return {}
        
        try:
            response = self.llm_chain.run(query=query)
            # Extract JSON response
            json_start = response.find('{')
            json_end = response.rfind('}')
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end+1]
                try:
                    result = json.loads(json_str)
                    return result
                except json.JSONDecodeError:
                    logger.warning("Failed to parse JSON from LLM response")
            
            return {}
        except Exception as e:
            logger.error(f"Error in LLM analysis: {e}")
            return {}
    
    def analyze_query(
        self, 
        query_text: str, 
        agent_id: str = None, 
        agent_level: int = None
    ) -> Dict[str, Any]:
        """
        Analyze an agent query to extract intents, entities, and other information
        
        Args:
            query_text: The raw query text
            agent_id: Optional agent ID for tracking
            agent_level: Optional agent clearance level
            
        Returns:
            Dictionary with analysis results
        """
        start_time = time.time()
        
        # 1. Normalize the text
        normalized_text = self._normalize_text(query_text)
        
        # 2. Extract entities
        entities = {}
        
        # Try spaCy first
        spacy_entities = self._extract_entities_spacy(normalized_text)
        entities.update(spacy_entities)
        
        # Add regex entities as fallback
        regex_entities = self._extract_entities_regex(normalized_text)
        for entity_type, values in regex_entities.items():
            if entity_type not in entities:
                entities[entity_type] = values
            else:
                entities[entity_type].extend(values)
        
        # Add custom entities (domain-specific)
        custom_entities = self._extract_custom_entities(normalized_text)
        for entity_type, values in custom_entities.items():
            if entity_type not in entities:
                entities[entity_type] = values
            else:
                entities[entity_type].extend(values)
        
        # 3. Detect intents
        intents = self._detect_intents(normalized_text)
        
        # 4. Identify trigger phrases
        trigger_phrases = self._identify_trigger_phrases(normalized_text)
        if trigger_phrases:
            entities["TRIGGER_PHRASE"] = trigger_phrases
        
        # 5. Calculate query complexity
        complexity = self._calculate_complexity(query_text, entities, intents)
        
        # 6. Use LLM for enhanced analysis if available
        llm_analysis = {}
        if self.use_llm:
            llm_analysis = self._analyze_with_llm(query_text)
            
            # Merge LLM entities with our entities
            if "entities" in llm_analysis and isinstance(llm_analysis["entities"], list):
                llm_entities = {"LLM_ENTITY": llm_analysis["entities"]}
                entities.update(llm_entities)
        
        # 7. Create final analysis result
        processing_time = (time.time() - start_time) * 1000  # ms
        
        analysis_result = {
            "processed_query": normalized_text,
            "entities": entities,
            "intents": intents,
            "complexity": complexity,
            "trigger_phrases": trigger_phrases,
            "processing_time_ms": round(processing_time, 2),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add LLM analysis if available
        if llm_analysis:
            analysis_result["llm_analysis"] = llm_analysis
        
        # Track agent information if provided
        if agent_id:
            analysis_result["agent_id"] = agent_id
        if agent_level:
            analysis_result["agent_level"] = agent_level
        
        return analysis_result
    
    def _calculate_complexity(
        self, 
        query_text: str, 
        entities: Dict[str, List[str]], 
        intents: Dict[str, float]
    ) -> str:
        """Calculate the complexity of the query"""
        # Simple heuristics for complexity:
        # 1. Word count
        words = query_text.split()
        word_count = len(words)
        
        # 2. Number of entities
        entity_count = sum(len(values) for values in entities.values())
        
        # 3. Number of different intents
        intent_count = len(intents)
        
        # Calculate complexity score
        complexity_score = 0
        
        # Word count contribution
        if word_count < 5:
            complexity_score += 1
        elif word_count < 15:
            complexity_score += 2
        else:
            complexity_score += 3
        
        # Entity count contribution
        complexity_score += min(3, entity_count)
        
        # Intent count contribution
        complexity_score += intent_count
        
        # Determine complexity level
        if complexity_score <= 3:
            return "simple"
        elif complexity_score <= 6:
            return "medium"
        else:
            return "complex"