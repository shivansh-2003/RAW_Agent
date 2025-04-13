# rules_matcher.py

import os
import json
import logging
import time
import re
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from datetime import datetime
import numpy as np
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("rules_matcher.log")
    ]
)
logger = logging.getLogger("shadow_rules_matcher")

# Models
class RuleMatch(BaseModel):
    """Rule match result"""
    rule_id: int
    trigger_phrases: List[str]
    required_level: Union[int, str]
    response_instruction: str
    response_text: Optional[str] = None
    match_score: float
    match_method: str  # "vector", "graph", "keyword", "hybrid"
    matched_phrases: List[str] = Field(default_factory=list)

class RulesMatcher:
    """
    Rules Matching Engine for Project SHADOW
    
    This engine identifies which rules match an agent's query based on:
    1. Keyword/trigger phrase matching
    2. Vector similarity (if embeddings available)
    3. Graph traversal for related concepts
    4. Hybrid approach combining the above
    """
    
    def __init__(self, rules_file_path: str, use_embeddings: bool = False):
        """Initialize the Rules Matcher"""
        self.rules_file_path = rules_file_path
        self.use_embeddings = use_embeddings
        
        # Load rules
        self.rules = self._load_rules()
        
        # Initialize embeddings if requested
        if use_embeddings:
            self._init_embeddings()
        else:
            self.embeddings = None
            self.rule_vectors = {}
        
        # Build trigger phrase index
        self.trigger_phrase_index = self._build_trigger_phrase_index()
        
        # Build graph of related rules (if needed for graph traversal)
        self.rule_graph = self._build_rule_graph()
        
        logger.info(f"Rules Matcher initialized with {len(self.rules)} rules")
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load rules from JSON file"""
        try:
            with open(self.rules_file_path, 'r') as f:
                data = json.load(f)
                return data.get('rules', [])
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            return []
    
    def _init_embeddings(self):
        """Initialize embeddings for vector similarity search"""
        try:
            # Try to import sentence-transformers for embeddings
            from sentence_transformers import SentenceTransformer
            
            # Load a pre-trained model
            self.embeddings = SentenceTransformer('all-MiniLM-L6-v2')
            
            # Generate embeddings for all rules
            self.rule_vectors = {}
            
            for rule in self.rules:
                rule_id = rule["id"]
                
                # Create a text representation of the rule
                rule_text = f"Rule {rule_id}: "
                if "trigger_phrases" in rule:
                    rule_text += "Triggers: " + ", ".join(rule["trigger_phrases"]) + ". "
                if "response_instruction" in rule:
                    rule_text += "Instruction: " + rule["response_instruction"]
                
                # Generate embedding
                embedding = self.embeddings.encode(rule_text)
                self.rule_vectors[rule_id] = embedding
            
            logger.info(f"Generated embeddings for {len(self.rule_vectors)} rules")
        
        except ImportError:
            logger.warning("Sentence-transformers not available. Vector similarity disabled.")
            self.embeddings = None
            self.rule_vectors = {}
        
        except Exception as e:
            logger.error(f"Error initializing embeddings: {e}")
            self.embeddings = None
            self.rule_vectors = {}
    
    def _build_trigger_phrase_index(self) -> Dict[str, List[int]]:
        """Build an index of trigger phrases to rule IDs for quick lookup"""
        index = {}
        
        for rule in self.rules:
            rule_id = rule["id"]
            trigger_phrases = rule.get("trigger_phrases", [])
            
            for phrase in trigger_phrases:
                phrase_lower = phrase.lower()
                if phrase_lower not in index:
                    index[phrase_lower] = []
                
                index[phrase_lower].append(rule_id)
        
        return index
    
    def _build_rule_graph(self) -> Dict[int, Set[int]]:
        """Build a graph of related rules for graph traversal"""
        graph = {}
        
        # For simplicity, we'll consider rules related if they:
        # 1. Have the same required clearance level
        # 2. Share common words in trigger phrases
        
        # Initialize graph nodes
        for rule in self.rules:
            rule_id = rule["id"]
            graph[rule_id] = set()
        
        # Connect related rules
        for i, rule1 in enumerate(self.rules):
            rule1_id = rule1["id"]
            rule1_level = rule1.get("required_level")
            rule1_phrases = rule1.get("trigger_phrases", [])
            rule1_words = set()
            
            # Extract words from trigger phrases
            for phrase in rule1_phrases:
                rule1_words.update(phrase.lower().split())
            
            for j, rule2 in enumerate(self.rules):
                if i == j:
                    continue  # Skip self-comparison
                
                rule2_id = rule2["id"]
                rule2_level = rule2.get("required_level")
                rule2_phrases = rule2.get("trigger_phrases", [])
                rule2_words = set()
                
                # Extract words from trigger phrases
                for phrase in rule2_phrases:
                    rule2_words.update(phrase.lower().split())
                
                # Check if rules are related
                is_related = False
                
                # Same clearance level
                if rule1_level == rule2_level:
                    is_related = True
                
                # Common words in trigger phrases
                common_words = rule1_words.intersection(rule2_words)
                if len(common_words) >= 2:  # At least 2 common words
                    is_related = True
                
                # Add edges if related
                if is_related:
                    graph[rule1_id].add(rule2_id)
                    graph[rule2_id].add(rule1_id)
        
        return graph
    
    def keyword_match(
        self, 
        query_text: str,
        extracted_entities: Dict[str, List[str]] = None
    ) -> List[RuleMatch]:
        """Find rule matches based on keyword/trigger phrase matching"""
        matches = []
        query_lower = query_text.lower()
        
        # Direct trigger phrase matching
        for rule in self.rules:
            rule_id = rule["id"]
            trigger_phrases = rule.get("trigger_phrases", [])
            matched_phrases = []
            
            # Check if any trigger phrase is in the query
            for phrase in trigger_phrases:
                phrase_lower = phrase.lower()
                if phrase_lower in query_lower:
                    matched_phrases.append(phrase)
            
            # If we have matches, create a RuleMatch
            if matched_phrases:
                match_score = len(max(matched_phrases, key=len)) / len(query_text)
                
                matches.append(
                    RuleMatch(
                        rule_id=rule_id,
                        trigger_phrases=trigger_phrases,
                        required_level=rule.get("required_level", "any"),
                        response_instruction=rule.get("response_instruction", ""),
                        response_text=rule.get("response_text", ""),
                        match_score=match_score,
                        match_method="keyword",
                        matched_phrases=matched_phrases
                    )
                )
        
        # Entity-based matching
        if extracted_entities:
            # Check if we have trigger phrases in extracted entities
            trigger_entities = []
            
            # Collect potential trigger phrases from entities
            for entity_type, entities in extracted_entities.items():
                if entity_type in ["OPERATION", "PROTOCOL", "CODEPHRASE", "TRIGGER_PHRASE"]:
                    trigger_entities.extend(entities)
            
            # Check each potential trigger entity
            for entity in trigger_entities:
                entity_lower = entity.lower()
                
                # Look for exact matches in our index
                if entity_lower in self.trigger_phrase_index:
                    rule_ids = self.trigger_phrase_index[entity_lower]
                    
                    for rule_id in rule_ids:
                        # Check if this rule is already matched
                        if any(match.rule_id == rule_id for match in matches):
                            continue
                        
                        # Find the rule
                        rule = next((r for r in self.rules if r["id"] == rule_id), None)
                        if not rule:
                            continue
                        
                        # Create a match
                        match_score = len(entity) / len(query_text)
                        
                        matches.append(
                            RuleMatch(
                                rule_id=rule_id,
                                trigger_phrases=rule.get("trigger_phrases", []),
                                required_level=rule.get("required_level", "any"),
                                response_instruction=rule.get("response_instruction", ""),
                                response_text=rule.get("response_text", ""),
                                match_score=match_score,
                                match_method="entity",
                                matched_phrases=[entity]
                            )
                        )
        
        # Sort by match score
        matches.sort(key=lambda x: x.match_score, reverse=True)
        return matches
    
    def vector_match(self, query_text: str, top_k: int = 5) -> List[RuleMatch]:
        """Find rule matches based on vector similarity"""
        if not self.embeddings or not self.rule_vectors:
            return []
        
        try:
            # Generate query embedding
            query_embedding = self.embeddings.encode(query_text)
            
            # Calculate similarity with all rules
            similarities = {}
            
            for rule_id, rule_vector in self.rule_vectors.items():
                # Calculate cosine similarity
                similarity = np.dot(query_embedding, rule_vector) / (
                    np.linalg.norm(query_embedding) * np.linalg.norm(rule_vector)
                )
                similarities[rule_id] = float(similarity)
            
            # Sort by similarity
            sorted_rules = sorted(similarities.items(), key=lambda x: x[1], reverse=True)
            top_rules = sorted_rules[:top_k]
            
            # Create rule matches
            matches = []
            
            for rule_id, similarity in top_rules:
                # Only include if similarity is above threshold
                if similarity < 0.5:  # Minimum similarity threshold
                    continue
                
                # Find the rule
                rule = next((r for r in self.rules if r["id"] == rule_id), None)
                if not rule:
                    continue
                
                matches.append(
                    RuleMatch(
                        rule_id=rule_id,
                        trigger_phrases=rule.get("trigger_phrases", []),
                        required_level=rule.get("required_level", "any"),
                        response_instruction=rule.get("response_instruction", ""),
                        response_text=rule.get("response_text", ""),
                        match_score=similarity,
                        match_method="vector",
                        matched_phrases=[]  # No specific phrases for vector match
                    )
                )
            
            return matches
        
        except Exception as e:
            logger.error(f"Error in vector matching: {e}")
            return []
    
    def graph_match(
        self, 
        seed_rules: List[int], 
        depth: int = 1
    ) -> List[RuleMatch]:
        """Find related rules using graph traversal"""
        if not self.rule_graph:
            return []
        
        matches = []
        visited = set()
        
        # BFS traversal starting from seed rules
        queue = [(rule_id, 0) for rule_id in seed_rules]  # (rule_id, depth)
        
        while queue:
            rule_id, current_depth = queue.pop(0)
            
            if rule_id in visited:
                continue
            
            visited.add(rule_id)
            
            # Skip seed rules (they're already matched)
            if current_depth > 0:
                # Find the rule
                rule = next((r for r in self.rules if r["id"] == rule_id), None)
                if rule:
                    # Calculate diminishing score based on depth
                    score = 0.9 ** current_depth  # Score decreases with depth
                    
                    matches.append(
                        RuleMatch(
                            rule_id=rule_id,
                            trigger_phrases=rule.get("trigger_phrases", []),
                            required_level=rule.get("required_level", "any"),
                            response_instruction=rule.get("response_instruction", ""),
                            response_text=rule.get("response_text", ""),
                            match_score=score,
                            match_method="graph",
                            matched_phrases=[]  # No specific phrases for graph matches
                        )
                    )
            
            # Continue traversal if not at max depth
            if current_depth < depth:
                # Get related rules
                related_rules = self.rule_graph.get(rule_id, set())
                
                for related_id in related_rules:
                    if related_id not in visited:
                        queue.append((related_id, current_depth + 1))
        
        # Sort by match score
        matches.sort(key=lambda x: x.match_score, reverse=True)
        return matches
    
    def hybrid_match(
        self, 
        query_text: str, 
        extracted_entities: Dict[str, List[str]] = None,
        top_k: int = 5
    ) -> List[RuleMatch]:
        """
        Combine multiple matching methods for optimal results
        
        1. Start with keyword matches (high precision)
        2. Add vector matches if available (semantic understanding)
        3. Expand with graph matches (related concepts)
        """
        all_matches = {}
        
        # Start with keyword matches
        keyword_matches = self.keyword_match(query_text, extracted_entities)
        
        # Add to all_matches
        for match in keyword_matches:
            all_matches[match.rule_id] = {
                "match": match,
                "score": match.match_score,
                "methods": [match.match_method]
            }
        
        # Add vector matches if available
        if self.use_embeddings:
            vector_matches = self.vector_match(query_text, top_k)
            
            for match in vector_matches:
                rule_id = match.rule_id
                
                if rule_id not in all_matches:
                    all_matches[rule_id] = {
                        "match": match,
                        "score": match.match_score * 0.7,  # Weight vector matches slightly lower
                        "methods": [match.match_method]
                    }
                else:
                    # Combine scores
                    all_matches[rule_id]["score"] += match.match_score * 0.7
                    all_matches[rule_id]["methods"].append(match.match_method)
        
        # Collect seed rules for graph traversal
        seed_rules = list(all_matches.keys())
        
        # Only do graph traversal if we have seed rules
        if seed_rules:
            graph_matches = self.graph_match(seed_rules, depth=1)
            
            for match in graph_matches:
                rule_id = match.rule_id
                
                if rule_id not in all_matches:
                    all_matches[rule_id] = {
                        "match": match,
                        "score": match.match_score * 0.5,  # Weight graph matches lower
                        "methods": [match.match_method]
                    }
                else:
                    # We don't add graph match scores for rules we already matched
                    all_matches[rule_id]["methods"].append(match.match_method)
        
        # Convert back to list of matches
        hybrid_matches = []
        
        for rule_id, data in all_matches.items():
            match = data["match"]
            methods = data["methods"]
            
            # Create a new match with hybrid method and combined score
            hybrid_match = RuleMatch(
                rule_id=match.rule_id,
                trigger_phrases=match.trigger_phrases,
                required_level=match.required_level,
                response_instruction=match.response_instruction,
                response_text=match.response_text,
                match_score=data["score"],
                match_method="hybrid" if len(methods) > 1 else methods[0],
                matched_phrases=match.matched_phrases
            )
            
            hybrid_matches.append(hybrid_match)
        
        # Sort by combined score
        hybrid_matches.sort(key=lambda x: x.match_score, reverse=True)
        
        return hybrid_matches[:top_k]
    
    def find_matching_rules(
        self, 
        query_text: str, 
        extracted_entities: Dict[str, List[str]] = None,
        intents: Dict[str, float] = None
    ) -> List[RuleMatch]:
        """Find rules that match the query"""
        try:
            # Use hybrid matching for best results
            matches = self.hybrid_match(query_text, extracted_entities)
            
            # If no matches, fall back to simple keyword matching with looser criteria
            if not matches:
                # Try partial word matching
                query_words = set(query_text.lower().split())
                
                for rule in self.rules:
                    rule_id = rule["id"]
                    trigger_phrases = rule.get("trigger_phrases", [])
                    
                    for phrase in trigger_phrases:
                        phrase_words = set(phrase.lower().split())
                        
                        # Check if any significant words overlap
                        common_words = query_words.intersection(phrase_words)
                        
                        # If we have at least 1 significant common word, consider it a match
                        if common_words and any(len(word) > 4 for word in common_words):
                            # Calculate score based on overlap
                            score = len(common_words) / max(len(query_words), len(phrase_words))
                            
                            matches.append(
                                RuleMatch(
                                    rule_id=rule_id,
                                    trigger_phrases=trigger_phrases,
                                    required_level=rule.get("required_level", "any"),
                                    response_instruction=rule.get("response_instruction", ""),
                                    response_text=rule.get("response_text", ""),
                                    match_score=score * 0.7,  # Lower confidence for partial matches
                                    match_method="partial",
                                    matched_phrases=[phrase]
                                )
                            )
                            
                            # Only match once per rule
                            break
                
                # Sort by score
                matches.sort(key=lambda x: x.match_score, reverse=True)
            
            # Log matches for debugging
            if matches:
                logger.debug(f"Found {len(matches)} matching rules for query: {query_text[:50]}...")
                for i, match in enumerate(matches[:3]):
                    logger.debug(f"  Match {i+1}: Rule {match.rule_id} (score: {match.match_score:.2f}, method: {match.match_method})")
            else:
                logger.warning(f"No matching rules found for query: {query_text[:50]}...")
            
            return matches
        
        except Exception as e:
            logger.error(f"Error finding matching rules: {e}")
            return []
    
    def get_rule_by_id(self, rule_id: int) -> Optional[Dict[str, Any]]:
        """Get a rule by ID"""
        return next((rule for rule in self.rules if rule["id"] == rule_id), None)