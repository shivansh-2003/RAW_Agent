# hybrid_retrieval_engine.py

import os
import logging
import numpy as np
import json
import networkx as nx
import faiss
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from datetime import datetime
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("hybrid_retrieval.log")
    ]
)
logger = logging.getLogger("shadow_hybrid_retrieval")

class RuleMatch(BaseModel):
    """Rule match data model"""
    rule_id: int
    trigger_phrases: List[str]
    required_level: Union[int, str]
    response_instruction: str
    response_text: Optional[str] = None
    match_score: float
    match_method: str  # "vector", "graph", "hybrid", "keyword"
    confidence: float = 1.0  # Confidence in the match (0-1)

class RetrievalContext(BaseModel):
    """Context for retrieval operations"""
    agent_id: str
    agent_level: int
    session_id: Optional[str] = None
    query_id: str
    query_timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # Security and operational parameters
    security_level: str = "standard"  # "standard", "elevated", "critical"
    retrieval_mode: str = "balanced"  # "precision", "balanced", "recall"
    result_limit: int = 5
    
class HybridRetrievalEngine:
    """
    Advanced hybrid retrieval engine for Project SHADOW
    
    Combines vector search, knowledge graph traversal, and rule-based matching
    to provide context-aware, security-conscious retrieval of intelligence data.
    """
    
    def __init__(
        self,
        vector_store_path: str,
        graph_db_path: str,
        rules_file_path: str,
        embedding_dimension: int = 768,
        vector_similarity_threshold: float = 0.65,
        graph_depth_limit: int = 3,
        fallback_to_keyword: bool = True
    ):
        self.vector_store_path = vector_store_path
        self.graph_db_path = graph_db_path
        self.rules_file_path = rules_file_path
        self.embedding_dimension = embedding_dimension
        self.vector_similarity_threshold = vector_similarity_threshold
        self.graph_depth_limit = graph_depth_limit
        self.fallback_to_keyword = fallback_to_keyword
        
        # Load components
        self.rules = self._load_rules()
        self.faiss_index = self._load_vector_index()
        self.knowledge_graph = self._load_knowledge_graph()
        self.rule_embeddings = self._load_rule_embeddings()
        self.security_checks = self._initialize_security_checks()
        
        logger.info(f"Hybrid Retrieval Engine initialized with {len(self.rules)} rules")
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load rules from the JSON file"""
        try:
            with open(self.rules_file_path, 'r') as f:
                data = json.load(f)
                return data.get('rules', [])
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            return []
    
    def _load_vector_index(self) -> Optional[Any]:
        """Load FAISS vector index"""
        try:
            if os.path.exists(f"{self.vector_store_path}/index.faiss"):
                logger.info("Loading FAISS index from disk")
                index = faiss.read_index(f"{self.vector_store_path}/index.faiss")
                return index
            else:
                logger.warning("FAISS index not found, initializing empty index")
                # Create empty index
                index = faiss.IndexFlatIP(self.embedding_dimension)  # Inner product (cosine similarity)
                return index
        except Exception as e:
            logger.error(f"Error loading vector index: {e}")
            return None
    
    def _load_rule_embeddings(self) -> Dict[int, np.ndarray]:
        """Load rule embeddings"""
        try:
            embeddings_path = f"{self.vector_store_path}/rule_embeddings.npz"
            if os.path.exists(embeddings_path):
                data = np.load(embeddings_path, allow_pickle=True)
                return {int(k): v for k, v in data['embeddings'].item().items()}
            else:
                logger.warning("Rule embeddings not found")
                return {}
        except Exception as e:
            logger.error(f"Error loading rule embeddings: {e}")
            return {}
    
    def _load_knowledge_graph(self) -> nx.DiGraph:
        """Load knowledge graph"""
        try:
            graph_path = f"{self.graph_db_path}/graph.json"
            if os.path.exists(graph_path):
                with open(graph_path, 'r') as f:
                    graph_data = json.load(f)
                
                G = nx.node_link_graph(graph_data)
                logger.info(f"Loaded knowledge graph with {len(G.nodes)} nodes and {len(G.edges)} edges")
                return G
            else:
                logger.warning("Knowledge graph not found, initializing empty graph")
                return nx.DiGraph()
        except Exception as e:
            logger.error(f"Error loading knowledge graph: {e}")
            return nx.DiGraph()
    
    def _initialize_security_checks(self) -> Dict[str, Any]:
        """Initialize security checks and filters"""
        return {
            "clearance_checks": True,
            "anomaly_detection": True,
            "mosaic_pattern_analysis": True,
            "query_sanitization": True,
            "ghost_step_integration": True
        }
    
    def vector_search(
        self, 
        query_embedding: np.ndarray, 
        context: RetrievalContext
    ) -> List[RuleMatch]:
        """
        Perform vector similarity search
        
        Args:
            query_embedding: Embedded query vector
            context: Retrieval context with agent details
            
        Returns:
            List of rule matches sorted by relevance
        """
        if self.faiss_index is None or self.faiss_index.ntotal == 0:
            logger.warning("Vector index is empty, skipping vector search")
            return []
        
        try:
            # Normalize the query vector
            query_norm = np.linalg.norm(query_embedding)
            if query_norm > 0:
                normalized_query = query_embedding / query_norm
            else:
                normalized_query = query_embedding
            
            # Convert to the right shape and dtype
            query_vector = np.array([normalized_query], dtype=np.float32)
            
            # Set search parameters based on retrieval mode
            k = context.result_limit
            if context.retrieval_mode == "recall":
                k = min(k * 2, self.faiss_index.ntotal)  # Get more results for recall-oriented search
            
            # Perform search
            scores, indices = self.faiss_index.search(query_vector, k)
            
            # Process results
            matches = []
            
            # Map index positions back to rule IDs
            with open(f"{self.vector_store_path}/index_to_id.json", 'r') as f:
                index_to_id = json.load(f)
                
            for i, (index, score) in enumerate(zip(indices[0], scores[0])):
                if score < self.vector_similarity_threshold:
                    continue
                
                # Get rule ID from index
                rule_id = int(index_to_id.get(str(index), -1))
                if rule_id == -1:
                    continue
                
                # Find the rule
                rule = next((r for r in self.rules if r["id"] == rule_id), None)
                if not rule:
                    continue
                
                # Apply clearance level filtering
                required_level = rule.get("required_level")
                if required_level != "any" and int(required_level) > context.agent_level:
                    # Skip rules that require higher clearance
                    continue
                
                # Create match object
                match = RuleMatch(
                    rule_id=rule_id,
                    trigger_phrases=rule.get("trigger_phrases", []),
                    required_level=required_level,
                    response_instruction=rule.get("response_instruction", ""),
                    response_text=rule.get("response_text", ""),
                    match_score=float(score),
                    match_method="vector",
                    confidence=min(float(score) / 0.9, 1.0)  # Scale score to confidence
                )
                
                matches.append(match)
            
            # Sort by score
            matches.sort(key=lambda x: x.match_score, reverse=True)
            return matches
            
        except Exception as e:
            logger.error(f"Error in vector search: {e}")
            return []
    
    def graph_search(
        self, 
        query_tokens: List[str], 
        context: RetrievalContext
    ) -> List[RuleMatch]:
        """
        Perform knowledge graph traversal search
        
        Args:
            query_tokens: Tokenized query terms and phrases
            context: Retrieval context with agent details
            
        Returns:
            List of rule matches sorted by relevance
        """
        if not self.knowledge_graph or len(self.knowledge_graph.nodes) == 0:
            logger.warning("Knowledge graph is empty, skipping graph search")
            return []
        
        try:
            # Prepare n-grams from tokens for matching
            ngrams = []
            
            # Add original tokens
            ngrams.extend(query_tokens)
            
            # Add bigrams
            if len(query_tokens) >= 2:
                bigrams = [f"{query_tokens[i]} {query_tokens[i+1]}" for i in range(len(query_tokens)-1)]
                ngrams.extend(bigrams)
            
            # Add trigrams
            if len(query_tokens) >= 3:
                trigrams = [f"{query_tokens[i]} {query_tokens[i+1]} {query_tokens[i+2]}" for i in range(len(query_tokens)-2)]
                ngrams.extend(trigrams)
            
            # Track matched nodes
            matched_nodes = set()
            phrase_matches = {}
            
            # Find direct phrase matches
            for token in ngrams:
                token_lower = token.lower()
                
                # Look for matches in phrase nodes
                for node, attrs in self.knowledge_graph.nodes(data=True):
                    if attrs.get("type") != "phrase":
                        continue
                    
                    node_text = attrs.get("text", "").lower()
                    
                    # Check for exact or partial matches
                    if token_lower == node_text or token_lower in node_text or node_text in token_lower:
                        matched_nodes.add(node)
                        
                        # Calculate match quality
                        if token_lower == node_text:
                            quality = 1.0  # Exact match
                        elif token_lower in node_text:
                            quality = len(token_lower) / len(node_text)  # Partial match
                        else:
                            quality = len(node_text) / len(token_lower)  # Partial match
                        
                        phrase_matches[node] = max(quality, phrase_matches.get(node, 0))
            
            # Define traversal function for graph exploration
            def traverse_graph(start_node, depth=0, visited=None, path_quality=1.0):
                if visited is None:
                    visited = set()
                
                if depth >= self.graph_depth_limit or start_node in visited:
                    return {}
                
                visited.add(start_node)
                rule_scores = {}
                
                # Process outgoing edges
                for target in self.knowledge_graph.successors(start_node):
                    edge_data = self.knowledge_graph.get_edge_data(start_node, target)
                    edge_type = edge_data.get("type", "")
                    edge_weight = edge_data.get("weight", 0.8)  # Default weight if not specified
                    
                    # Apply quality degradation for non-primary edges
                    if edge_type == "semantic":
                        new_quality = path_quality * edge_weight
                    else:
                        new_quality = path_quality * 0.9  # Slight degradation for other edge types
                    
                    # If target is a rule, add it to scores
                    if target.startswith("rule_"):
                        rule_id = int(target.split("_")[1])
                        if rule_id not in rule_scores:
                            rule_scores[rule_id] = 0
                        rule_scores[rule_id] = max(rule_scores[rule_id], new_quality)
                    
                    # Continue traversal
                    deeper_scores = traverse_graph(target, depth + 1, visited, new_quality)
                    for rule_id, score in deeper_scores.items():
                        if rule_id not in rule_scores:
                            rule_scores[rule_id] = 0
                        rule_scores[rule_id] = max(rule_scores[rule_id], score)
                
                return rule_scores
            
            # Collect rule scores from traversals
            all_rule_scores = {}
            
            for phrase_node, quality in phrase_matches.items():
                traversal_scores = traverse_graph(phrase_node, path_quality=quality)
                
                for rule_id, score in traversal_scores.items():
                    if rule_id not in all_rule_scores:
                        all_rule_scores[rule_id] = 0
                    all_rule_scores[rule_id] = max(all_rule_scores[rule_id], score)
            
            # Convert scores to matches
            matches = []
            
            for rule_id, score in all_rule_scores.items():
                # Find the rule
                rule = next((r for r in self.rules if r["id"] == rule_id), None)
                if not rule:
                    continue
                
                # Apply clearance level filtering
                required_level = rule.get("required_level")
                if required_level != "any" and int(required_level) > context.agent_level:
                    # Skip rules that require higher clearance
                    continue
                
                # Create match object
                match = RuleMatch(
                    rule_id=rule_id,
                    trigger_phrases=rule.get("trigger_phrases", []),
                    required_level=required_level,
                    response_instruction=rule.get("response_instruction", ""),
                    response_text=rule.get("response_text", ""),
                    match_score=score,
                    match_method="graph",
                    confidence=min(score, 1.0)  # Score is already 0-1
                )
                
                matches.append(match)
            
            # Sort by score
            matches.sort(key=lambda x: x.match_score, reverse=True)
            return matches[:context.result_limit]
        
        except Exception as e:
            logger.error(f"Error in graph search: {e}")
            return []
    
    def keyword_search(
        self, 
        query_tokens: List[str], 
        context: RetrievalContext
    ) -> List[RuleMatch]:
        """
        Perform keyword-based search
        
        Args:
            query_tokens: Tokenized query terms
            context: Retrieval context with agent details
            
        Returns:
            List of rule matches sorted by relevance
        """
        try:
            matches = []
            query_text = " ".join(query_tokens).lower()
            
            for rule in self.rules:
                # Check if any trigger phrase is in the query
                matched_phrase = None
                max_score = 0
                
                for phrase in rule.get("trigger_phrases", []):
                    phrase_lower = phrase.lower()
                    if phrase_lower in query_text:
                        # Calculate a score based on phrase length relative to query
                        score = len(phrase) / len(query_text) if query_text else 0
                        if score > max_score:
                            max_score = score
                            matched_phrase = phrase
                
                if matched_phrase:
                    # Check clearance level
                    required_level = rule.get("required_level")
                    if required_level != "any" and int(required_level) > context.agent_level:
                        continue
                    
                    matches.append(
                        RuleMatch(
                            rule_id=rule["id"],
                            trigger_phrases=rule.get("trigger_phrases", []),
                            required_level=required_level,
                            response_instruction=rule.get("response_instruction", ""),
                            response_text=rule.get("response_text", ""),
                            match_score=max_score,
                            match_method="keyword",
                            confidence=max_score * 0.8  # Lower confidence for keyword matches
                        )
                    )
            
            # Sort by score
            matches.sort(key=lambda x: x.match_score, reverse=True)
            return matches[:context.result_limit]
        
        except Exception as e:
            logger.error(f"Error in keyword search: {e}")
            return []
    
    def hybrid_search(
        self, 
        query_embedding: np.ndarray,
        query_tokens: List[str], 
        context: RetrievalContext
    ) -> Tuple[List[RuleMatch], Dict[str, Any]]:
        """
        Perform hybrid search combining vector, graph, and keyword methods
        
        Args:
            query_embedding: Embedded query vector
            query_tokens: Tokenized query terms
            context: Retrieval context with agent details
            
        Returns:
            Tuple of (rule matches, search metadata)
        """
        try:
            # Track search metadata
            metadata = {
                "methods_used": [],
                "method_counts": {},
                "timing": {},
                "fallback_triggered": False
            }
            
            # Start with empty results
            vector_matches = []
            graph_matches = []
            keyword_matches = []
            
            # Adjust search strategy based on security level and retrieval mode
            vector_weight = 0.6
            graph_weight = 0.4
            keyword_weight = 0.2
            
            if context.security_level == "critical":
                # In critical security mode, prioritize exact matches
                vector_weight = 0.4
                graph_weight = 0.3
                keyword_weight = 0.3
            
            if context.retrieval_mode == "precision":
                # Precision mode prioritizes vector similarity
                vector_weight = 0.7
                graph_weight = 0.2
                keyword_weight = 0.1
            elif context.retrieval_mode == "recall":
                # Recall mode emphasizes finding all potential matches
                vector_weight = 0.4
                graph_weight = 0.4
                keyword_weight = 0.2
            
            # Perform searches in parallel (in real implementation)
            # For now, we'll do them sequentially
            
            # Vector search
            import time
            start_time = time.time()
            vector_matches = self.vector_search(query_embedding, context)
            metadata["timing"]["vector_search"] = time.time() - start_time
            metadata["methods_used"].append("vector")
            metadata["method_counts"]["vector"] = len(vector_matches)
            
            # Graph search
            start_time = time.time()
            graph_matches = self.graph_search(query_tokens, context)
            metadata["timing"]["graph_search"] = time.time() - start_time
            metadata["methods_used"].append("graph")
            metadata["method_counts"]["graph"] = len(graph_matches)
            
            # Only do keyword search if we have few or no results
            if self.fallback_to_keyword and (len(vector_matches) + len(graph_matches) < 2):
                start_time = time.time()
                keyword_matches = self.keyword_search(query_tokens, context)
                metadata["timing"]["keyword_search"] = time.time() - start_time
                metadata["methods_used"].append("keyword")
                metadata["method_counts"]["keyword"] = len(keyword_matches)
                metadata["fallback_triggered"] = True
            
            # If all searches failed, force a keyword search
            if not vector_matches and not graph_matches and not keyword_matches and self.fallback_to_keyword:
                start_time = time.time()
                keyword_matches = self.keyword_search(query_tokens, context)
                metadata["timing"]["keyword_search"] = time.time() - start_time
                metadata["methods_used"].append("keyword")
                metadata["method_counts"]["keyword"] = len(keyword_matches)
                metadata["fallback_triggered"] = True
            
            # Calculate combined scores using weighted approach
            rule_scores = {}
            
            # Function to update rule scores
            def update_scores(matches, weight, method):
                for i, match in enumerate(matches):
                    rule_id = match.rule_id
                    
                    # Adjust score based on position
                    position_factor = 1.0 / (i + 1)  # Higher rank = higher score
                    adjusted_score = match.match_score * position_factor
                    
                    if rule_id not in rule_scores:
                        rule_scores[rule_id] = {
                            "weighted_score": 0,
                            "max_raw_score": 0,
                            "methods": set(),
                            "match": match,
                            "confidence": 0
                        }
                    
                    # Update weighted score
                    rule_scores[rule_id]["weighted_score"] += adjusted_score * weight
                    
                    # Track max raw score
                    rule_scores[rule_id]["max_raw_score"] = max(
                        rule_scores[rule_id]["max_raw_score"],
                        match.match_score
                    )
                    
                    # Track methods and confidence
                    rule_scores[rule_id]["methods"].add(method)
                    rule_scores[rule_id]["confidence"] = max(
                        rule_scores[rule_id]["confidence"],
                        match.confidence * weight
                    )
            
            # Update scores from each method
            update_scores(vector_matches, vector_weight, "vector")
            update_scores(graph_matches, graph_weight, "graph")
            update_scores(keyword_matches, keyword_weight, "keyword")
            
            # Convert to final matches
            hybrid_matches = []
            for rule_id, data in rule_scores.items():
                match = data["match"]
                
                # Method determination
                if len(data["methods"]) > 1:
                    method = "hybrid"
                else:
                    method = list(data["methods"])[0]
                
                # Create hybrid match
                hybrid_match = RuleMatch(
                    rule_id=match.rule_id,
                    trigger_phrases=match.trigger_phrases,
                    required_level=match.required_level,
                    response_instruction=match.response_instruction,
                    response_text=match.response_text,
                    match_score=data["weighted_score"],
                    match_method=method,
                    confidence=data["confidence"]
                )
                
                hybrid_matches.append(hybrid_match)
            
            # Sort by score
            hybrid_matches.sort(key=lambda x: x.match_score, reverse=True)
            
            # Calculate metadata
            metadata["total_candidates"] = len(rule_scores)
            metadata["top_method"] = hybrid_matches[0].match_method if hybrid_matches else "none"
            metadata["confidence"] = hybrid_matches[0].confidence if hybrid_matches else 0
            
            # Limit results
            final_matches = hybrid_matches[:context.result_limit]
            
            return final_matches, metadata
        
        except Exception as e:
            logger.error(f"Error in hybrid search: {e}")
            # Try to fall back to keyword search in case of error
            try:
                if self.fallback_to_keyword:
                    keyword_matches = self.keyword_search(query_tokens, context)
                    return keyword_matches, {
                        "methods_used": ["keyword_fallback"],
                        "error": str(e),
                        "fallback_triggered": True
                    }
            except:
                pass
            
            # Return empty results if all else fails
            return [], {"error": str(e)}
    
    def security_filter(
        self, 
        matches: List[RuleMatch], 
        context: RetrievalContext
    ) -> List[RuleMatch]:
        """
        Apply security filters to matches
        
        Args:
            matches: List of rule matches
            context: Retrieval context with agent details
            
        Returns:
            Filtered list of rule matches
        """
        try:
            filtered_matches = []
            
            for match in matches:
                # Apply clearance level check (redundant, but a safeguard)
                required_level = match.required_level
                if required_level != "any" and int(required_level) > context.agent_level:
                    continue
                
                # Apply security filters based on context
                if context.security_level == "critical":
                    # In critical security mode, only return high-confidence matches
                    if match.confidence < 0.8:
                        continue
                
                # Apply mosaic pattern analysis
                # This would check if this request combined with recent requests
                # reveals sensitive information through mosaic effect
                # For now, we'll just include all matches
                
                filtered_matches.append(match)
            
            return filtered_matches
        
        except Exception as e:
            logger.error(f"Error in security filter: {e}")
            return matches  # Return original matches if filtering fails
    
    def process_query(
        self,
        query_embedding: np.ndarray,
        query_tokens: List[str],
        context: RetrievalContext
    ) -> Tuple[List[RuleMatch], Dict[str, Any]]:
        """
        Process a query using the hybrid retrieval engine
        
        Args:
            query_embedding: Embedded query vector
            query_tokens: Tokenized query terms
            context: Retrieval context with agent details
            
        Returns:
            Tuple of (filtered rule matches, search metadata)
        """
        # Perform hybrid search
        matches, metadata = self.hybrid_search(query_embedding, query_tokens, context)
        
        # Apply security filters
        filtered_matches = self.security_filter(matches, context)
        metadata["filtered_count"] = len(matches) - len(filtered_matches)
        
        return filtered_matches, metadata
    
    def execute_special_directive(
        self,
        directive: str, 
        context: RetrievalContext
    ) -> Optional[RuleMatch]:
        """
        Handle special directives like "Omega Echo", "Protocol Zeta", etc.
        
        Args:
            directive: The special directive string
            context: Retrieval context
            
        Returns:
            A rule match if a directive is recognized, None otherwise
        """
        # Check for direct matches against special directives
        directive_lower = directive.lower()
        
        # Look for direct matches with special response phrases
        for rule in self.rules:
            for phrase in rule.get("trigger_phrases", []):
                if phrase.lower() == directive_lower:
                    # This is an exact match for a special directive
                    if rule.get("response_text"):
                        # Create a rule match
                        return RuleMatch(
                            rule_id=rule["id"],
                            trigger_phrases=[phrase],
                            required_level=rule.get("required_level", "any"),
                            response_instruction=rule.get("response_instruction", ""),
                            response_text=rule.get("response_text", ""),
                            match_score=1.0,  # Perfect score for direct match
                            match_method="directive",
                            confidence=1.0
                        )
        
        # No special directive found
        return None

    def enhance_retrieval_context(
        self,
        query_text: str,
        context: RetrievalContext
    ) -> RetrievalContext:
        """
        Enhance retrieval context with query analysis
        
        Args:
            query_text: The raw query text
            context: The basic retrieval context
            
        Returns:
            Enhanced retrieval context
        """
        # Copy context to avoid modifying the original
        enhanced_context = RetrievalContext(**context.dict())
        
        # Analyze query complexity
        query_length = len(query_text.split())
        if query_length > 20:
            # For complex queries, adjust retrieval mode to favor precision
            enhanced_context.retrieval_mode = "precision"
        elif query_length < 5:
            # For very short queries, use recall to avoid missing relevant matches
            enhanced_context.retrieval_mode = "recall"
        
        # Check for time-sensitive patterns
        time_sensitive_phrases = [
            "urgent", "immediate", "emergency", "time-sensitive", 
            "deadline", "critical", "now", "asap"
        ]
        if any(phrase in query_text.lower() for phrase in time_sensitive_phrases):
            enhanced_context.security_level = "critical"
        
        # Set result limit based on query complexity
        if query_length > 15:
            # More complex queries may need more results
            enhanced_context.result_limit = min(10, context.result_limit)
        
        return enhanced_context