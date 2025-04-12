# advanced_rag_layer.py

import os
import time
import json
import uuid
import logging
import numpy as np
import faiss
import networkx as nx
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator
import httpx
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import FAISS
from langchain.schema import Document
from langchain.llms import Anthropic
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("advanced_rag.log")
    ]
)
logger = logging.getLogger("shadow_advanced_rag")

# Initialize FastAPI app
app = FastAPI(
    title="SHADOW Advanced RAG Layer",
    description="Advanced Retrieval-Augmented Generation for Project SHADOW",
    version="1.0.0"
)

# Add CORS middleware if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "internal_service_key")
RULES_FILE_PATH = os.getenv("RULES_FILE_PATH", "data.json")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-mpnet-base-v2")
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", 512))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", 50))
VECTOR_STORE_PATH = os.getenv("VECTOR_STORE_PATH", "./vector_store")
GRAPH_DB_PATH = os.getenv("GRAPH_DB_PATH", "./graph_store")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "your-api-key")
TOP_K_VECTOR = int(os.getenv("TOP_K_VECTOR", 5))
TOP_K_GRAPH = int(os.getenv("TOP_K_GRAPH", 3))

# API Key verification
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != INTERNAL_API_KEY:
        logger.warning(f"Invalid API key attempt: {api_key[:5]}...")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return True

# Data Models
class RuleMatch(BaseModel):
    rule_id: int
    trigger_phrases: List[str]
    required_level: Union[int, str]
    response_instruction: str
    response_text: Optional[str] = None
    match_score: float
    match_method: str  # "vector", "graph", "hybrid"

class QueryRequest(BaseModel):
    query_text: str
    agent_level: int
    agent_id: str
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class QueryResponse(BaseModel):
    rule_match: Optional[RuleMatch] = None
    response_text: str
    greeting: str
    matched_sources: List[str] = Field(default_factory=list)
    search_strategy: str
    query_time_ms: float
    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class SecurityLog(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    agent_id: Optional[str] = None
    query_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "info"  # info, warning, error, critical
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# RAG Components

class AdvancedRAG:
    def __init__(self):
        self.rules = self._load_rules()
        self.embeddings = self._init_embeddings()
        self.vector_store = self._init_vector_store()
        self.knowledge_graph = self._init_knowledge_graph()
        self.llm = self._init_llm()
        self.response_chain = self._init_response_chain()
        logger.info("Advanced RAG Layer initialized successfully")

    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load rules from the JSON file"""
        try:
            with open(RULES_FILE_PATH, 'r') as f:
                data = json.load(f)
                return data.get('rules', [])
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            # Return empty list as fallback
            return []

    def _init_embeddings(self):
        """Initialize the embedding model"""
        try:
            return HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
        except Exception as e:
            logger.error(f"Error initializing embeddings: {e}")
            raise

    def _init_vector_store(self):
        """Initialize or load the vector store"""
        try:
            # Check if vector store exists
            if os.path.exists(f"{VECTOR_STORE_PATH}/index.faiss"):
                logger.info("Loading existing vector store")
                return FAISS.load_local(VECTOR_STORE_PATH, self.embeddings)
            
            # Initialize new vector store
            logger.info("Initializing new vector store")
            
            # Create documents from rules
            documents = []
            for rule in self.rules:
                # Create a document for each rule
                content = f"Rule ID: {rule['id']}\nTrigger Phrases: {', '.join(rule['trigger_phrases'])}\n"
                content += f"Required Level: {rule['required_level']}\n"
                content += f"Response Instruction: {rule['response_instruction']}\n"
                
                if rule.get('response_text'):
                    content += f"Response Text: {rule['response_text']}\n"
                
                metadata = {
                    "rule_id": rule["id"],
                    "required_level": rule["required_level"],
                    "trigger_phrases": rule["trigger_phrases"]
                }
                
                documents.append(Document(page_content=content, metadata=metadata))
            
            # Split documents into chunks
            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=CHUNK_SIZE,
                chunk_overlap=CHUNK_OVERLAP
            )
            
            splits = text_splitter.split_documents(documents)
            
            # Create vector store
            vector_store = FAISS.from_documents(splits, self.embeddings)
            
            # Save vector store
            os.makedirs(VECTOR_STORE_PATH, exist_ok=True)
            vector_store.save_local(VECTOR_STORE_PATH)
            
            return vector_store
        except Exception as e:
            logger.error(f"Error initializing vector store: {e}")
            raise

    def _init_knowledge_graph(self):
        """Initialize the knowledge graph"""
        try:
            # Check if graph store exists
            if os.path.exists(f"{GRAPH_DB_PATH}/graph.json"):
                logger.info("Loading existing knowledge graph")
                with open(f"{GRAPH_DB_PATH}/graph.json", 'r') as f:
                    graph_data = json.load(f)
                
                G = nx.node_link_graph(graph_data)
                return G
            
            # Initialize new knowledge graph
            logger.info("Initializing new knowledge graph")
            G = nx.DiGraph()
            
            # Add nodes for each rule
            for rule in self.rules:
                rule_id = rule["id"]
                G.add_node(
                    f"rule_{rule_id}", 
                    type="rule",
                    rule_id=rule_id,
                    required_level=rule["required_level"]
                )
                
                # Add nodes for each trigger phrase
                for phrase in rule["trigger_phrases"]:
                    phrase_node = f"phrase_{phrase}"
                    if not G.has_node(phrase_node):
                        G.add_node(phrase_node, type="phrase", text=phrase)
                    
                    # Connect trigger phrase to rule
                    G.add_edge(phrase_node, f"rule_{rule_id}", type="triggers")
                
                # Add semantic connections between rules
                if "related_rules" in rule:
                    for related_id in rule.get("related_rules", []):
                        G.add_edge(
                            f"rule_{rule_id}", 
                            f"rule_{related_id}", 
                            type="related"
                        )
            
            # Add additional semantic connections
            self._add_semantic_connections(G)
            
            # Save the graph
            os.makedirs(GRAPH_DB_PATH, exist_ok=True)
            with open(f"{GRAPH_DB_PATH}/graph.json", 'w') as f:
                json.dump(nx.node_link_data(G), f)
            
            return G
        except Exception as e:
            logger.error(f"Error initializing knowledge graph: {e}")
            raise

    def _add_semantic_connections(self, G):
        """Add semantic connections between rules based on trigger phrase similarity"""
        # Extract phrases for each rule
        rule_phrases = {}
        for rule in self.rules:
            rule_id = rule["id"]
            rule_phrases[rule_id] = rule["trigger_phrases"]
        
        # Calculate Jaccard similarity between rule trigger phrases
        for rule_id1, phrases1 in rule_phrases.items():
            for rule_id2, phrases2 in rule_phrases.items():
                if rule_id1 != rule_id2:
                    # Calculate intersection and union
                    intersection = set(phrases1).intersection(set(phrases2))
                    union = set(phrases1).union(set(phrases2))
                    
                    # Calculate Jaccard similarity
                    if union:
                        similarity = len(intersection) / len(union)
                        
                        # Add edge if similarity is above threshold
                        if similarity > 0.2:  # Arbitrary threshold
                            G.add_edge(
                                f"rule_{rule_id1}", 
                                f"rule_{rule_id2}", 
                                type="semantic", 
                                weight=similarity
                            )

    def _init_llm(self):
        """Initialize the language model"""
        try:
            return Anthropic(api_key=ANTHROPIC_API_KEY)
        except Exception as e:
            logger.error(f"Error initializing LLM: {e}")
            # Return None as fallback, we'll handle this in the query methods
            return None

    def _init_response_chain(self):
        """Initialize the response generation chain"""
        if not self.llm:
            return None
        
        prompt_template = """
        You are an advanced intelligence assistant for RAW (Research and Analysis Wing) agents.
        You must format responses according to the specific instructions for each query type.
        
        AGENT LEVEL: {agent_level}
        QUERY: {query}
        MATCHED RULE: {matched_rule}
        RESPONSE INSTRUCTION: {response_instruction}
        
        If a specific response text is provided, use it exactly. Otherwise, generate a response
        following the response instruction, keeping in mind the agent's clearance level.
        
        Remember:
        - Level 1 agents receive basic, instructional responses
        - Level 2 agents receive tactical, direct responses
        - Level 3 agents receive analytical, multi-layered responses
        - Level 4 agents receive coded language with essential confirmations
        - Level 5 agents receive vague, layered responses, sometimes as counter-questions
        
        Your response:
        """
        
        prompt = PromptTemplate(
            input_variables=["agent_level", "query", "matched_rule", "response_instruction"],
            template=prompt_template
        )
        
        return LLMChain(llm=self.llm, prompt=prompt)

    def get_agent_greeting(self, agent_level: int) -> str:
        """Get the appropriate greeting for an agent based on their level"""
        greetings = {
            1: "Salute, Shadow Cadet.",
            2: "Bonjour, Sentinel.",
            3: "Eyes open, Phantom.",
            4: "In the wind, Commander.",
            5: "The unseen hand moves, Whisper."
        }
        
        return greetings.get(agent_level, "Greetings, Agent.")

    def vector_search(self, query: str, agent_level: int) -> List[RuleMatch]:
        """Search for relevant rules using vector similarity"""
        try:
            # Perform vector search
            docs_and_scores = self.vector_store.similarity_search_with_score(query, k=TOP_K_VECTOR)
            
            # Process results
            matches = []
            for doc, score in docs_and_scores:
                rule_id = doc.metadata.get("rule_id")
                
                # Find the full rule
                rule = next((r for r in self.rules if r["id"] == rule_id), None)
                if not rule:
                    continue
                
                # Check clearance level
                required_level = rule.get("required_level")
                if required_level != "any" and int(required_level) > agent_level:
                    continue
                
                # Convert score to similarity (FAISS returns distance, not similarity)
                similarity = 1.0 / (1.0 + score)
                
                matches.append(
                    RuleMatch(
                        rule_id=rule_id,
                        trigger_phrases=rule.get("trigger_phrases", []),
                        required_level=required_level,
                        response_instruction=rule.get("response_instruction", ""),
                        response_text=rule.get("response_text", ""),
                        match_score=similarity,
                        match_method="vector"
                    )
                )
            
            # Sort by score
            matches.sort(key=lambda x: x.match_score, reverse=True)
            return matches
        except Exception as e:
            logger.error(f"Error in vector search: {e}")
            return []

    def graph_search(self, query: str, agent_level: int) -> List[RuleMatch]:
        """Search for relevant rules using graph traversal"""
        try:
            # Tokenize query into potential trigger phrases
            tokens = query.lower().split()
            bigrams = [' '.join(tokens[i:i+2]) for i in range(len(tokens)-1)]
            trigrams = [' '.join(tokens[i:i+3]) for i in range(len(tokens)-2)]
            
            potential_phrases = tokens + bigrams + trigrams
            
            # Find matches in the graph
            matched_phrase_nodes = []
            for phrase in potential_phrases:
                # Look for exact or partial matches
                for node, attrs in self.knowledge_graph.nodes(data=True):
                    if attrs.get("type") == "phrase":
                        node_text = attrs.get("text", "").lower()
                        if phrase in node_text or node_text in phrase:
                            matched_phrase_nodes.append(node)
            
            # Traverse graph to find connected rules
            rule_scores = {}
            for phrase_node in matched_phrase_nodes:
                # Get all rules connected to this phrase
                for rule_node in self.knowledge_graph.successors(phrase_node):
                    if not rule_node.startswith("rule_"):
                        continue
                    
                    # Extract rule ID from node name
                    rule_id = int(rule_node.split("_")[1])
                    
                    # Check clearance level
                    rule = next((r for r in self.rules if r["id"] == rule_id), None)
                    if not rule:
                        continue
                    
                    required_level = rule.get("required_level")
                    if required_level != "any" and int(required_level) > agent_level:
                        continue
                    
                    # Increment score for this rule
                    if rule_id not in rule_scores:
                        rule_scores[rule_id] = 0
                    rule_scores[rule_id] += 1
            
            # Find additional related rules
            related_rules = set()
            for rule_id in rule_scores.keys():
                rule_node = f"rule_{rule_id}"
                
                # Get rules related to matched rules
                for related_node in self.knowledge_graph.successors(rule_node):
                    if related_node.startswith("rule_"):
                        related_id = int(related_node.split("_")[1])
                        related_rules.add(related_id)
                
                # Also get rules that point to matched rules
                for predecessor in self.knowledge_graph.predecessors(rule_node):
                    if predecessor.startswith("rule_"):
                        pred_id = int(predecessor.split("_")[1])
                        related_rules.add(pred_id)
            
            # Add related rules with lower scores
            for related_id in related_rules:
                if related_id not in rule_scores:
                    rule = next((r for r in self.rules if r["id"] == related_id), None)
                    if not rule:
                        continue
                    
                    required_level = rule.get("required_level")
                    if required_level != "any" and int(required_level) > agent_level:
                        continue
                    
                    rule_scores[related_id] = 0.5  # Lower score for related rules
            
            # Convert scores to matches
            matches = []
            for rule_id, score in rule_scores.items():
                rule = next((r for r in self.rules if r["id"] == rule_id), None)
                if not rule:
                    continue
                
                # Normalize score to 0-1 range
                normalized_score = min(score / 3.0, 1.0)  # Cap at 1.0
                
                matches.append(
                    RuleMatch(
                        rule_id=rule_id,
                        trigger_phrases=rule.get("trigger_phrases", []),
                        required_level=rule.get("required_level"),
                        response_instruction=rule.get("response_instruction", ""),
                        response_text=rule.get("response_text", ""),
                        match_score=normalized_score,
                        match_method="graph"
                    )
                )
            
            # Sort by score
            matches.sort(key=lambda x: x.match_score, reverse=True)
            return matches[:TOP_K_GRAPH]
        except Exception as e:
            logger.error(f"Error in graph search: {e}")
            return []

    def keyword_search(self, query: str, agent_level: int) -> List[RuleMatch]:
        """Simple keyword search as a fallback method"""
        try:
            matches = []
            query_lower = query.lower()
            
            for rule in self.rules:
                # Check if any trigger phrase is in the query
                for phrase in rule.get("trigger_phrases", []):
                    phrase_lower = phrase.lower()
                    if phrase_lower in query_lower:
                        # Check clearance level
                        required_level = rule.get("required_level")
                        if required_level != "any" and int(required_level) > agent_level:
                            continue
                        
                        # Calculate a simple score based on exact match
                        score = len(phrase) / len(query) if len(query) > 0 else 0
                        
                        matches.append(
                            RuleMatch(
                                rule_id=rule["id"],
                                trigger_phrases=rule.get("trigger_phrases", []),
                                required_level=required_level,
                                response_instruction=rule.get("response_instruction", ""),
                                response_text=rule.get("response_text", ""),
                                match_score=score,
                                match_method="keyword"
                            )
                        )
                        break  # Only match a rule once
            
            # Sort by score
            matches.sort(key=lambda x: x.match_score, reverse=True)
            return matches
        except Exception as e:
            logger.error(f"Error in keyword search: {e}")
            return []

    def hybrid_search(self, query: str, agent_level: int) -> Tuple[List[RuleMatch], str]:
        """Combine multiple search methods for best results"""
        try:
            # Get results from each method
            vector_matches = self.vector_search(query, agent_level)
            graph_matches = self.graph_search(query, agent_level)
            
            # Start with empty results if primary methods fail
            if not vector_matches and not graph_matches:
                keyword_matches = self.keyword_search(query, agent_level)
                if keyword_matches:
                    return keyword_matches, "keyword"
                return [], "no_match"
            
            # Hybrid scoring approach
            rule_scores = {}
            
            # Process vector matches
            for match in vector_matches:
                rule_id = match.rule_id
                if rule_id not in rule_scores:
                    rule_scores[rule_id] = {"match": match, "score": 0, "methods": []}
                
                # Add vector score with higher weight (0.7)
                rule_scores[rule_id]["score"] += match.match_score * 0.7
                rule_scores[rule_id]["methods"].append("vector")
            
            # Process graph matches
            for match in graph_matches:
                rule_id = match.rule_id
                if rule_id not in rule_scores:
                    rule_scores[rule_id] = {"match": match, "score": 0, "methods": []}
                
                # Add graph score with lower weight (0.3)
                rule_scores[rule_id]["score"] += match.match_score * 0.3
                rule_scores[rule_id]["methods"].append("graph")
            
            # Convert back to list of matches with combined scores
            hybrid_matches = []
            for rule_id, data in rule_scores.items():
                match = data["match"]
                
                # Create a new match with hybrid method and combined score
                hybrid_match = RuleMatch(
                    rule_id=match.rule_id,
                    trigger_phrases=match.trigger_phrases,
                    required_level=match.required_level,
                    response_instruction=match.response_instruction,
                    response_text=match.response_text,
                    match_score=data["score"],
                    match_method="hybrid"
                )
                
                hybrid_matches.append(hybrid_match)
            
            # Sort by combined score
            hybrid_matches.sort(key=lambda x: x.match_score, reverse=True)
            
            search_method = "hybrid"
            if hybrid_matches and len(rule_scores[hybrid_matches[0].rule_id]["methods"]) == 1:
                # If the top match came from only one method, report that method
                search_method = rule_scores[hybrid_matches[0].rule_id]["methods"][0]
            
            return hybrid_matches, search_method
        except Exception as e:
            logger.error(f"Error in hybrid search: {e}")
            # Fall back to keyword search
            keyword_matches = self.keyword_search(query, agent_level)
            return keyword_matches, "keyword_fallback"

    def generate_response(self, query: str, agent_level: int, rule_match: Optional[RuleMatch]) -> str:
        """Generate a response based on the matched rule"""
        try:
            # If no match found, return a generic response
            if not rule_match:
                return "No matching information found in the database."
            
            # If rule has a direct response text, use it
            if rule_match.response_text:
                return rule_match.response_text
            
            # Otherwise, use LLM to generate response based on instruction
            if self.response_chain:
                response = self.response_chain.run(
                    agent_level=agent_level,
                    query=query,
                    matched_rule=f"Rule {rule_match.rule_id}: {', '.join(rule_match.trigger_phrases)}",
                    response_instruction=rule_match.response_instruction
                )
                return response
            
            # Fallback if LLM chain is not available
            return f"Following instruction: {rule_match.response_instruction}"
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return "Error generating response. Please try again later."

    def process_query(self, query_request: QueryRequest) -> QueryResponse:
        """Process a query and generate a response"""
        start_time = time.time()
        query_id = str(uuid.uuid4())
        
        try:
            # Log query
            self._log_query(
                query_id=query_id,
                agent_id=query_request.agent_id,
                agent_level=query_request.agent_level,
                query_text=query_request.query_text
            )
            
            # Perform hybrid search
            matches, search_method = self.hybrid_search(
                query=query_request.query_text,
                agent_level=query_request.agent_level
            )
            
            # Get the top match
            top_match = matches[0] if matches else None
            
            # Generate greeting
            greeting = self.get_agent_greeting(query_request.agent_level)
            
            # Generate response
            response_text = self.generate_response(
                query=query_request.query_text,
                agent_level=query_request.agent_level,
                rule_match=top_match
            )
            
            # Calculate query time
            query_time_ms = (time.time() - start_time) * 1000
            
            # Create response
            response = QueryResponse(
                rule_match=top_match,
                response_text=response_text,
                greeting=greeting,
                matched_sources=[f"Rule {m.rule_id}" for m in matches[:3]] if matches else [],
                search_strategy=search_method,
                query_time_ms=query_time_ms,
                query_id=query_id
            )
            
            # Log successful query
            self._log_query_success(
                query_id=query_id,
                agent_id=query_request.agent_id,
                matched_rule_id=top_match.rule_id if top_match else None,
                search_method=search_method,
                query_time_ms=query_time_ms
            )
            
            return response
        except Exception as e:
            query_time_ms = (time.time() - start_time) * 1000
            logger.error(f"Error processing query: {e}")
            
            # Log query error
            self._log_query_error(
                query_id=query_id,
                agent_id=query_request.agent_id,
                error=str(e),
                query_time_ms=query_time_ms
            )
            
            # Return fallback response
            greeting = self.get_agent_greeting(query_request.agent_level)
            return QueryResponse(
                response_text="I'm unable to process your query at this time. Please try again later.",
                greeting=greeting,
                search_strategy="error",
                query_time_ms=query_time_ms,
                query_id=query_id
            )

    def _log_query(self, query_id: str, agent_id: str, agent_level: int, query_text: str):
        """Log incoming query"""
        log_entry = SecurityLog(
            event_type="query_received",
            agent_id=agent_id,
            query_id=query_id,
            details={
                "query_text": query_text,
                "agent_level": agent_level
            }
        )
        
        logger.info(f"Query received: {query_id} - Agent: {agent_id} (L{agent_level}) - '{query_text}'")

    def _log_query_success(self, query_id: str, agent_id: str, matched_rule_id: Optional[int], 
                          search_method: str, query_time_ms: float):
        """Log successful query processing"""
        log_entry = SecurityLog(
            event_type="query_processed",
            agent_id=agent_id,
            query_id=query_id,
            details={
                "matched_rule_id": matched_rule_id,
                "search_method": search_method,
                "query_time_ms": query_time_ms
            }
        )
        
        logger.info(
            f"Query processed: {query_id} - Agent: {agent_id} - "
            f"Rule: {matched_rule_id or 'none'} - Method: {search_method} - "
            f"Time: {query_time_ms:.2f}ms"
        )

    def _log_query_error(self, query_id: str, agent_id: str, error: str, query_time_ms: float):
        """Log query processing error"""
        log_entry = SecurityLog(
            event_type="query_error",
            agent_id=agent_id,
            query_id=query_id,
            details={
                "error": error,
                "query_time_ms": query_time_ms
            },
            severity="error"
        )
        
        logger.error(f"Query error: {query_id} - Agent: {agent_id} - Error: {error}")

# Initialize the RAG system
rag_system = AdvancedRAG()

# API Endpoints
@app.post("/query", response_model=QueryResponse)
async def process_query(
    query_request: QueryRequest,
    api_key: bool = Depends(verify_api_key)
):
    """Process a query and return a response"""
    return rag_system.process_query(query_request)

@app.get("/rules/{rule_id}")
async def get_rule(
    rule_id: int,
    agent_level: int,
    api_key: bool = Depends(verify_api_key)
):
    """Get a specific rule if agent has appropriate clearance"""
    # Find the rule
    rule = next((r for r in rag_system.rules if r["id"] == rule_id), None)
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    # Check clearance level
    required_level = rule.get("required_level")
    if required_level != "any" and int(required_level) > agent_level:
        # Return a restricted view with minimal information
        return {
            "id": rule_id,
            "message": "Access denied. You don't have sufficient clearance to view this rule.",
            "required_level": required_level
        }
    
    # Return rule if agent has sufficient clearance
    return rule

@app.get("/related-rules/{rule_id}")
async def get_related_rules(
    rule_id: int,
    agent_level: int,
    api_key: bool = Depends(verify_api_key)
):
    """Get rules related to a specific rule"""
    # Check if rule exists
    rule = next((r for r in rag_system.rules if r["id"] == rule_id), None)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    # Get related rules from knowledge graph
    try:
        rule_node = f"rule_{rule_id}"
        related_rules = []
        
        if rule_node in rag_system.knowledge_graph:
            # Get successors (outgoing connections)
            for successor in rag_system.knowledge_graph.successors(rule_node):
                if successor.startswith("rule_"):
                    related_id = int(successor.split("_")[1])
                    related_rule = next((r for r in rag_system.rules if r["id"] == related_id), None)
                    
                    if related_rule:
                        # Check clearance level
                        required_level = related_rule.get("required_level")
                        if required_level == "any" or int(required_level) <= agent_level:
                            related_rules.append({
                                "id": related_id,
                                "trigger_phrases": related_rule.get("trigger_phrases", []),
                                "relation_type": "outgoing"
                            })
            
            # Get predecessors (incoming connections)
            for predecessor in rag_system.knowledge_graph.predecessors(rule_node):
                if predecessor.startswith("rule_"):
                    related_id = int(predecessor.split("_")[1])
                    related_rule = next((r for r in rag_system.rules if r["id"] == related_id), None)
                    
                    if related_rule:
                        # Check clearance level
                        required_level = related_rule.get("required_level")
                        if required_level == "any" or int(required_level) <= agent_level:
                            related_rules.append({
                                "id": related_id,
                                "trigger_phrases": related_rule.get("trigger_phrases", []),
                                "relation_type": "incoming"
                            })
        
        return {"rule_id": rule_id, "related_rules": related_rules}
    except Exception as e:
        logger.error(f"Error getting related rules: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving related rules"
        )

@app.get("/search")
async def semantic_search(
    query: str,
    agent_level: int,
    search_type: str = "hybrid",
    top_k: int = 5,
    api_key: bool = Depends(verify_api_key)
):
    """Search rules using vector, graph, or hybrid methods"""
    if search_type == "vector":
        matches = rag_system.vector_search(query, agent_level)
    elif search_type == "graph":
        matches = rag_system.graph_search(query, agent_level)
    elif search_type == "keyword":
        matches = rag_system.keyword_search(query, agent_level)
    else:  # Default to hybrid
        matches, _ = rag_system.hybrid_search(query, agent_level)
    
    # Limit to top_k
    matches = matches[:top_k]
    
    # Convert to response format
    results = []
    for match in matches:
        results.append({
            "rule_id": match.rule_id,
            "trigger_phrases": match.trigger_phrases,
            "required_level": match.required_level,
            "match_score": match.match_score,
            "match_method": match.match_method
        })
    
    return {"query": query, "search_type": search_type, "results": results}

@app.post("/update-vector-store")
async def update_vector_store(
    background_tasks: BackgroundTasks,
    api_key: bool = Depends(verify_api_key)
):
    """Update the vector store with the latest rules"""
    background_tasks.add_task(rag_system._init_vector_store)
    return {"status": "success", "message": "Vector store update started"}

@app.post("/update-knowledge-graph")
async def update_knowledge_graph(
    background_tasks: BackgroundTasks,
    api_key: bool = Depends(verify_api_key)
):
    """Update the knowledge graph with the latest rules"""
    background_tasks.add_task(rag_system._init_knowledge_graph)
    return {"status": "success", "message": "Knowledge graph update started"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check if RAG components are initialized
        vector_store_health = rag_system.vector_store is not None
        knowledge_graph_health = rag_system.knowledge_graph is not None
        llm_health = rag_system.llm is not None
        
        # Get component sizes
        rule_count = len(rag_system.rules)
        node_count = len(rag_system.knowledge_graph.nodes) if knowledge_graph_health else 0
        edge_count = len(rag_system.knowledge_graph.edges) if knowledge_graph_health else 0
        
        health_status = "healthy"
        if not vector_store_health or not knowledge_graph_health:
            health_status = "degraded"
        
        return {
            "status": health_status,
            "components": {
                "vector_store": vector_store_health,
                "knowledge_graph": knowledge_graph_health,
                "llm": llm_health
            },
            "stats": {
                "rule_count": rule_count,
                "knowledge_graph_nodes": node_count,
                "knowledge_graph_edges": edge_count
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment or use default
    port = int(os.getenv("PORT", 8003))
    
    # Configure uvicorn server
    uvicorn.run(
        "advanced_rag_layer:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("ENVIRONMENT") != "production",
        log_level="info"
    )