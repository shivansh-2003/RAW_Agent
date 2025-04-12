# shadow_rag_integration.py

import os
import time
import json
import logging
import argparse
import uuid
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import RAG components
from vector_store_builder import VectorStoreBuilder
from knowledge_graph_builder import KnowledgeGraphBuilder
from hybrid_retrieval_engine import HybridRetrievalEngine, RetrievalContext, RuleMatch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("shadow_rag.log")
    ]
)
logger = logging.getLogger("shadow_rag_integration")

# Configuration
RULES_FILE_PATH = os.getenv("RULES_FILE_PATH", "data.json")
VECTOR_STORE_PATH = os.getenv("VECTOR_STORE_PATH", "./vector_store")
GRAPH_DB_PATH = os.getenv("GRAPH_DB_PATH", "./graph_store")
GRAPH_FILE_PATH = os.getenv("GRAPH_FILE_PATH", f"{GRAPH_DB_PATH}/graph.json")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-mpnet-base-v2")

# Data models for API
class QueryRequest(BaseModel):
    """Query request from agent"""
    query_text: str
    agent_id: str
    agent_level: int
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class QueryResponse(BaseModel):
    """Response to agent query"""
    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    greeting: str
    response_text: str
    matched_rule_id: Optional[int] = None
    rule_confidence: Optional[float] = None
    processing_time_ms: float
    security_level: str = "standard"
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class RuleInfo(BaseModel):
    """Rule information for API responses"""
    rule_id: int
    trigger_phrases: List[str]
    required_level: Union[int, str]
    response_instruction: str
    has_response_text: bool
    connections: Dict[str, int] = Field(default_factory=dict)

class RagStatusResponse(BaseModel):
    """RAG system status information"""
    vector_store: Dict[str, Any]
    knowledge_graph: Dict[str, Any]
    hybrid_retrieval: Dict[str, Any]
    system_ready: bool
    initialization_time: Optional[float] = None
    last_update: Optional[datetime] = None

class ShadowRAGIntegration:
    """
    Integration of Vector Store, Knowledge Graph, and Hybrid Retrieval
    for Project SHADOW RAG system
    """
    
    def __init__(self):
        self.rules = self._load_rules()
        self.vector_store = None
        self.knowledge_graph = None
        self.retrieval_engine = None
        self.system_ready = False
        self.initialization_time = None
        self.last_update = None
        
        # Initialize greetings by agent level
        self.agent_greetings = {
            1: "Salute, Shadow Cadet.",
            2: "Bonjour, Sentinel.",
            3: "Eyes open, Phantom.",
            4: "In the wind, Commander.",
            5: "The unseen hand moves, Whisper."
        }
        
        # Initialize components
        self._initialize_components()
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load rules from JSON file"""
        try:
            with open(RULES_FILE_PATH, 'r') as f:
                data = json.load(f)
                return data.get('rules', [])
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            return []
    
    def _initialize_components(self):
        """Initialize all RAG components"""
        start_time = time.time()
        
        try:
            # Initialize vector store builder
            vs_builder = VectorStoreBuilder(
                rules_file_path=RULES_FILE_PATH,
                vector_store_path=VECTOR_STORE_PATH,
                embedding_model=EMBEDDING_MODEL
            )
            
            # Load or build vector store
            if not vs_builder.load_existing_vector_store():
                logger.info("Building new vector store...")
                vs_builder.build_vector_store()
            
            self.vector_store = vs_builder
            
            # Initialize knowledge graph builder
            kg_builder = KnowledgeGraphBuilder(
                rules_file_path=RULES_FILE_PATH,
                graph_output_path=GRAPH_FILE_PATH,
                embedding_model=EMBEDDING_MODEL
            )
            
            # Build knowledge graph if it doesn't exist
            if not os.path.exists(GRAPH_FILE_PATH):
                logger.info("Building new knowledge graph...")
                kg_builder.build_knowledge_graph()
            
            self.knowledge_graph = kg_builder
            
            # Initialize hybrid retrieval engine
            self.retrieval_engine = HybridRetrievalEngine(
                vector_store_path=VECTOR_STORE_PATH,
                graph_db_path=GRAPH_DB_PATH,
                rules_file_path=RULES_FILE_PATH,
                embedding_dimension=768
            )
            
            self.system_ready = True
            self.initialization_time = time.time() - start_time
            self.last_update = datetime.utcnow()
            
            logger.info(f"RAG integration initialized in {self.initialization_time:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Error initializing RAG components: {e}")
            self.system_ready = False
    
    def process_query(self, request: QueryRequest) -> QueryResponse:
        """
        Process an agent query using the RAG system
        
        Args:
            request: Query request from agent
            
        Returns:
            Query response with rule match and generated text
        """
        if not self.system_ready:
            raise Exception("RAG system is not ready")
        
        start_time = time.time()
        
        try:
            # Prepare query
            query_text = request.query_text
            agent_level = request.agent_level
            
            # Check for special directives first
            special_match = self.retrieval_engine.execute_special_directive(
                query_text, 
                RetrievalContext(
                    agent_id=request.agent_id, 
                    agent_level=agent_level,
                    query_id=str(uuid.uuid4())
                )
            )
            
            if special_match:
                # Handle special directive
                processing_time = (time.time() - start_time) * 1000
                
                return QueryResponse(
                    greeting=self.agent_greetings.get(agent_level, "Greetings, Agent."),
                    response_text=special_match.response_text,
                    matched_rule_id=special_match.rule_id,
                    rule_confidence=1.0,  # Perfect confidence for special directives
                    processing_time_ms=processing_time,
                    security_level="standard"
                )
            
            # Create retrieval context
            context = RetrievalContext(
                agent_id=request.agent_id,
                agent_level=agent_level,
                session_id=request.session_id,
                query_id=str(uuid.uuid4()),
                metadata=request.metadata
            )
            
            # Enhance context with query analysis
            enhanced_context = self.retrieval_engine.enhance_retrieval_context(
                query_text=query_text,
                context=context
            )
            
            # Embed query for vector search
            query_embedding = self.vector_store.embedding_model.encode([query_text])[0]
            
            # Tokenize query for graph search
            query_tokens = query_text.lower().split()
            
            # Process query with hybrid retrieval
            matches, metadata = self.retrieval_engine.process_query(
                query_embedding=query_embedding,
                query_tokens=query_tokens,
                context=enhanced_context
            )
            
            # Get top match
            top_match = matches[0] if matches else None
            
            # Get greeting based on agent level
            greeting = self.agent_greetings.get(agent_level, "Greetings, Agent.")
            
            # Generate response text
            if top_match:
                # Use response text if available, otherwise use instruction
                if top_match.response_text:
                    response_text = top_match.response_text
                else:
                    # In a real implementation, this would use an LLM to generate a response
                    # based on the matched rule's instruction
                    response_text = f"Following instruction: {top_match.response_instruction}"
            else:
                response_text = "No matching information found."
            
            processing_time = (time.time() - start_time) * 1000
            
            # Create response
            response = QueryResponse(
                greeting=greeting,
                response_text=response_text,
                matched_rule_id=top_match.rule_id if top_match else None,
                rule_confidence=top_match.confidence if top_match else None,
                processing_time_ms=processing_time,
                security_level=enhanced_context.security_level
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error processing query: {e}")
            processing_time = (time.time() - start_time) * 1000
            
            # Return error response
            return QueryResponse(
                greeting=self.agent_greetings.get(request.agent_level, "Greetings, Agent."),
                response_text="I'm unable to process your query at this time. Please try again later.",
                processing_time_ms=processing_time,
                security_level="error"
            )
    
    def get_rule_info(self, rule_id: int, agent_level: int) -> Optional[RuleInfo]:
        """
        Get information about a specific rule
        
        Args:
            rule_id: Rule ID to retrieve
            agent_level: Agent's clearance level
            
        Returns:
            Rule information if found and authorized
        """
        # Find the rule
        rule = next((r for r in self.rules if r["id"] == rule_id), None)
        if not rule:
            return None
        
        # Check clearance level
        required_level = rule.get("required_level")
        if required_level != "any" and int(required_level) > agent_level:
            # Return limited info for unauthorized access
            return RuleInfo(
                rule_id=rule_id,
                trigger_phrases=[],
                required_level=required_level,
                response_instruction="Access denied. Insufficient clearance level.",
                has_response_text=False,
                connections={}
            )
        
        # Get connections from knowledge graph
        connections = {}
        rule_node = f"rule_{rule_id}"
        
        if hasattr(self.knowledge_graph, "knowledge_graph"):
            graph = self.knowledge_graph.knowledge_graph
            
            if rule_node in graph:
                # Count incoming connections
                in_edges = graph.in_edges(rule_node)
                in_types = {}
                for u, _ in in_edges:
                    edge_type = graph.edges[u, rule_node].get('type', 'unknown')
                    if edge_type not in in_types:
                        in_types[edge_type] = 0
                    in_types[edge_type] += 1
                
                connections["incoming"] = in_types
                
                # Count outgoing connections
                out_edges = graph.out_edges(rule_node)
                out_types = {}
                for _, v in out_edges:
                    edge_type = graph.edges[rule_node, v].get('type', 'unknown')
                    if edge_type not in out_types:
                        out_types[edge_type] = 0
                    out_types[edge_type] += 1
                
                connections["outgoing"] = out_types
        
        # Create rule info
        return RuleInfo(
            rule_id=rule_id,
            trigger_phrases=rule.get("trigger_phrases", []),
            required_level=required_level,
            response_instruction=rule.get("response_instruction", ""),
            has_response_text=bool(rule.get("response_text")),
            connections=connections
        )
    
    def get_system_status(self) -> RagStatusResponse:
        """Get RAG system status information"""
        vector_store_status = {
            "initialized": self.vector_store is not None,
            "vector_count": self.vector_store.index.ntotal if self.vector_store and hasattr(self.vector_store, "index") else 0,
            "document_count": len(self.vector_store.document_store) if self.vector_store and hasattr(self.vector_store, "document_store") else 0,
            "embedding_model": self.vector_store.embedding_model_name if self.vector_store else "not initialized"
        }
        
        knowledge_graph_status = {
            "initialized": self.knowledge_graph is not None,
            "node_count": len(self.knowledge_graph.knowledge_graph.nodes) if self.knowledge_graph and hasattr(self.knowledge_graph, "knowledge_graph") else 0,
            "edge_count": len(self.knowledge_graph.knowledge_graph.edges) if self.knowledge_graph and hasattr(self.knowledge_graph, "knowledge_graph") else 0,
            "embedding_model": self.knowledge_graph.embedding_model_name if self.knowledge_graph else "not initialized"
        }
        
        hybrid_retrieval_status = {
            "initialized": self.retrieval_engine is not None,
            "vector_similarity_threshold": self.retrieval_engine.vector_similarity_threshold if self.retrieval_engine else 0,
            "graph_depth_limit": self.retrieval_engine.graph_depth_limit if self.retrieval_engine else 0,
            "fallback_to_keyword": self.retrieval_engine.fallback_to_keyword if self.retrieval_engine else False
        }
        
        return RagStatusResponse(
            vector_store=vector_store_status,
            knowledge_graph=knowledge_graph_status,
            hybrid_retrieval=hybrid_retrieval_status,
            system_ready=self.system_ready,
            initialization_time=self.initialization_time,
            last_update=self.last_update
        )
    
    def update_components(self) -> bool:
        """Update all RAG components with latest rules"""
        try:
            # Reload rules
            self.rules = self._load_rules()
            
            # Update vector store
            if self.vector_store:
                self.vector_store.update_vector_store(self.rules)
            
            # Rebuild knowledge graph
            if self.knowledge_graph:
                self.knowledge_graph.build_knowledge_graph()
            
            # Re-initialize retrieval engine
            self.retrieval_engine = HybridRetrievalEngine(
                vector_store_path=VECTOR_STORE_PATH,
                graph_db_path=GRAPH_DB_PATH,
                rules_file_path=RULES_FILE_PATH,
                embedding_dimension=768
            )
            
            self.last_update = datetime.utcnow()
            
            logger.info("RAG components updated successfully")
            return True
        except Exception as e:
            logger.error(f"Error updating RAG components: {e}")
            return False

# Create FastAPI application
app = FastAPI(
    title="Project SHADOW RAG Integration",
    description="Advanced RAG integration for Project SHADOW",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize RAG integration
rag_integration = ShadowRAGIntegration()

@app.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    """Process an agent query"""
    if not rag_integration.system_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RAG system is initializing. Please try again later."
        )
    
    try:
        return rag_integration.process_query(request)
    except Exception as e:
        logger.error(f"Error processing query: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing query: {str(e)}"
        )

@app.get("/rules/{rule_id}", response_model=RuleInfo)
async def get_rule_info(rule_id: int, agent_level: int):
    """Get information about a specific rule"""
    if not rag_integration.system_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RAG system is initializing. Please try again later."
        )
    
    rule_info = rag_integration.get_rule_info(rule_id, agent_level)
    if not rule_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id} not found"
        )
    
    return rule_info

@app.get("/status", response_model=RagStatusResponse)
async def get_system_status():
    """Get RAG system status information"""
    return rag_integration.get_system_status()

@app.post("/update")
async def update_rag_components(background_tasks: BackgroundTasks):
    """Update RAG components with latest rules"""
    background_tasks.add_task(rag_integration.update_components)
    return {"status": "success", "message": "RAG components update started in the background"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy" if rag_integration.system_ready else "initializing",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

# Command-line interface for testing
def cli_test():
    """Command-line interface for testing RAG components"""
    parser = argparse.ArgumentParser(description="Project SHADOW RAG Testing CLI")
    parser.add_argument("--query", type=str, help="Query to test")
    parser.add_argument("--level", type=int, default=3, help="Agent clearance level (1-5)")
    parser.add_argument("--agent-id", type=str, default="test_agent", help="Agent ID")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if not args.query:
        # Interactive mode
        print("Project SHADOW RAG Testing CLI")
        print("==============================")
        print(f"System status: {'Ready' if rag_integration.system_ready else 'Initializing'}")
        
        while True:
            query = input("\nEnter query (or 'exit' to quit): ")
            if query.lower() in ["exit", "quit", "q"]:
                break
            
            agent_level = args.level
            
            # Process query
            request = QueryRequest(
                query_text=query,
                agent_id=args.agent_id,
                agent_level=agent_level
            )
            
            try:
                response = rag_integration.process_query(request)
                
                print(f"\n{response.greeting}")
                print(response.response_text)
                
                if args.verbose:
                    print(f"\nMatched Rule: {response.matched_rule_id}")
                    print(f"Confidence: {response.rule_confidence:.2f}")
                    print(f"Processing Time: {response.processing_time_ms:.2f} ms")
                    print(f"Security Level: {response.security_level}")
            
            except Exception as e:
                print(f"Error: {e}")
    
    else:
        # Single query mode
        request = QueryRequest(
            query_text=args.query,
            agent_id=args.agent_id,
            agent_level=args.level
        )
        
        try:
            response = rag_integration.process_query(request)
            
            print(f"\n{response.greeting}")
            print(response.response_text)
            
            if args.verbose:
                print(f"\nMatched Rule: {response.matched_rule_id}")
                print(f"Confidence: {response.rule_confidence:.2f}")
                print(f"Processing Time: {response.processing_time_ms:.2f} ms")
                print(f"Security Level: {response.security_level}")
        
        except Exception as e:
            print(f"Error: {e}")

# Main entry point
if __name__ == "__main__":
    # Check if running as CLI or web service
    import sys
    
    if len(sys.argv) > 1:
        # Run as CLI tool
        cli_test()
    else:
        # Run web service
        import uvicorn
        uvicorn.run(
            "shadow_rag_integration:app",
            host="0.0.0.0",
            port=8080,
            reload=False
        )