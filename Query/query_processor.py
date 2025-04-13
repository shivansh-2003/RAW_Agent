# query_processor.py

import os
import time
import json
import logging
import uuid
import httpx
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator

# Local imports
from nlp_engine import NLPEngine
from rules_matcher import RulesMatcher
from level_checker import ClearanceLevelChecker

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("query_processor.log")
    ]
)
logger = logging.getLogger("shadow_query_processor")

# Initialize FastAPI app
app = FastAPI(
    title="SHADOW Query Processor",
    description="Core query processing service for Project SHADOW",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
RULES_FILE_PATH = os.getenv("RULES_FILE_PATH", "data.json")
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "internal_service_key")
SECURITY_SERVICE_URL = os.getenv("SECURITY_SERVICE_URL", "http://security-service:8003")
RESPONSE_GEN_URL = os.getenv("RESPONSE_GEN_URL", "http://response-generator:8004")
SESSION_SERVICE_URL = os.getenv("SESSION_SERVICE_URL", "http://session-service:8002")

# Initialize API key header for service-to-service auth
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

# Initialize core components
nlp_engine = NLPEngine()
rules_matcher = RulesMatcher(rules_file_path=RULES_FILE_PATH)
level_checker = ClearanceLevelChecker()

# API key verification for internal services
async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != INTERNAL_API_KEY:
        logger.warning(f"Invalid API key attempt: {api_key[:5]}...")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return True

# Data models
class QueryRequest(BaseModel):
    """Agent query request"""
    query_text: str
    agent_id: str
    agent_level: int
    session_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('agent_level')
    def validate_agent_level(cls, v):
        if v not in range(1, 6):
            raise ValueError('Agent level must be between 1 and 5')
        return v

class RuleMatch(BaseModel):
    """Rule match result"""
    rule_id: int
    trigger_phrases: List[str]
    required_level: Union[int, str]
    response_instruction: str
    response_text: Optional[str] = None
    match_score: float
    match_method: str  # "vector", "graph", "keyword", "hybrid"

class ProcessedQueryResult(BaseModel):
    """Result of query processing"""
    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    agent_level: int
    original_query: str
    processed_query: str
    matched_rules: List[RuleMatch]
    selected_rule_id: Optional[int] = None
    processing_time_ms: float
    nlp_analysis: Dict[str, Any]
    security_flags: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class QueryResponse(BaseModel):
    """Final response to agent query"""
    query_id: str
    greeting: str
    response_text: str
    matched_rule_id: Optional[int] = None
    processing_time_ms: float

# Processing functions
async def process_query(request: QueryRequest) -> ProcessedQueryResult:
    """Process an agent query from start to finish"""
    start_time = time.time()
    
    # Generate a unique query ID
    query_id = str(uuid.uuid4())
    
    try:
        # 1. Run the query through the NLP Engine
        nlp_result = nlp_engine.analyze_query(
            query_text=request.query_text,
            agent_id=request.agent_id,
            agent_level=request.agent_level
        )
        
        processed_query = nlp_result["processed_query"]
        extracted_entities = nlp_result["entities"]
        intents = nlp_result["intents"]
        
        # 2. Find matching rules with the Rules Matcher
        rule_matches = rules_matcher.find_matching_rules(
            query_text=processed_query,
            extracted_entities=extracted_entities,
            intents=intents
        )
        
        # 3. Check clearance levels with Level Checker
        filtered_matches = level_checker.filter_by_clearance(
            rule_matches=rule_matches,
            agent_level=request.agent_level
        )
        
        # 4. Check for security concerns or anomalies
        security_flags = []
        
        # Check for clearance escalation attempts
        for match in rule_matches:
            if match not in filtered_matches:
                # This rule was filtered out due to insufficient clearance
                security_flags.append("clearance_escalation_attempt")
                break
        
        # 5. Select the best matching rule
        selected_rule = None
        selected_rule_id = None
        
        if filtered_matches:
            # Sort by match score
            filtered_matches.sort(key=lambda x: x.match_score, reverse=True)
            selected_rule = filtered_matches[0]
            selected_rule_id = selected_rule.rule_id
        
        # 6. Check for special time-based or conditional rules
        current_hour = datetime.utcnow().hour
        # Example: Rule 31 (Facility X-17) should return weather report after 2 AM UTC
        if selected_rule_id == 31 and current_hour >= 2 and current_hour < 4:
            # Flag this for the Response Generator to handle
            if "time_conditional" not in security_flags:
                security_flags.append("time_conditional")
        
        # Calculate processing time
        processing_time_ms = (time.time() - start_time) * 1000
        
        # Log security flags if any
        if security_flags:
            logger.warning(f"Security flags raised for query {query_id}: {security_flags}")
            
            # Optional: Report to security service
            await report_security_flags(
                query_id=query_id,
                agent_id=request.agent_id,
                agent_level=request.agent_level,
                flags=security_flags,
                query_text=request.query_text
            )
        
        # Construct the result
        result = ProcessedQueryResult(
            query_id=query_id,
            agent_id=request.agent_id,
            agent_level=request.agent_level,
            original_query=request.query_text,
            processed_query=processed_query,
            matched_rules=filtered_matches,
            selected_rule_id=selected_rule_id,
            processing_time_ms=processing_time_ms,
            nlp_analysis={
                "entities": extracted_entities,
                "intents": intents,
                "query_complexity": nlp_result.get("complexity", "medium")
            },
            security_flags=security_flags
        )
        
        return result
    
    except Exception as e:
        logger.error(f"Error processing query: {e}")
        
        # Return a minimal result with error flag
        return ProcessedQueryResult(
            query_id=query_id,
            agent_id=request.agent_id,
            agent_level=request.agent_level,
            original_query=request.query_text,
            processed_query=request.query_text,
            matched_rules=[],
            selected_rule_id=None,
            processing_time_ms=(time.time() - start_time) * 1000,
            nlp_analysis={},
            security_flags=["processing_error"]
        )

async def report_security_flags(
    query_id: str,
    agent_id: str,
    agent_level: int,
    flags: List[str],
    query_text: str
) -> None:
    """Report security flags to the security monitoring service"""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{SECURITY_SERVICE_URL}/report-security-flags",
                headers={"X-API-Key": INTERNAL_API_KEY},
                json={
                    "query_id": query_id,
                    "agent_id": agent_id,
                    "agent_level": agent_level,
                    "flags": flags,
                    "query_text": query_text,
                    "timestamp": datetime.utcnow().isoformat()
                },
                timeout=2.0
            )
    except Exception as e:
        logger.error(f"Error reporting security flags: {e}")

async def update_session_activity(session_id: str) -> bool:
    """Update session activity timestamp"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{SESSION_SERVICE_URL}/sessions/{session_id}",
                headers={"X-API-Key": INTERNAL_API_KEY},
                json={"extend_expiry": True},
                timeout=2.0
            )
            return response.status_code == 200
    except Exception as e:
        logger.error(f"Error updating session activity: {e}")
        return False

async def generate_response(result: ProcessedQueryResult) -> QueryResponse:
    """Call the Response Generator service to create the final response"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{RESPONSE_GEN_URL}/generate",
                headers={"X-API-Key": INTERNAL_API_KEY},
                json={
                    "query_id": result.query_id,
                    "agent_id": result.agent_id,
                    "agent_level": result.agent_level,
                    "query_text": result.original_query,
                    "matched_rule_id": result.selected_rule_id,
                    "security_flags": result.security_flags,
                    "processing_time_ms": result.processing_time_ms
                },
                timeout=5.0
            )
            
            if response.status_code == 200:
                return QueryResponse(**response.json())
            else:
                # Handle error by generating a fallback response
                logger.error(f"Error from Response Generator: {response.status_code}")
                return QueryResponse(
                    query_id=result.query_id,
                    greeting=get_default_greeting(result.agent_level),
                    response_text="I'm unable to process your request at this time.",
                    matched_rule_id=None,
                    processing_time_ms=result.processing_time_ms
                )
    except Exception as e:
        logger.error(f"Error calling Response Generator: {e}")
        return QueryResponse(
            query_id=result.query_id,
            greeting=get_default_greeting(result.agent_level),
            response_text="I'm unable to process your request at this time.",
            matched_rule_id=None,
            processing_time_ms=result.processing_time_ms
        )

def get_default_greeting(agent_level: int) -> str:
    """Get default greeting based on agent level"""
    greetings = {
        1: "Salute, Shadow Cadet.",
        2: "Bonjour, Sentinel.",
        3: "Eyes open, Phantom.",
        4: "In the wind, Commander.",
        5: "The unseen hand moves, Whisper."
    }
    return greetings.get(agent_level, "Greetings, Agent.")

# API Endpoints
@app.post("/process", response_model=ProcessedQueryResult)
async def process_query_endpoint(
    request: QueryRequest,
    background_tasks: BackgroundTasks,
    api_key: bool = Depends(verify_api_key)
):
    """Process a query and return the processing result"""
    # Update session activity in the background
    background_tasks.add_task(update_session_activity, request.session_id)
    
    # Process the query
    result = await process_query(request)
    
    return result

@app.post("/query", response_model=QueryResponse)
async def query_endpoint(
    request: QueryRequest,
    background_tasks: BackgroundTasks,
    api_key: bool = Depends(verify_api_key)
):
    """Process a query and generate a response"""
    # Update session activity in the background
    background_tasks.add_task(update_session_activity, request.session_id)
    
    # Process the query
    result = await process_query(request)
    
    # Generate response
    response = await generate_response(result)
    
    return response

@app.get("/rules/{rule_id}")
async def get_rule(rule_id: int, agent_level: int, api_key: bool = Depends(verify_api_key)):
    """Get information about a specific rule"""
    rule = rules_matcher.get_rule_by_id(rule_id)
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    
    # Check clearance level
    if level_checker.has_clearance(rule, agent_level):
        # Return full rule info
        return rule
    else:
        # Return limited info
        return {
            "id": rule_id,
            "message": "Access denied. Insufficient clearance level.",
            "required_level": rule.get("required_level")
        }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Check Rules Matcher initialization
    rules_loaded = len(rules_matcher.rules) > 0
    
    return {
        "status": "healthy" if rules_loaded else "degraded",
        "components": {
            "nlp_engine": True,
            "rules_matcher": rules_loaded,
            "level_checker": True
        },
        "rules_count": len(rules_matcher.rules),
        "timestamp": datetime.utcnow().isoformat()
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    logger.info("Query Processor starting up")
    
    # Log the number of rules loaded
    logger.info(f"Loaded {len(rules_matcher.rules)} rules")

if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment or use default
    port = int(os.getenv("PORT", 8003))
    
    # Configure uvicorn server
    uvicorn.run(
        "query_processor:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("ENVIRONMENT") != "production",
        log_level="info"
    )