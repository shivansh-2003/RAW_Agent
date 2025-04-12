# main.py - Project SHADOW API

import os
import time
import json
import uuid
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import components
from shadow_rag_integration import ShadowRAGIntegration, QueryRequest, QueryResponse
from mosaic_anomaly_detection import MosaicAnomalyDetection, QueryEvent, AnomalyDetectionResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("shadow_api.log")
    ]
)
logger = logging.getLogger("shadow_api")

# Configuration
RULES_FILE_PATH = os.getenv("RULES_FILE_PATH", "data.json")
VECTOR_STORE_PATH = os.getenv("VECTOR_STORE_PATH", "./vector_store")
GRAPH_DB_PATH = os.getenv("GRAPH_DB_PATH", "./graph_store")
EVENT_HISTORY_FILE = os.getenv("EVENT_HISTORY_FILE", "./data/event_history.json")
API_KEY = os.getenv("API_KEY", "super-secret-api-key")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8001")
SESSION_SERVICE_URL = os.getenv("SESSION_SERVICE_URL", "http://localhost:8002")

# Create FastAPI application
app = FastAPI(
    title="Project SHADOW API",
    description="Intelligence Retrieval System for RAW Agents",
    version="1.0.0",
    docs_url="/docs" if os.getenv("ENVIRONMENT") != "production" else None
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API key verification
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != API_KEY:
        logger.warning(f"Invalid API key attempt: {api_key[:5]}...")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return True

# Define models
class AgentAuthRequest(BaseModel):
    """Agent authentication request"""
    agent_id: str
    clearance_level: int
    credentials: Dict[str, Any]

class AgentAuthResponse(BaseModel):
    """Agent authentication response"""
    agent_id: str
    clearance_level: int
    session_id: str
    token: str
    greeting: str
    expires_at: str

class AgentQueryRequest(BaseModel):
    """Agent query request"""
    query_text: str
    agent_id: str
    agent_level: int
    session_id: str
    neural_verification_data: Optional[str] = None
    
    @validator('agent_level')
    def validate_agent_level(cls, v):
        if v not in range(1, 6):
            raise ValueError('Agent level must be between 1 and 5')
        return v

class AgentQueryResponse(BaseModel):
    """Agent query response"""
    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    greeting: str
    response_text: str
    matched_rule_id: Optional[int] = None
    security_level: str = "standard"
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AnomayDetectionResponse(BaseModel):
    """Anomaly detection response"""
    is_anomalous: bool
    anomaly_score: float
    anomaly_types: List[str]
    details: Dict[str, Any]
    action_required: bool = False
    recommended_actions: List[str] = Field(default_factory=list)

class SystemStatusResponse(BaseModel):
    """System status response"""
    rag_status: Dict[str, Any]
    anomaly_detection_status: Dict[str, Any]
    system_health: str
    active_sessions: int = 0
    current_load: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# Initialize components
rag_integration = ShadowRAGIntegration()
anomaly_detector = MosaicAnomalyDetection(
    rules_file_path=RULES_FILE_PATH,
    event_history_file=EVENT_HISTORY_FILE
)

@app.post("/auth/login", response_model=AgentAuthResponse)
async def agent_login(request: AgentAuthRequest, api_key: bool = Depends(verify_api_key)):
    """Agent login and authentication"""
    try:
        # In a real implementation, this would call the Authentication Service
        # For now, we'll just create a fake session
        agent_id = request.agent_id
        clearance_level = request.clearance_level
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Generate fake token
        token = f"shadow-token-{agent_id}-{int(time.time())}"
        
        # Get agent greeting
        agent_greetings = {
            1: "Salute, Shadow Cadet.",
            2: "Bonjour, Sentinel.",
            3: "Eyes open, Phantom.",
            4: "In the wind, Commander.",
            5: "The unseen hand moves, Whisper."
        }
        greeting = agent_greetings.get(clearance_level, "Greetings, Agent.")
        
        # Set expiration (30 minutes from now)
        expires_at = (datetime.utcnow() + datetime.timedelta(minutes=30)).isoformat()
        
        # Log successful login
        logger.info(f"Agent {agent_id} (Level {clearance_level}) logged in with session {session_id}")
        
        return AgentAuthResponse(
            agent_id=agent_id,
            clearance_level=clearance_level,
            session_id=session_id,
            token=token,
            greeting=greeting,
            expires_at=expires_at
        )
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}"
        )

@app.post("/agent/query", response_model=AgentQueryResponse)
async def process_agent_query(
    request: AgentQueryRequest,
    background_tasks: BackgroundTasks,
    api_key: bool = Depends(verify_api_key)
):
    """Process an agent query"""
    try:
        start_time = time.time()
        
        # Prepare RAG query request
        rag_request = QueryRequest(
            query_text=request.query_text,
            agent_id=request.agent_id,
            agent_level=request.agent_level,
            session_id=request.session_id,
            metadata={
                "ip_address": request.client.host if hasattr(request, 'client') else None,
                "user_agent": request.headers.get("User-Agent") if hasattr(request, 'headers') else None,
                "neural_verification": bool(request.neural_verification_data)
            }
        )
        
        # Process query with RAG system
        rag_response = rag_integration.process_query(rag_request)
        
        # Create query event for anomaly detection
        event = QueryEvent(
            query_id=rag_response.query_id,
            agent_id=request.agent_id,
            query_text=request.query_text,
            agent_level=request.agent_level,
            timestamp=datetime.utcnow(),
            matched_rule_id=rag_response.matched_rule_id,
            rule_required_level=None,  # Will be filled in background task
            session_id=request.session_id,
            ip_address=request.client.host if hasattr(request, 'client') else None,
            user_agent=request.headers.get("User-Agent") if hasattr(request, 'headers') else None
        )
        
        # Run anomaly detection in background
        background_tasks.add_task(process_anomalies, event)
        
        # Return response
        return AgentQueryResponse(
            query_id=rag_response.query_id,
            greeting=rag_response.greeting,
            response_text=rag_response.response_text,
            matched_rule_id=rag_response.matched_rule_id,
            security_level=rag_response.security_level
        )
        
    except Exception as e:
        logger.error(f"Query processing error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing query: {str(e)}"
        )

@app.get("/security/anomalies/{query_id}", response_model=AnomayDetectionResponse)
async def get_anomaly_detection(
    query_id: str,
    api_key: bool = Depends(verify_api_key)
):
    """Get anomaly detection results for a query"""
    # In a real implementation, this would retrieve results from a database
    # For now, we'll just return dummy data
    return {
        "is_anomalous": False,
        "anomaly_score": 0.1,
        "anomaly_types": [],
        "details": {},
        "action_required": False,
        "recommended_actions": []
    }

@app.get("/security/agent/{agent_id}/risk", response_model=Dict[str, Any])
async def get_agent_risk_profile(
    agent_id: str,
    api_key: bool = Depends(verify_api_key)
):
    """Get risk profile for an agent"""
    try:
        profile = anomaly_detector.get_agent_risk_profile(agent_id)
        return profile
    except Exception as e:
        logger.error(f"Error retrieving agent risk profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving risk profile: {str(e)}"
        )

@app.get("/security/system/risk", response_model=Dict[str, Any])
async def get_system_risk_assessment(
    api_key: bool = Depends(verify_api_key)
):
    """Get system-wide risk assessment"""
    try:
        assessment = anomaly_detector.get_system_risk_assessment()
        return assessment
    except Exception as e:
        logger.error(f"Error retrieving system risk assessment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving risk assessment: {str(e)}"
        )

@app.get("/system/status", response_model=SystemStatusResponse)
async def get_system_status(
    api_key: bool = Depends(verify_api_key)
):
    """Get system status information"""
    try:
        # Get RAG system status
        rag_status = rag_integration.get_system_status()
        
        # Get anomaly detection status
        anomaly_detection_status = {
            "event_count": len(anomaly_detector.event_history),
            "agent_count": len(anomaly_detector.agent_history),
            "sensitive_rule_sets": len(anomaly_detector.sensitive_rule_sets)
        }
        
        # Determine system health
        system_health = "healthy"
        if not rag_status.system_ready:
            system_health = "degraded"
        
        # Get active sessions count (dummy value for now)
        active_sessions = 10
        
        # Calculate current load (dummy value for now)
        current_load = 0.5
        
        return SystemStatusResponse(
            rag_status=rag_status.dict(),
            anomaly_detection_status=anomaly_detection_status,
            system_health=system_health,
            active_sessions=active_sessions,
            current_load=current_load
        )
    except Exception as e:
        logger.error(f"Error retrieving system status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving system status: {str(e)}"
        )

@app.post("/system/update")
async def update_system_components(
    background_tasks: BackgroundTasks,
    api_key: bool = Depends(verify_api_key)
):
    """Update all system components"""
    background_tasks.add_task(update_all_components)
    return {"status": "success", "message": "System update started in the background"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

# Background tasks
async def process_anomalies(event: QueryEvent):
    """Process anomalies for a query event"""
    try:
        # If we have a matched rule, get its required level
        if event.matched_rule_id is not None:
            rule = next((r for r in rag_integration.rules if r["id"] == event.matched_rule_id), None)
            if rule and rule.get("required_level") != "any":
                event.rule_required_level = int(rule.get("required_level"))
        
        # Detect anomalies
        result = anomaly_detector.detect_anomalies_for_event(event)
        
        # Log results
        if result.is_anomalous:
            logger.warning(
                f"Anomaly detected for agent {event.agent_id} (Level {event.agent_level}): "
                f"Score {result.anomaly_score}, Types: {result.anomaly_types}"
            )
            
            # If critical anomaly, take action
            if result.anomaly_score > 0.8:
                logger.critical(
                    f"CRITICAL ANOMALY for agent {event.agent_id}: "
                    f"{', '.join(result.anomaly_types)}"
                )
                # In a real implementation, this would trigger additional security measures
        
        # Save the detection result (in a real implementation)
        # Here we would store the result in a database
    
    except Exception as e:
        logger.error(f"Error processing anomalies: {e}")

async def update_all_components():
    """Update all system components"""
    try:
        # Update RAG components
        rag_integration.update_components()
        
        # No need to update anomaly detector, it works with the same rules file
        
        logger.info("All system components updated successfully")
    except Exception as e:
        logger.error(f"Error updating system components: {e}")

# Main entry point
if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment or use default
    port = int(os.getenv("PORT", 8000))
    
    # Configure uvicorn server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("ENVIRONMENT") == "development",
        log_level="info"
    )