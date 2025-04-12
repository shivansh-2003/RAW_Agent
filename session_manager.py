# session_manager.py

import os
import time
import redis
import logging
import uuid
import json
import asyncio
import httpx
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, Request, status, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("session_manager.log")
    ]
)
logger = logging.getLogger("shadow_session_manager")

# Initialize FastAPI app
app = FastAPI(
    title="SHADOW Session Manager",
    description="Advanced session management for Project SHADOW",
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

# Initialize Redis for session storage
try:
    redis_client = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        db=0,
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5
    )
    # Test connection
    redis_client.ping()
    logger.info("Successfully connected to Redis")
except redis.ConnectionError as e:
    logger.error(f"Failed to connect to Redis: {e}")
    redis_client = None

# Configuration
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://authentication-service:8001")
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", 30))
SESSION_CLEANUP_INTERVAL = int(os.getenv("SESSION_CLEANUP_INTERVAL", 60))  # seconds
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "internal_service_key")
MAX_SESSIONS_PER_AGENT = {
    1: 1,  # Level 1 agents can only have 1 active session
    2: 2,  # Level 2 agents can have 2 active sessions
    3: 3,  # Level 3 agents can have 3 active sessions
    4: 5,  # Level 4 agents can have 5 active sessions
    5: 10  # Level 5 agents can have 10 active sessions
}

# Define API key security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

# Models
class Session(BaseModel):
    session_id: str
    agent_id: str
    clearance_level: int
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SessionCreate(BaseModel):
    agent_id: str
    clearance_level: int
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('clearance_level')
    def validate_clearance_level(cls, v):
        if v not in range(1, 6):
            raise ValueError('Clearance level must be between 1 and 5')
        return v

class SessionUpdate(BaseModel):
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    metadata: Optional[Dict[str, Any]] = None
    extend_expiry: bool = False

class SessionStats(BaseModel):
    total_active_sessions: int
    sessions_by_clearance: Dict[str, int]
    total_agents_online: int
    avg_session_duration_minutes: float = 0
    most_active_agent_counts: Dict[str, int] = Field(default_factory=dict)

class SecurityLog(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "info"  # info, warning, error, critical
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# API Key verification
async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != INTERNAL_API_KEY:
        logger.warning(f"Invalid API key attempt: {api_key[:5]}...")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return True

# Helper functions
def log_security_event(
    event_type: str,
    details: Dict[str, Any] = {},
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    severity: str = "info"
) -> None:
    """Log security events"""
    event = SecurityLog(
        event_type=event_type,
        agent_id=agent_id,
        session_id=session_id,
        details=details,
        severity=severity
    )
    
    # Log to application logger
    log_message = f"{event.event_type} - Agent: {agent_id or 'unknown'} - Session: {session_id or 'none'}"
    
    if severity == "info":
        logger.info(log_message)
    elif severity == "warning":
        logger.warning(log_message)
    elif severity == "error":
        logger.error(log_message)
    elif severity == "critical":
        logger.critical(log_message)
    
    # In production, would also store in database

# Session management functions
def create_session(
    agent_id: str,
    clearance_level: int,
    ip_address: str,
    user_agent: str,
    metadata: Dict[str, Any] = {}
) -> Optional[Session]:
    """Create a new session for an agent"""
    if not redis_client:
        logger.error("Cannot create session: Redis connection not available")
        return None
        
    # Check if agent already has maximum allowed sessions
    active_sessions = get_active_sessions_for_agent(agent_id)
    max_sessions = MAX_SESSIONS_PER_AGENT.get(clearance_level, 1)
    
    if len(active_sessions) >= max_sessions:
        # If max sessions reached, terminate the oldest session
        if active_sessions:
            active_sessions.sort(key=lambda s: s.last_activity)
            oldest_session = active_sessions[0]
            terminate_session(oldest_session.session_id)
            log_security_event(
                event_type="session_auto_terminated",
                details={"reason": "max_sessions_reached", "new_session_ip": ip_address},
                agent_id=agent_id,
                session_id=oldest_session.session_id,
                severity="info"
            )
    
    try:
        # Create new session
        session_id = str(uuid.uuid4())
        created_at = datetime.utcnow()
        expires_at = created_at + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        
        session = Session(
            session_id=session_id,
            agent_id=agent_id,
            clearance_level=clearance_level,
            created_at=created_at,
            expires_at=expires_at,
            last_activity=created_at,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata
        )
        
        # Store session in Redis
        session_key = f"session:{session_id}"
        session_data = session.dict()
        
        # Convert datetime objects to ISO format for Redis storage
        session_data["created_at"] = session_data["created_at"].isoformat()
        session_data["expires_at"] = session_data["expires_at"].isoformat()
        session_data["last_activity"] = session_data["last_activity"].isoformat()
        
        # Convert metadata to JSON string if it's a dict
        if isinstance(session_data["metadata"], dict):
            session_data["metadata"] = json.dumps(session_data["metadata"])
        
        # Store the session
        redis_client.hset(session_key, mapping=session_data)
        redis_client.expire(session_key, int(timedelta(minutes=SESSION_TIMEOUT_MINUTES).total_seconds()))
        
        # Add to agent sessions index
        redis_client.sadd(f"agent_sessions:{agent_id}", session_id)
        
        # Add to clearance level index
        redis_client.sadd(f"clearance_sessions:{clearance_level}", session_id)
        
        # Log session creation
        log_security_event(
            event_type="session_created",
            details={"ip_address": ip_address, "expires_at": expires_at.isoformat()},
            agent_id=agent_id,
            session_id=session_id,
            severity="info"
        )
        
        return session
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return None

def get_session(session_id: str) -> Optional[Session]:
    """Get a session by ID"""
    if not redis_client:
        logger.error(f"Cannot get session: Redis connection not available")
        return None
        
    try:
        session_key = f"session:{session_id}"
        session_data = redis_client.hgetall(session_key)
        
        if not session_data:
            return None
        
        # Convert string timestamps back to datetime
        session_data["created_at"] = datetime.fromisoformat(session_data["created_at"])
        session_data["expires_at"] = datetime.fromisoformat(session_data["expires_at"])
        session_data["last_activity"] = datetime.fromisoformat(session_data["last_activity"])
        
        # Convert string boolean to actual boolean
        session_data["is_active"] = session_data["is_active"].lower() == "true"
        
        # Convert clearance level to integer
        session_data["clearance_level"] = int(session_data["clearance_level"])
        
        # Convert metadata from string to dict if it exists
        if "metadata" in session_data and isinstance(session_data["metadata"], str):
            try:
                session_data["metadata"] = json.loads(session_data["metadata"])
            except:
                session_data["metadata"] = {}
        
        # Check if session is expired
        if session_data["expires_at"] < datetime.utcnow():
            # Session is expired but still in Redis, mark it as inactive
            session_data["is_active"] = False
        
        return Session(**session_data)
    except Exception as e:
        logger.error(f"Error retrieving session {session_id}: {e}")
        return None

def update_session(session_id: str, updates: SessionUpdate) -> Optional[Session]:
    """Update a session with new data"""
    if not redis_client:
        logger.error(f"Cannot update session: Redis connection not available")
        return None
        
    try:
        session = get_session(session_id)
        if not session:
            return None
        
        # Don't update expired or inactive sessions
        if not session.is_active or session.expires_at < datetime.utcnow():
            logger.warning(f"Attempted to update inactive/expired session {session_id}")
            return None
        
        # Update the session with new data
        session_key = f"session:{session_id}"
        
        update_data = {}
        
        # Update last activity timestamp
        update_data["last_activity"] = updates.last_activity.isoformat()
        
        # Update metadata if provided
        if updates.metadata is not None:
            # Merge existing metadata with new metadata
            merged_metadata = {**session.metadata, **updates.metadata}
            update_data["metadata"] = json.dumps(merged_metadata)
        
        # Update Redis
        redis_client.hset(session_key, mapping=update_data)
        
        # Extend expiry if requested
        if updates.extend_expiry:
            new_expiry = datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
            redis_client.hset(session_key, "expires_at", new_expiry.isoformat())
            redis_client.expire(session_key, int(timedelta(minutes=SESSION_TIMEOUT_MINUTES).total_seconds()))
        else:
            # Reset expiration to remaining time
            remaining_seconds = max(0, int((session.expires_at - datetime.utcnow()).total_seconds()))
            if remaining_seconds > 0:
                redis_client.expire(session_key, remaining_seconds)
        
        # Return updated session
        return get_session(session_id)
    except Exception as e:
        logger.error(f"Error updating session {session_id}: {e}")
        return None

def terminate_session(session_id: str) -> bool:
    """Terminate a session"""
    if not redis_client:
        logger.error(f"Cannot terminate session: Redis connection not available")
        return False
        
    try:
        session = get_session(session_id)
        if not session:
            return False
        
        # Get session data
        session_key = f"session:{session_id}"
        agent_id = session.agent_id
        clearance_level = session.clearance_level
        
        # Remove session from Redis
        redis_client.delete(session_key)
        
        # Remove from agent sessions index
        redis_client.srem(f"agent_sessions:{agent_id}", session_id)
        
        # Remove from clearance level index
        redis_client.srem(f"clearance_sessions:{clearance_level}", session_id)
        
        # Log session termination
        log_security_event(
            event_type="session_terminated",
            agent_id=agent_id,
            session_id=session_id,
            severity="info"
        )
        
        return True
    except Exception as e:
        logger.error(f"Error terminating session {session_id}: {e}")
        return False

def get_active_sessions_for_agent(agent_id: str) -> List[Session]:
    """Get all active sessions for an agent"""
    if not redis_client:
        logger.error(f"Cannot get sessions: Redis connection not available")
        return []
        
    try:
        sessions = []
        
        # Get session IDs for the agent
        session_ids = redis_client.smembers(f"agent_sessions:{agent_id}")
        
        for session_id in session_ids:
            session = get_session(session_id)
            if session and session.is_active:
                sessions.append(session)
        
        return sessions
    except Exception as e:
        logger.error(f"Error retrieving sessions for agent {agent_id}: {e}")
        return []

def get_sessions_by_clearance_level(clearance_level: int) -> List[Session]:
    """Get all active sessions for a given clearance level"""
    if not redis_client:
        logger.error(f"Cannot get sessions: Redis connection not available")
        return []
        
    try:
        sessions = []
        
        # Get session IDs for the clearance level
        session_ids = redis_client.smembers(f"clearance_sessions:{clearance_level}")
        
        for session_id in session_ids:
            session = get_session(session_id)
            if session and session.is_active:
                sessions.append(session)
        
        return sessions
    except Exception as e:
        logger.error(f"Error retrieving sessions for clearance level {clearance_level}: {e}")
        return []

def get_session_stats() -> SessionStats:
    """Get session statistics"""
    if not redis_client:
        logger.error(f"Cannot get session stats: Redis connection not available")
        return SessionStats(
            total_active_sessions=0,
            sessions_by_clearance={},
            total_agents_online=0
        )
        
    try:
        # Collect stats by clearance level
        sessions_by_clearance = {}
        unique_agents = set()
        total_active = 0
        all_sessions = []
        agent_session_counts = {}
        
        for level in range(1, 6):  # Levels 1-5
            sessions = get_sessions_by_clearance_level(level)
            sessions_by_clearance[str(level)] = len(sessions)
            total_active += len(sessions)
            all_sessions.extend(sessions)
            
            for session in sessions:
                unique_agents.add(session.agent_id)
                # Count sessions per agent
                if session.agent_id not in agent_session_counts:
                    agent_session_counts[session.agent_id] = 0
                agent_session_counts[session.agent_id] += 1
        
        # Calculate average session duration
        now = datetime.utcnow()
        session_durations = []
        for session in all_sessions:
            duration_minutes = (now - session.created_at).total_seconds() / 60
            session_durations.append(duration_minutes)
        
        avg_duration = 0
        if session_durations:
            avg_duration = sum(session_durations) / len(session_durations)
        
        # Get top 5 agents with most sessions
        most_active_agents = {}
        if agent_session_counts:
            sorted_agents = sorted(agent_session_counts.items(), key=lambda x: x[1], reverse=True)
            top_agents = sorted_agents[:5]
            most_active_agents = dict(top_agents)
        
        return SessionStats(
            total_active_sessions=total_active,
            sessions_by_clearance=sessions_by_clearance,
            total_agents_online=len(unique_agents),
            avg_session_duration_minutes=round(avg_duration, 2),
            most_active_agent_counts=most_active_agents
        )
    except Exception as e:
        logger.error(f"Error generating session stats: {e}")
        return SessionStats(
            total_active_sessions=0,
            sessions_by_clearance={},
            total_agents_online=0
        )

async def cleanup_expired_sessions():
    """Clean up expired sessions"""
    if not redis_client:
        logger.error(f"Cannot clean up sessions: Redis connection not available")
        return
        
    try:
        now = datetime.utcnow()
        expiry_count = 0
        
        # Scan all session keys
        cursor = 0
        while True:
            cursor, keys = redis_client.scan(cursor, match="session:*", count=100)
            
            for key in keys:
                # Get expiration time
                session_data = redis_client.hgetall(key)
                if not session_data or "expires_at" not in session_data:
                    continue
                
                # Parse expiration time
                try:
                    expires_at = datetime.fromisoformat(session_data["expires_at"])
                    agent_id = session_data.get("agent_id")
                    session_id = key.split(":", 1)[1]
                    
                    # Check if expired
                    if expires_at < now:
                        # Extract session ID from key
                        terminate_session(session_id)
                        expiry_count += 1
                        
                        if agent_id:
                            log_security_event(
                                event_type="session_expired",
                                agent_id=agent_id,
                                session_id=session_id,
                                severity="info"
                            )
                except (ValueError, KeyError):
                    # Handle invalid data
                    continue
            
            if cursor == 0:
                break
        
        if expiry_count > 0:
            logger.info(f"Cleaned up {expiry_count} expired sessions")
    except Exception as e:
        logger.error(f"Error in session cleanup: {e}")

async def verify_session_neural_signature(session_id: str, neural_signature_data: str) -> bool:
    """
    Verify a neural signature during an active session
    Used for high-security operations that require re-verification
    """
    if not redis_client:
        logger.error(f"Cannot verify neural signature: Redis connection not available")
        return False
        
    try:
        session = get_session(session_id)
        if not session:
            return False
        
        # Only relevant for high-level agents
        if session.clearance_level < 5:
            return True  # Low-level agents don't need neural signature
        
        # Create security context
        security_context = {
            "clearance_level": session.clearance_level,
            "risk_level": "medium",  # Could be dynamic based on operation type
            "session_verification": True,
            "session_id": session_id,
            "ip_address": session.ip_address
        }
        
        # Call the authentication service to verify
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{AUTH_SERVICE_URL}/neural-signatures/verify/{session.agent_id}",
                    json={
                        "neural_signature_data": neural_signature_data,
                        "security_context": security_context
                    },
                    headers={"X-API-Key": INTERNAL_API_KEY},
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    verified = result.get("verified", False)
                    
                    # Log the verification result
                    log_security_event(
                        event_type="neural_signature_verification",
                        details={
                            "result": "success" if verified else "failed",
                            "verification_type": "session"
                        },
                        agent_id=session.agent_id,
                        session_id=session_id,
                        severity="info" if verified else "warning"
                    )
                    
                    return verified
                else:
                    logger.error(f"Error response from auth service: {response.status_code} - {response.text}")
                    return False
            except Exception as e:
                logger.error(f"Error verifying session neural signature: {e}")
                return False
    except Exception as e:
        logger.error(f"Error in neural signature verification: {e}")
        return False

# API Endpoints
@app.post("/sessions", response_model=Session)
async def create_new_session(
    session_data: SessionCreate, 
    request: Request,
    api_key: bool = Depends(verify_api_key)
):
    """Create a new session for an agent"""
    ip_address = request.client.host
    user_agent = request.headers.get("User-Agent", "Unknown")
    
    # Create the session
    session = create_session(
        agent_id=session_data.agent_id,
        clearance_level=session_data.clearance_level,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata=session_data.metadata
    )
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create session"
        )
    
    return session

@app.get("/sessions/{session_id}", response_model=Session)
async def get_session_by_id(session_id: str, api_key: bool = Depends(verify_api_key)):
    """Get a session by ID"""
    session = get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return session

@app.put("/sessions/{session_id}", response_model=Session)
async def update_session_by_id(
    session_id: str, 
    updates: SessionUpdate,
    api_key: bool = Depends(verify_api_key)
):
    """Update a session"""
    updated_session = update_session(session_id, updates)
    if not updated_session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired"
        )
    
    return updated_session

@app.delete("/sessions/{session_id}")
async def delete_session(session_id: str, api_key: bool = Depends(verify_api_key)):
    """Terminate a session"""
    success = terminate_session(session_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return {"status": "success", "message": "Session terminated"}

@app.get("/agents/{agent_id}/sessions", response_model=List[Session])
async def get_agent_sessions(agent_id: str, api_key: bool = Depends(verify_api_key)):
    """Get all active sessions for an agent"""
    sessions = get_active_sessions_for_agent(agent_id)
    return sessions

@app.delete("/agents/{agent_id}/sessions")
async def terminate_agent_sessions(agent_id: str, api_key: bool = Depends(verify_api_key)):
    """Terminate all sessions for an agent"""
    sessions = get_active_sessions_for_agent(agent_id)
    
    terminated_count = 0
    for session in sessions:
        if terminate_session(session.session_id):
            terminated_count += 1
    
    log_security_event(
        event_type="agent_sessions_terminated",
        details={"count": terminated_count},
        agent_id=agent_id,
        severity="info"
    )
    
    return {
        "status": "success",
        "message": f"Terminated {terminated_count} sessions for agent {agent_id}"
    }

@app.get("/stats", response_model=SessionStats)
async def get_stats(api_key: bool = Depends(verify_api_key)):
    """Get session statistics"""
    return get_session_stats()

@app.post("/sessions/{session_id}/verify-neural-signature")
async def verify_session_with_neural_signature(
    session_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    api_key: bool = Depends(verify_api_key)
):
    """Verify an active session with a neural signature for high-security operations"""
    # Get session
    session = get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Check if session is active
    if not session.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is not active"
        )
    
    # Only required for high-clearance agents
    if session.clearance_level < 5:
        return {"verified": True, "message": "Neural signature not required for this clearance level"}
    
    # Get neural signature data from request
    data = await request.json()
    neural_signature_data = data.get("neural_signature_data")
    
    if not neural_signature_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Neural signature data is required"
        )
    
    # Verify neural signature
    verified = await verify_session_neural_signature(session_id, neural_signature_data)
    
    if not verified:
        # Log failed verification
        log_security_event(
            event_type="neural_signature_verification_failed",
            agent_id=session.agent_id,
            session_id=session_id,
            severity="warning"
        )
        
        # In high-security environments, you might want to invalidate the session
        background_tasks.add_task(terminate_session, session_id)
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Neural signature verification failed"
        )
    
    # Update session with verification timestamp
    update_data = SessionUpdate(
        metadata={
            "last_neural_verification": datetime.utcnow().isoformat(),
            "verification_source": request.client.host
        }
    )
    
    update_session(session_id, update_data)
    
    return {
        "verified": True,
        "message": "Neural signature verified successfully"
    }

@app.post("/cleanup")
async def manual_cleanup(api_key: bool = Depends(verify_api_key)):
    """Manually trigger cleanup of expired sessions"""
    await cleanup_expired_sessions()
    return {"status": "success", "message": "Cleanup completed"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Check Redis connection
    redis_health = True
    if redis_client:
        try:
            redis_client.ping()
        except Exception as e:
            redis_health = False
            logger.error(f"Redis health check failed: {e}")
    else:
        redis_health = False
    
    # Check auth service connection
    auth_service_health = False
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{AUTH_SERVICE_URL}/health",
                timeout=2.0
            )
            auth_service_health = response.status_code == 200
    except Exception as e:
        logger.error(f"Auth service health check failed: {e}")
    
    health_status = "healthy" if redis_health and auth_service_health else "degraded" if redis_health else "unhealthy"
    
    return {
        "status": health_status,
        "redis": redis_health,
        "auth_service": auth_service_health,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

# Background task to periodically clean up expired sessions
@app.on_event("startup")
async def start_cleanup_task():
    import asyncio
    
    # Check if Redis is available
    if redis_client:
        try:
            redis_client.ping()
            logger.info("Redis connection successful")
        except redis.ConnectionError:
            logger.warning("Redis connection failed - session management will be limited")
    else:
        logger.warning("Redis client not initialized - session management will be limited")
    
    async def cleanup_task():
        while True:
            try:
                await cleanup_expired_sessions()
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
            
            await asyncio.sleep(SESSION_CLEANUP_INTERVAL)
    
    # Start the background task
    asyncio.create_task(cleanup_task())

@app.on_event("shutdown")
async def shutdown_event():
    """Run tasks when the service shuts down"""
    logger.info("Session Manager shutting down")
    
    # Close Redis connection if it exists
    if redis_client:
        redis_client.close()

if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment or use default
    port = int(os.getenv("PORT", 8002))
    
    # Configure uvicorn server
    uvicorn.run(
        "session_manager:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("ENVIRONMENT") != "production",
        log_level="info"
    )