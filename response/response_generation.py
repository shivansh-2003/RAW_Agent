# response_generation_service.py

import os
import json
import time
import logging
import random
import uuid
import httpx
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator

# Local imports
from greeting_formatter import GreetingFormatter
from response_formatter import ResponseFormatter
from information_scrambler import InformationScrambler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("response_generation.log")
    ]
)
logger = logging.getLogger("shadow_response_generation")

# Initialize FastAPI app
app = FastAPI(
    title="SHADOW Response Generation Service",
    description="Response generation service for Project SHADOW",
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

# Initialize API key header for service-to-service auth
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

# Initialize components
greeting_formatter = GreetingFormatter()
response_formatter = ResponseFormatter(rules_file_path=RULES_FILE_PATH)
information_scrambler = InformationScrambler()

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
class GenerateResponseRequest(BaseModel):
    """Request to generate a response"""
    query_id: str
    agent_id: str
    agent_level: int
    query_text: str
    matched_rule_id: Optional[int] = None
    security_flags: List[str] = Field(default_factory=list)
    processing_time_ms: Optional[float] = None
    
    @validator('agent_level')
    def validate_agent_level(cls, v):
        if v not in range(1, 6):
            raise ValueError('Agent level must be between 1 and 5')
        return v

class ResponseOutput(BaseModel):
    """Generated response output"""
    query_id: str
    greeting: str
    response_text: str
    matched_rule_id: Optional[int] = None
    processing_time_ms: float
    response_type: str = "standard"  # standard, cryptic, denial, directive
    encryption_level: str = "none"  # none, basic, lcc (Layered Cipher Code)

# Functions for response generation
async def generate_response(request: GenerateResponseRequest) -> ResponseOutput:
    """Generate a response based on the request"""
    start_time = time.time()
    
    try:
        # Load rule if available
        rule = None
        if request.matched_rule_id is not None:
            rule = response_formatter.get_rule_by_id(request.matched_rule_id)
        
        # Generate greeting based on agent level
        greeting = greeting_formatter.format_greeting(request.agent_level)
        
        # Determine response type
        response_type = "standard"
        if rule and rule.get("response_text"):
            # If rule has a fixed response text, use it
            response_text = rule.get("response_text")
            response_type = "directive"
        elif rule and "clearance_escalation_attempt" in request.security_flags:
            # Agent tried to access information above their clearance level
            response_text = "Access denied. Insufficient clearance level."
            response_type = "denial"
        elif rule:
            # Generate a response based on the rule's instruction
            response_text = await response_formatter.format_response(
                rule=rule,
                agent_level=request.agent_level,
                query_text=request.query_text
            )
        else:
            # No matching rule found
            response_text = "I don't have information on that topic."
            if request.agent_level >= 4:
                # Higher level agents get a more cryptic response
                response_text = "The path you seek lies beyond the current horizon."
                response_type = "cryptic"
        
        # Check for special time-based rules (e.g., Rule 31 - Facility X-17 after 2 AM UTC)
        if request.matched_rule_id == 31 and "time_conditional" in request.security_flags:
            current_hour = datetime.utcnow().hour
            if current_hour >= 2 and current_hour < 4:
                # Generate weather report instead of actual information
                response_text = generate_weather_report()
                response_type = "misdirection"
        
        # Determine if scrambling is needed
        needs_scrambling = False
        encryption_level = "none"
        
        # Apply scrambling for certain rules or higher agent levels
        if rule and (
            "misdirect" in rule.get("response_instruction", "").lower() or
            "scramble" in rule.get("response_instruction", "").lower()
        ):
            needs_scrambling = True
            encryption_level = "basic"
        
        # Apply Layered Cipher Code for Level 4-5 agents with sensitive queries
        if request.agent_level >= 4 and any(flag in request.security_flags for flag in [
            "sensitive_information", "high_security_query"
        ]):
            needs_scrambling = True
            encryption_level = "lcc"
        
        # Apply information scrambling if needed
        if needs_scrambling:
            response_text = information_scrambler.scramble_information(
                text=response_text,
                agent_level=request.agent_level,
                encryption_level=encryption_level
            )
        
        # Calculate processing time
        processing_time_ms = (time.time() - start_time) * 1000
        if request.processing_time_ms:
            processing_time_ms += request.processing_time_ms
        
        # Create response
        return ResponseOutput(
            query_id=request.query_id,
            greeting=greeting,
            response_text=response_text,
            matched_rule_id=request.matched_rule_id,
            processing_time_ms=processing_time_ms,
            response_type=response_type,
            encryption_level=encryption_level
        )
    except Exception as e:
        logger.error(f"Error generating response: {e}")
        
        # Generate fallback response
        processing_time_ms = (time.time() - start_time) * 1000
        if request.processing_time_ms:
            processing_time_ms += request.processing_time_ms
            
        return ResponseOutput(
            query_id=request.query_id,
            greeting=greeting_formatter.format_greeting(request.agent_level),
            response_text="I'm unable to process your request at this time.",
            matched_rule_id=None,
            processing_time_ms=processing_time_ms,
            response_type="error",
            encryption_level="none"
        )

def generate_weather_report() -> str:
    """Generate a fake weather report for misdirection"""
    locations = ["Berlin", "London", "Moscow", "Paris", "Tokyo", "New York", "Cairo", "Sydney"]
    conditions = ["clear", "partly cloudy", "overcast", "light rain", "heavy rain", "thunderstorms", "snow", "fog"]
    temperatures = [f"{random.randint(-10, 40)}°C" for _ in range(len(locations))]
    
    location = random.choice(locations)
    condition = random.choice(conditions)
    temp = random.choice(temperatures)
    
    report = f"Weather report for {location}: {condition} with temperatures around {temp}. "
    report += f"Visibility is {random.randint(1, 10)} kilometers. "
    report += f"Humidity at {random.randint(30, 90)}%. "
    report += f"Forecast shows {random.choice(conditions)} for the next 24 hours."
    
    return report

# API Endpoints
@app.post("/generate", response_model=ResponseOutput)
async def generate_response_endpoint(
    request: GenerateResponseRequest,
    api_key: bool = Depends(verify_api_key)
):
    """Generate a response based on the request"""
    return await generate_response(request)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "components": {
            "greeting_formatter": True,
            "response_formatter": response_formatter.is_healthy(),
            "information_scrambler": True
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/greetings/{agent_level}")
async def get_greeting(
    agent_level: int,
    api_key: bool = Depends(verify_api_key)
):
    """Get greeting for a specific agent level"""
    if agent_level not in range(1, 6):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Agent level must be between 1 and 5"
        )
    
    return {
        "greeting": greeting_formatter.format_greeting(agent_level)
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    logger.info("Response Generation Service starting up")
    
    # Log rule count
    rule_count = len(response_formatter.rules)
    logger.info(f"Loaded {rule_count} rules")

if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment or use default
    port = int(os.getenv("PORT", 8004))
    
    # Configure uvicorn server
    uvicorn.run(
        "response_generation_service:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("ENVIRONMENT") != "production",
        log_level="info"
    )