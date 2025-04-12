# secure_gateway.py

import os
import time
import uuid
import hmac
import hashlib
import json
import jwt
import redis
import logging
import httpx
import asyncio
from typing import Dict, Optional, Tuple, List, Any, Union
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from pydantic import BaseModel, Field, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("secure_gateway.log")
    ]
)
logger = logging.getLogger("shadow_secure_gateway")

# Initialize FastAPI app
app = FastAPI(
    title="SHADOW Secure Gateway",
    description="Security gateway for Project SHADOW",
    version="1.0.0",
    docs_url="/docs" if os.getenv("ENVIRONMENT") != "production" else None
)

# Add CORS middleware if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize Redis for rate limiting and token blacklisting
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
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecretkey_change_in_production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
API_KEY_HEADER = "X-API-Key"
SIGNATURE_HEADER = "X-Signature"
TIMESTAMP_HEADER = "X-Timestamp"
NONCE_HEADER = "X-Nonce"
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "internal_service_key")
SIGNATURE_SECRET = os.getenv("SIGNATURE_SECRET", "signature_secret_key")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://authentication-service:8001")
SESSION_SERVICE_URL = os.getenv("SESSION_SERVICE_URL", "http://session-service:8002")

# Service URLs
SERVICE_ENDPOINTS = {
    "auth": AUTH_SERVICE_URL,
    "session": SESSION_SERVICE_URL,
    # Add other internal services as needed
}

# Security settings
REPLAY_PROTECTION_WINDOW = int(os.getenv("REPLAY_PROTECTION_WINDOW", 300))  # seconds
MAX_REQUEST_SIZE = int(os.getenv("MAX_REQUEST_SIZE", 1048576))  # 1MB default
STRICT_TRANSPORT_SECURITY_MAX_AGE = int(os.getenv("STRICT_TRANSPORT_SECURITY_MAX_AGE", 31536000))  # 1 year

# OAuth2 password bearer for token auth
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)

# Define models
class TokenData(BaseModel):
    agent_id: str
    clearance_level: int
    codename: str
    session_id: str
    exp: int
    iat: int
    jti: str

class RequestMetadata(BaseModel):
    client_ip: str
    user_agent: str
    timestamp: float
    path: str
    method: str
    headers: Dict[str, str]
    
class SecurityLog(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str
    agent_id: Optional[str] = None
    clearance_level: Optional[int] = None
    client_ip: str
    path: str
    method: str
    details: Dict[str, Any] = {}
    severity: str = "info"  # info, warning, error, critical

class ServiceRoutingInfo(BaseModel):
    service_name: str
    endpoint: str
    method: str
    requires_auth: bool = True
    min_clearance_level: int = 1
    rate_limit: str = "60/minute"

# Middleware for request validation and security logging
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    # Extract request metadata
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    method = request.method
    
    # Add request ID to request state for logging
    request.state.request_id = request_id
    
    # Skip validation for OPTIONS requests (CORS preflight)
    if method == "OPTIONS":
        response = await call_next(request)
        return response
    
    # Validate request size
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_SIZE:
        logger.warning(f"Request size exceeds limit: {content_length} bytes from {client_ip}")
        return Response(
            content=json.dumps({"detail": "Request too large"}),
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            media_type="application/json"
        )
    
    # Validate timestamp if provided
    timestamp_valid = True
    if TIMESTAMP_HEADER in request.headers:
        try:
            req_timestamp = float(request.headers[TIMESTAMP_HEADER])
            current_time = time.time()
            # Allow window for timestamp
            if abs(current_time - req_timestamp) > REPLAY_PROTECTION_WINDOW:
                timestamp_valid = False
                logger.warning(f"Invalid timestamp in request {request_id} from {client_ip}")
        except (ValueError, TypeError):
            timestamp_valid = False
            logger.warning(f"Malformed timestamp in request {request_id} from {client_ip}")
    
    # Validate nonce to prevent replay attacks
    nonce_valid = True
    if NONCE_HEADER in request.headers and redis_client:
        nonce = request.headers[NONCE_HEADER]
        nonce_key = f"nonce:{nonce}"
        if redis_client.exists(nonce_key):
            nonce_valid = False
            logger.warning(f"Duplicate nonce detected in request {request_id} from {client_ip}")
        else:
            # Store nonce for replay protection window to prevent reuse
            redis_client.setex(nonce_key, REPLAY_PROTECTION_WINDOW, "1")
    
    # If timestamp or nonce validation fails, reject the request
    if not timestamp_valid or not nonce_valid:
        log_security_event(
            event_type="request_validation_failed",
            client_ip=client_ip,
            path=path,
            method=method,
            details={
                "reason": "Invalid timestamp or nonce",
                "timestamp_valid": timestamp_valid,
                "nonce_valid": nonce_valid,
                "request_id": request_id
            },
            severity="warning"
        )
        return Response(
            content=json.dumps({"detail": "Request validation failed"}),
            status_code=status.HTTP_400_BAD_REQUEST,
            media_type="application/json"
        )
    
    # Process the request
    try:
        # Create a modified request with potential body reading
        response = await call_next(request)
        processing_time = time.time() - start_time
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Request-ID"] = request_id
        response.headers["Strict-Transport-Security"] = f"max-age={STRICT_TRANSPORT_SECURITY_MAX_AGE}"
        
        # Log successful request
        log_security_event(
            event_type="request_completed",
            client_ip=client_ip,
            path=path,
            method=method,
            details={
                "processing_time_ms": round(processing_time * 1000, 2), 
                "status_code": response.status_code,
                "request_id": request_id
            },
            severity="info"
        )
        
        return response
    except Exception as e:
        # Log exception
        log_security_event(
            event_type="request_exception",
            client_ip=client_ip,
            path=path,
            method=method,
            details={
                "error": str(e),
                "request_id": request_id
            },
            severity="error"
        )
        raise

# Ghost-Step Algorithm Implementation
def apply_ghost_step(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Applies the Ghost-Step Algorithm to remove digital traces
    from the data being transmitted
    """
    # Create a copy to avoid modifying the original
    sanitized_data = data.copy()
    
    # Remove or obfuscate identifying metadata
    if "metadata" in sanitized_data:
        if "user_agent" in sanitized_data["metadata"]:
            sanitized_data["metadata"]["user_agent"] = "standardized-agent"
        
        if "client_version" in sanitized_data["metadata"]:
            # Keep only major version
            parts = sanitized_data["metadata"]["client_version"].split(".")
            if len(parts) > 0:
                sanitized_data["metadata"]["client_version"] = f"{parts[0]}.0.0"
        
        # Remove any tracking identifiers
        for key in list(sanitized_data["metadata"].keys()):
            if "id" in key.lower() or "track" in key.lower() or "fingerprint" in key.lower():
                del sanitized_data["metadata"][key]
    
    # Add noise to timing information
    if "timestamp" in sanitized_data:
        # Add random noise ±500ms
        noise = (hash(str(sanitized_data)) % 1000 - 500) / 1000
        sanitized_data["timestamp"] = round(sanitized_data["timestamp"] + noise, 3)
    
    # Normalize data structures to standard formats
    # This removes unique structural signatures
    if "data" in sanitized_data and isinstance(sanitized_data["data"], dict):
        # Sort keys alphabetically
        sanitized_data["data"] = {k: sanitized_data["data"][k] for k in sorted(sanitized_data["data"].keys())}
    
    # Redact any identifying information that might be in values
    # This is a simplified example - real implementation would be more sophisticated
    if "data" in sanitized_data and isinstance(sanitized_data["data"], dict):
        for key, value in sanitized_data["data"].items():
            if isinstance(value, str) and len(value) > 100:
                # Truncate long strings to prevent data leakage
                sanitized_data["data"][key] = value[:100] + "..."
    
    # Add quantum misdirection noise fields
    sanitized_data["_q"] = int(time.time() * 1000) % 1000  # Millisecond noise
    
    return sanitized_data

# JWT Token Verification
async def verify_token(token: str = Depends(oauth2_scheme)) -> TokenData:
    """Verify JWT token and extract agent information"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode JWT token
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # Check if token is in the blacklist
        token_jti = payload.get("jti")
        if token_jti and redis_client and redis_client.exists(f"blacklist:token:{token_jti}"):
            raise credentials_exception
        
        # Extract token data
        agent_id = payload.get("agent_id")
        clearance_level = payload.get("clearance_level")
        codename = payload.get("codename")
        session_id = payload.get("session_id")
        exp = payload.get("exp")
        iat = payload.get("iat")
        jti = payload.get("jti")
        
        # Verify required fields
        if not all([agent_id, clearance_level, codename, session_id, exp, iat, jti]):
            raise credentials_exception
            
        # Create TokenData object
        token_data = TokenData(
            agent_id=agent_id,
            clearance_level=clearance_level,
            codename=codename,
            session_id=session_id,
            exp=exp,
            iat=iat,
            jti=jti
        )
        
        # Check if token is expired
        if time.time() > exp:
            raise credentials_exception
            
        # Verify session is still active by talking to the session service
        session_valid = await verify_active_session(session_id)
        if not session_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        return token_data
        
    except jwt.PyJWTError as e:
        logger.error(f"JWT verification error: {str(e)}")
        raise credentials_exception

# API Key Verification
async def verify_api_key(api_key: str = Depends(api_key_header)) -> Dict[str, Any]:
    """Verify the API key provided in the header"""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )
    
    # Check if it's the internal API key
    if api_key == INTERNAL_API_KEY:
        return {"service": "internal", "permissions": ["read", "write", "admin"]}
    
    # In a production environment, this would verify against a secure database
    # For now, we just have a simple check
    if redis_client:
        api_key_data = redis_client.hgetall(f"api_key:{api_key}")
        if api_key_data:
            return {
                "service": api_key_data.get("service", "unknown"),
                "permissions": api_key_data.get("permissions", "").split(",")
            }
    
    # Key is not valid
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )

# Request Signature Verification
async def verify_request_signature(request: Request) -> bool:
    """Verify the HMAC signature of the request"""
    signature = request.headers.get(SIGNATURE_HEADER)
    timestamp = request.headers.get(TIMESTAMP_HEADER)
    nonce = request.headers.get(NONCE_HEADER)
    
    if not all([signature, timestamp, nonce]):
        return False
    
    # Get the request body
    body = await request.body()
    
    # Compute expected signature
    # message = timestamp + nonce + body
    message = f"{timestamp}:{nonce}".encode()
    if body:
        message += b":" + body
    
    secret = SIGNATURE_SECRET.encode()
    expected_signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    
    return hmac.compare_digest(signature, expected_signature)

# Security Event Logging
def log_security_event(
    event_type: str,
    client_ip: str,
    path: str,
    method: str,
    details: Dict[str, Any] = {},
    agent_id: Optional[str] = None,
    clearance_level: Optional[int] = None,
    severity: str = "info"
) -> None:
    """Log security events for audit and monitoring"""
    log_entry = SecurityLog(
        event_type=event_type,
        agent_id=agent_id,
        clearance_level=clearance_level,
        client_ip=client_ip,
        path=path,
        method=method,
        details=details,
        severity=severity
    )
    
    # Log to application logger
    log_message = f"{log_entry.event_type} - Agent: {log_entry.agent_id or 'unknown'} - IP: {log_entry.client_ip} - Path: {log_entry.path}"
    
    if severity == "info":
        logger.info(log_message)
    elif severity == "warning":
        logger.warning(log_message)
    elif severity == "error":
        logger.error(log_message)
    elif severity == "critical":
        logger.critical(log_message)
    
    # In production, would also store in database or specialized SIEM system
    # This would be implemented with a call to a logging service

# Internal verification functions
async def verify_active_session(session_id: str) -> bool:
    """Verify that a session is still active by checking with the session service"""
    if not session_id:
        return False
        
    try:
        # Call session service to verify session
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{SESSION_SERVICE_URL}/sessions/{session_id}",
                headers={"X-API-Key": INTERNAL_API_KEY},
                timeout=2.0
            )
            
            if response.status_code == 200:
                session_data = response.json()
                # Check if session is active and not expired
                return session_data.get("is_active", False)
            
            return False
    except Exception as e:
        logger.error(f"Error verifying session: {e}")
        # Default to allowing the request if session service is down
        # This is a trade-off between availability and security
        # In a high-security environment, you might want to deny instead
        return True

async def forward_request(
    service: str,
    endpoint: str,
    method: str,
    headers: Dict[str, str],
    data: Any,
    agent_id: Optional[str] = None,
    clearance_level: Optional[int] = None
) -> Tuple[int, Dict[str, Any]]:
    """Forward a request to an internal service"""
    if service not in SERVICE_ENDPOINTS:
        return 404, {"detail": "Service not found"}
    
    service_url = SERVICE_ENDPOINTS[service]
    full_url = f"{service_url}/{endpoint}"
    
    # Copy relevant headers
    forwarded_headers = {
        "Content-Type": "application/json",
        "X-API-Key": INTERNAL_API_KEY,
        "X-Forwarded-For": headers.get("X-Forwarded-For", headers.get("Host", "unknown")),
        "X-Original-Method": method
    }
    
    # Add agent information if available
    if agent_id:
        forwarded_headers["X-Agent-ID"] = agent_id
    if clearance_level is not None:
        forwarded_headers["X-Clearance-Level"] = str(clearance_level)
    
    try:
        async with httpx.AsyncClient() as client:
            if method.upper() == "GET":
                response = await client.get(
                    full_url,
                    headers=forwarded_headers,
                    timeout=30.0
                )
            elif method.upper() == "POST":
                response = await client.post(
                    full_url,
                    headers=forwarded_headers,
                    json=data,
                    timeout=30.0
                )
            elif method.upper() == "PUT":
                response = await client.put(
                    full_url,
                    headers=forwarded_headers,
                    json=data,
                    timeout=30.0
                )
            elif method.upper() == "DELETE":
                response = await client.delete(
                    full_url,
                    headers=forwarded_headers,
                    timeout=30.0
                )
            else:
                return 405, {"detail": "Method not allowed"}
            
            # Return the response status and data
            try:
                response_data = response.json()
            except:
                response_data = {"detail": "Non-JSON response from service"}
            
            return response.status_code, response_data
    except httpx.RequestError as e:
        logger.error(f"Error forwarding request to {service}/{endpoint}: {e}")
        return 502, {"detail": f"Error communicating with internal service: {str(e)}"}

# Rate-limited endpoints
@app.get("/secure-endpoint")
@limiter.limit("5/minute")
async def secure_endpoint(
    request: Request,
    token_data: TokenData = Depends(verify_token)
):
    """Example of a secure endpoint with multiple security layers"""
    # Check agent clearance level
    if token_data.clearance_level < 3:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient clearance level"
        )
    
    # Apply Ghost-Step Algorithm to the response data
    response_data = {
        "message": "Secure data retrieved successfully",
        "timestamp": time.time(),
        "metadata": {
            "request_id": getattr(request.state, "request_id", str(uuid.uuid4())),
            "client_version": request.headers.get("User-Agent", "unknown")
        },
        "data": {
            "sensitive_value": "Protected information",
            "operation_status": "completed",
            "clearance_level": token_data.clearance_level,
            "codename": token_data.codename
        }
    }
    
    sanitized_response = apply_ghost_step(response_data)
    
    # Log the successful access
    log_security_event(
        event_type="secure_endpoint_accessed",
        client_ip=request.client.host,
        path="/secure-endpoint",
        method="GET",
        agent_id=token_data.agent_id,
        clearance_level=token_data.clearance_level,
        details={"session_id": token_data.session_id}
    )
    
    return sanitized_response

# API Proxy endpoint with clearance verification
@app.api_route("/api/{service}/{endpoint:path}", methods=["GET", "POST", "PUT", "DELETE"])
@limiter.limit("60/minute")
async def api_proxy(
    service: str,
    endpoint: str,
    request: Request,
    token_data: TokenData = Depends(verify_token)
):
    """
    Proxy requests to internal microservices 
    with appropriate security checks
    """
    # Check if the route is registered and if agent has sufficient clearance
    route_info = get_route_info(service, endpoint, request.method)
    
    if route_info.requires_auth and token_data.clearance_level < route_info.min_clearance_level:
        log_security_event(
            event_type="insufficient_clearance",
            client_ip=request.client.host,
            path=f"/api/{service}/{endpoint}",
            method=request.method,
            agent_id=token_data.agent_id,
            clearance_level=token_data.clearance_level,
            details={
                "required_level": route_info.min_clearance_level,
                "service": service
            },
            severity="warning"
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Clearance level {route_info.min_clearance_level} required"
        )
    
    # Get request body for non-GET requests
    data = None
    if request.method != "GET":
        try:
            data = await request.json()
            # Apply Ghost-Step Algorithm to sanitize the request
            data = apply_ghost_step(data)
        except:
            data = {}
    
    # Add agent information from token
    if data is None:
        data = {}
    data["agent_id"] = token_data.agent_id
    data["clearance_level"] = token_data.clearance_level
    
    # Forward the request to the appropriate service
    status_code, response_data = await forward_request(
        service=service,
        endpoint=endpoint,
        method=request.method,
        headers=dict(request.headers),
        data=data,
        agent_id=token_data.agent_id,
        clearance_level=token_data.clearance_level
    )
    
    # Log the forwarded request
    log_security_event(
        event_type="request_forwarded",
        agent_id=token_data.agent_id,
        clearance_level=token_data.clearance_level,
        client_ip=request.client.host,
        path=f"/api/{service}/{endpoint}",
        method=request.method,
        details={
            "destination_service": service,
            "status_code": status_code
        }
    )
    
    # If status code indicates an error, raise an HTTPException
    if status_code >= 400:
        detail = response_data.get("detail", "Error from internal service")
        raise HTTPException(status_code=status_code, detail=detail)
    
    return response_data

# Token revocation endpoint
@app.post("/revoke-token")
async def revoke_token(
    request: Request,
    token_data: TokenData = Depends(verify_token)
):
    """Revoke an active JWT token"""
    if not redis_client:
        # Redis is required for blacklisting
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token revocation service unavailable"
        )
    
    # Add token to blacklist
    # Use the token's jti (JWT ID) as the identifier
    blacklist_key = f"blacklist:token:{token_data.jti}"
    
    # Store in Redis with expiration set to the token's original expiration
    # This prevents the blacklist from growing indefinitely
    ttl = token_data.exp - int(time.time())
    if ttl > 0:
        redis_client.setex(blacklist_key, ttl, "1")
    
    # Also terminate the session
    if token_data.session_id:
        try:
            # Call session service to terminate session
            async with httpx.AsyncClient() as client:
                await client.delete(
                    f"{SESSION_SERVICE_URL}/sessions/{token_data.session_id}",
                    headers={"X-API-Key": INTERNAL_API_KEY},
                    timeout=2.0
                )
        except Exception as e:
            logger.error(f"Error terminating session: {e}")
    
    # Log token revocation
    log_security_event(
        event_type="token_revoked",
        agent_id=token_data.agent_id,
        clearance_level=token_data.clearance_level,
        client_ip=request.client.host,
        path="/revoke-token",
        method="POST",
        details={"session_id": token_data.session_id}
    )
    
    return {"status": "success", "message": "Token revoked successfully"}

# Internal API endpoints (for service-to-service communication)
@app.get("/internal/route-info/{service}/{endpoint}")
async def get_internal_route_info(
    service: str,
    endpoint: str,
    method: str,
    api_key: Dict[str, Any] = Depends(verify_api_key)
):
    """Get routing information for a specific endpoint (internal use only)"""
    if "admin" not in api_key.get("permissions", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    route_info = get_route_info(service, endpoint, method)
    return route_info.dict()

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    # Check Redis health
    redis_health = False
    if redis_client:
        try:
            redis_client.ping()
            redis_health = True
        except:
            redis_health = False
    
    # Check services health
    services_health = {}
    for service_name, service_url in SERVICE_ENDPOINTS.items():
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{service_url}/health",
                    timeout=2.0
                )
                services_health[service_name] = response.status_code == 200
        except:
            services_health[service_name] = False
    
    # Overall health status
    all_services_healthy = all(services_health.values())
    status_value = "healthy" if redis_health and all_services_healthy else "degraded" if redis_health or any(services_health.values()) else "unhealthy"
    
    return {
        "status": status_value,
        "timestamp": time.time(),
        "redis": redis_health,
        "services": services_health,
        "version": "1.0.0"
    }

# Helper function to get route information
# Helper function to get route information
def get_route_info(service: str, endpoint: str, method: str) -> ServiceRoutingInfo:
    """Get routing information for a service endpoint"""
    # In a real implementation, this would check against a database or config file
    # For this example, we're using hardcoded values
    
    # Default route info
    default_info = ServiceRoutingInfo(
        service_name=service,
        endpoint=endpoint,
        method=method,
        requires_auth=True,
        min_clearance_level=1,
        rate_limit="60/minute"
    )
    
    # Special rules for specific endpoints
    if service == "auth":
        if endpoint == "token" and method == "POST":
            # Login endpoint doesn't require auth
            return ServiceRoutingInfo(
                service_name=service,
                endpoint=endpoint,
                method=method,
                requires_auth=False,
                min_clearance_level=0,
                rate_limit="10/minute"
            )
        elif endpoint.startswith("neural-signatures"):
            # Neural signature endpoints require higher clearance
            return ServiceRoutingInfo(
                service_name=service,
                endpoint=endpoint,
                method=method,
                requires_auth=True,
                min_clearance_level=5,  # Only highest level agents
                rate_limit="10/minute"
            )
    elif service == "session":
        # Session management requires admin privileges
        if method in ["POST", "DELETE"]:
            return ServiceRoutingInfo(
                service_name=service,
                endpoint=endpoint,
                method=method,
                requires_auth=True,
                min_clearance_level=4,  # Field Commander or higher
                rate_limit="20/minute"
            )
    elif service == "query":
        # Query processing depends on the clearance level encoded in the endpoint
        if "l5" in endpoint:
            return ServiceRoutingInfo(
                service_name=service,
                endpoint=endpoint,
                method=method,
                requires_auth=True,
                min_clearance_level=5,
                rate_limit="10/minute"
            )
        elif "l4" in endpoint:
            return ServiceRoutingInfo(
                service_name=service,
                endpoint=endpoint,
                method=method,
                requires_auth=True,
                min_clearance_level=4,
                rate_limit="20/minute"
            )
        elif "l3" in endpoint:
            return ServiceRoutingInfo(
                service_name=service,
                endpoint=endpoint,
                method=method,
                requires_auth=True,
                min_clearance_level=3,
                rate_limit="30/minute"
            )
        elif "l2" in endpoint:
            return ServiceRoutingInfo(
                service_name=service,
                endpoint=endpoint,
                method=method,
                requires_auth=True,
                min_clearance_level=2,
                rate_limit="40/minute"
            )
    
    # Return default info for all other endpoints
    return default_info

# Startup events
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("Secure Gateway starting up")
    
    # Check Redis connection
    if redis_client:
        try:
            redis_client.ping()
            logger.info("Redis connection successful")
        except redis.ConnectionError:
            logger.warning("Redis connection failed - token blacklisting will be disabled")
    else:
        logger.warning("Redis client not initialized - token blacklisting will be disabled")
    
    # Check services availability
    for service_name, service_url in SERVICE_ENDPOINTS.items():
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{service_url}/health",
                    timeout=2.0
                )
                if response.status_code == 200:
                    logger.info(f"Service {service_name} is available")
                else:
                    logger.warning(f"Service {service_name} returned non-200 status: {response.status_code}")
        except Exception as e:
            logger.warning(f"Service {service_name} is not available: {e}")

# Shutdown events
@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown"""
    logger.info("Secure Gateway shutting down")
    
    # Close Redis connection if it exists
    if redis_client:
        redis_client.close()

# Main entry point
if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment or use default
    port = int(os.getenv("PORT", 8000))
    
    # Configure uvicorn server
    uvicorn.run(
        "secure_gateway:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("ENVIRONMENT") != "production",
        log_level="info"
    )