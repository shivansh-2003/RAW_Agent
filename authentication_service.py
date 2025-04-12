# authentication_service.py

import os
import jwt
import time
import uuid
import json
import hashlib
import secrets
import logging
import base64
import pyotp
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple, Any, Union
from fastapi import FastAPI, Depends, HTTPException, Header, Request, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from scipy import signal
from sklearn.decomposition import PCA
import redis
from supabase import create_client

# ==============================
# Configuration and Initialization
# ==============================

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("auth_service.log")
    ]
)
logger = logging.getLogger("shadow_auth_service")

# Initialize FastAPI app
app = FastAPI(
    title="SHADOW Authentication Service",
    description="Authentication and session management for Project SHADOW",
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

# Initialize Redis for session management and rate limiting
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

# Initialize Supabase client
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")
try:
    supabase = create_client(supabase_url, supabase_key)
    logger.info("Successfully initialized Supabase client")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {e}")
    supabase = None

# Configuration constants
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecretkey_change_in_production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))
PASSWORD_SALT_BYTES = 16
PASSWORD_HASH_ITERATIONS = 100000  # High iteration count for security
MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_ATTEMPTS", 5))
LOCKOUT_DURATION_MINUTES = int(os.getenv("LOCKOUT_DURATION_MINUTES", 15))
NEURAL_SIGNATURE_EXPIRY_DAYS = int(os.getenv("NEURAL_SIGNATURE_EXPIRY_DAYS", 90))
NEURAL_SIGNATURE_ROTATION_TRANSITION_DAYS = int(os.getenv("NEURAL_SIGNATURE_ROTATION_TRANSITION_DAYS", 7))
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "internal_service_key")

# ==============================
# Data Models
# ==============================

class Agent(BaseModel):
    """Basic agent information"""
    id: str
    username: str
    clearance_level: int
    codename: str
    is_active: bool = True
    
class AgentInDB(Agent):
    """Agent information stored in the database"""
    hashed_password: str
    salt: str
    totp_secret: Optional[str] = None
    neural_signature: Optional[str] = None
    failed_login_attempts: int = 0
    last_failed_attempt: Optional[datetime] = None
    locked_until: Optional[datetime] = None

class Token(BaseModel):
    """Token response model"""
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    clearance_level: int
    codename: str

class TokenData(BaseModel):
    """Data extracted from a JWT token"""
    agent_id: str
    clearance_level: int
    codename: str
    session_id: str
    exp: int
    jti: str

class LoginRequest(BaseModel):
    """Login request data"""
    username: str
    password: str
    totp_code: Optional[str] = None
    neural_signature_data: Optional[str] = None
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.isalnum():
            raise ValueError('username must be alphanumeric')
        return v

class RefreshTokenRequest(BaseModel):
    """Refresh token request data"""
    refresh_token: str

class RevokeTokenRequest(BaseModel):
    """Token revocation request data"""
    token: str
    token_type: str = "access"  # "access" or "refresh"

class PasswordChangeRequest(BaseModel):
    """Password change request data"""
    current_password: str
    new_password: str
    
    @validator('new_password')
    def password_strength(cls, v):
        if len(v) < 12:
            raise ValueError('password must be at least 12 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('password must contain at least one digit')
        if not any(c in '!@#$%^&*()_-+=<>?/[]{}|' for c in v):
            raise ValueError('password must contain at least one special character')
        return v

class Session(BaseModel):
    """Session information"""
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

class SessionUpdate(BaseModel):
    """Session update data"""
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    metadata: Optional[Dict[str, Any]] = None

class NeuralSignatureData(BaseModel):
    """Neural signature information"""
    signature_id: str
    agent_id: str
    signature_data: str  # Base64 encoded feature vector
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    rotation_count: int = 0
    previous_signature_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SecurityEvent(BaseModel):
    """Security event log"""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: Optional[str] = None
    event_type: str
    details: Dict[str, Any] = Field(default_factory=dict)
    severity: str  # "info", "warning", "error", "critical"
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# ==============================
# Password and Authentication Utilities
# ==============================

def get_password_hash(password: str) -> Tuple[str, str]:
    """Generate a secure password hash with a random salt"""
    salt = secrets.token_hex(PASSWORD_SALT_BYTES)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        salt.encode(), 
        PASSWORD_HASH_ITERATIONS
    ).hex()
    return pw_hash, salt

def verify_password(plain_password: str, hashed_password: str, salt: str) -> bool:
    """Verify password against stored hash and salt"""
    computed_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        plain_password.encode(), 
        salt.encode(), 
        PASSWORD_HASH_ITERATIONS
    ).hex()
    # Use constant-time comparison to prevent timing attacks
    return secrets.compare_digest(computed_hash, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a new JWT access token"""
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Add required JWT claims
    to_encode.update({
        "exp": expire.timestamp(),
        "iat": datetime.utcnow().timestamp(),
        "jti": str(uuid.uuid4())  # Unique token ID for revocation
    })
    
    # Encode and sign the JWT
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(agent_id: str) -> str:
    """Create a new refresh token with longer expiration"""
    jti = str(uuid.uuid4())
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    token_data = {
        "sub": agent_id,
        "exp": expire.timestamp(),
        "iat": datetime.utcnow().timestamp(),
        "jti": jti,
        "type": "refresh"
    }
    
    # Store refresh token in Redis for validation and revocation
    if redis_client:
        redis_key = f"refresh_token:{jti}"
        redis_client.setex(
            redis_key,
            int(timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS).total_seconds()),
            agent_id
        )
    
    # Encode and sign the JWT
    encoded_jwt = jwt.encode(token_data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

# ==============================
# Agent Data Access Functions
# ==============================

def get_agent_by_username(username: str) -> Optional[AgentInDB]:
    """Retrieve agent from database by username"""
    if not supabase:
        # Fallback for development/testing
        if username == "test_agent":
            return AgentInDB(
                id="test123",
                username="test_agent",
                hashed_password="salt" + get_password_hash("password")[0],  # Fake hash
                salt="salt",
                clearance_level=3,
                codename="Phantom Mind",
                is_active=True
            )
        return None

    try:
        response = supabase.table("agents").select("*").eq("username", username).execute()
        if response.data and len(response.data) > 0:
            return AgentInDB(**response.data[0])
        return None
    except Exception as e:
        logger.error(f"Database error retrieving agent: {e}")
        return None

def get_agent_by_id(agent_id: str) -> Optional[AgentInDB]:
    """Retrieve agent from database by ID"""
    if not supabase:
        # Fallback for development/testing
        if agent_id == "test123":
            return AgentInDB(
                id="test123",
                username="test_agent",
                hashed_password="salt" + get_password_hash("password")[0],  # Fake hash
                salt="salt",
                clearance_level=3,
                codename="Phantom Mind",
                is_active=True
            )
        return None

    try:
        response = supabase.table("agents").select("*").eq("id", agent_id).execute()
        if response.data and len(response.data) > 0:
            return AgentInDB(**response.data[0])
        return None
    except Exception as e:
        logger.error(f"Database error retrieving agent: {e}")
        return None

def update_agent_failed_attempts(agent_id: str, attempts: int, last_attempt: datetime) -> bool:
    """Update the failed login attempts for an agent"""
    if not supabase:
        # For testing without database
        logger.warning(f"No database connection, failed attempts not updated for agent {agent_id}")
        return True

    try:
        supabase.table("agents").update({
            "failed_login_attempts": attempts,
            "last_failed_attempt": last_attempt.isoformat()
        }).eq("id", agent_id).execute()
        return True
    except Exception as e:
        logger.error(f"Database error updating agent failed attempts: {e}")
        return False

def lock_agent_account(agent_id: str, locked_until: datetime) -> bool:
    """Lock an agent account until the specified time"""
    if not supabase:
        # For testing without database
        logger.warning(f"No database connection, account not locked for agent {agent_id}")
        return True

    try:
        supabase.table("agents").update({
            "locked_until": locked_until.isoformat()
        }).eq("id", agent_id).execute()
        return True
    except Exception as e:
        logger.error(f"Database error locking agent account: {e}")
        return False

def reset_agent_failed_attempts(agent_id: str) -> bool:
    """Reset the failed login attempts for an agent after successful login"""
    if not supabase:
        # For testing without database
        logger.warning(f"No database connection, failed attempts not reset for agent {agent_id}")
        return True

    try:
        supabase.table("agents").update({
            "failed_login_attempts": 0,
            "last_failed_attempt": None,
            "locked_until": None
        }).eq("id", agent_id).execute()
        return True
    except Exception as e:
        logger.error(f"Database error resetting agent failed attempts: {e}")
        return False

def update_agent_password(agent_id: str, password_hash: str, salt: str) -> bool:
    """Update an agent's password hash and salt"""
    if not supabase:
        # For testing without database
        logger.warning(f"No database connection, password not updated for agent {agent_id}")
        return True

    try:
        supabase.table("agents").update({
            "hashed_password": password_hash,
            "salt": salt
        }).eq("id", agent_id).execute()
        return True
    except Exception as e:
        logger.error(f"Database error updating agent password: {e}")
        return False

# ==============================
# TOTP Verification
# ==============================

def verify_totp(totp_secret: str, totp_code: str) -> bool:
    """Verify a TOTP code against the secret"""
    if not totp_secret or not totp_code:
        return False
    
    try:
        totp = pyotp.TOTP(totp_secret)
        return totp.verify(totp_code)
    except Exception as e:
        logger.error(f"TOTP verification error: {e}")
        return False

# ==============================
# Neural Signature Functions
# ==============================

def extract_neural_features(raw_data: bytes) -> np.ndarray:
    """
    Extract features from raw neural signature data
    This would typically involve signal processing, frequency analysis, etc.
    """
    # Convert bytes to numpy array (assuming float32 values)
    data = np.frombuffer(raw_data, dtype=np.float32)
    
    # Apply signal processing techniques
    # 1. Filter to relevant frequency bands (e.g., alpha, beta waves for EEG)
    sos = signal.butter(4, [8, 30], 'bandpass', fs=256, output='sos')
    filtered_data = signal.sosfilt(sos, data)
    
    # 2. Extract frequency domain features using FFT
    fft_features = np.abs(np.fft.rfft(filtered_data))
    
    # 3. Extract statistical features
    stat_features = np.array([
        np.mean(filtered_data),
        np.std(filtered_data),
        np.median(filtered_data),
        np.max(filtered_data),
        np.min(filtered_data),
        np.percentile(filtered_data, 25),
        np.percentile(filtered_data, 75)
    ])
    
    # 4. Dimensionality reduction for consistent feature vector size
    if len(fft_features) > 50:
        pca = PCA(n_components=50)
        fft_features = pca.fit_transform(fft_features.reshape(1, -1))[0]
    
    # 5. Combine features
    combined_features = np.concatenate([fft_features[:50], stat_features])
    
    # 6. Normalize the feature vector
    feature_norm = np.linalg.norm(combined_features)
    if feature_norm > 0:
        combined_features = combined_features / feature_norm
    
    return combined_features

def create_signature_template(raw_data: bytes) -> str:
    """
    Create a signature template from raw neural data
    Returns base64 encoded template
    """
    features = extract_neural_features(raw_data)
    template_bytes = features.tobytes()
    return base64.b64encode(template_bytes).decode('utf-8')

def register_neural_signature(agent_id: str, raw_data: bytes) -> NeuralSignatureData:
    """Register a new neural signature for an agent"""
    # Extract features and create template
    signature_data = create_signature_template(raw_data)
    
    # Create new signature record
    signature_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    expires_at = created_at + timedelta(days=NEURAL_SIGNATURE_EXPIRY_DAYS)
    
    signature = NeuralSignatureData(
        signature_id=signature_id,
        agent_id=agent_id,
        signature_data=signature_data,
        created_at=created_at,
        expires_at=expires_at,
        rotation_count=0,
        previous_signature_id=None,
        metadata={"source": "initial_registration"}
    )
    
    # Store in database
    store_neural_signature(signature)
    
    return signature

def store_neural_signature(signature: NeuralSignatureData) -> bool:
    """Store a neural signature in the database"""
    if not supabase:
        # For testing without database
        logger.warning(f"No database connection, neural signature not stored for agent {signature.agent_id}")
        return True

    try:
        # Using Supabase to store the signature
        signature_dict = signature.dict()
        
        # Convert datetime objects to ISO format
        signature_dict["created_at"] = signature_dict["created_at"].isoformat()
        if signature_dict["expires_at"]:
            signature_dict["expires_at"] = signature_dict["expires_at"].isoformat()
        
        supabase.table("neural_signatures").insert(signature_dict).execute()
        return True
    except Exception as e:
        logger.error(f"Error storing neural signature: {e}")
        return False

def get_active_neural_signature(agent_id: str) -> Optional[NeuralSignatureData]:
    """Get the currently active neural signature for an agent"""
    if not supabase:
        # For testing without database
        logger.warning(f"No database connection, returning dummy neural signature for agent {agent_id}")
        return NeuralSignatureData(
            signature_id="test-signature",
            agent_id=agent_id,
            signature_data="dummy-data",
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=90)
        )

    try:
        # Get the most recent active signature
        now = datetime.utcnow().isoformat()
        response = supabase.table("neural_signatures")\
            .select("*")\
            .eq("agent_id", agent_id)\
            .gt("expires_at", now)\
            .order("created_at", desc=True)\
            .limit(1)\
            .execute()
        
        if response.data and len(response.data) > 0:
            signature_data = response.data[0]
            
            # Convert date strings back to datetime
            signature_data["created_at"] = datetime.fromisoformat(signature_data["created_at"])
            if signature_data["expires_at"]:
                signature_data["expires_at"] = datetime.fromisoformat(signature_data["expires_at"])
            
            return NeuralSignatureData(**signature_data)
        
        return None
    except Exception as e:
        logger.error(f"Error retrieving neural signature: {e}")
        return None

def get_previous_signatures(agent_id: str, limit: int = 3) -> List[NeuralSignatureData]:
    """Get previous neural signatures for an agent"""
    if not supabase:
        # For testing without database
        logger.warning(f"No database connection, returning empty previous signatures for agent {agent_id}")
        return []

    try:
        now = datetime.utcnow().isoformat()
        response = supabase.table("neural_signatures")\
            .select("*")\
            .eq("agent_id", agent_id)\
            .lt("expires_at", now)\
            .order("created_at", desc=True)\
            .limit(limit)\
            .execute()
        
        signatures = []
        for data in response.data:
            # Convert date strings back to datetime
            data["created_at"] = datetime.fromisoformat(data["created_at"])
            if data["expires_at"]:
                data["expires_at"] = datetime.fromisoformat(data["expires_at"])
            
            signatures.append(NeuralSignatureData(**data))
        
        return signatures
    except Exception as e:
        logger.error(f"Error retrieving previous neural signatures: {e}")
        return []

def calculate_adaptive_threshold(agent_id: str, security_context: Dict[str, Any]) -> float:
    """
    Calculate an adaptive threshold for neural signature verification
    based on agent history and current security context
    """
    # Base threshold
    base_threshold = 0.85
    
    # Adjust based on clearance level
    clearance_level = security_context.get("clearance_level", 3)
    level_adjustment = min(0.05, (clearance_level - 1) * 0.01)  # Stricter for higher levels
    
    # Adjust based on agent's historical verification scores
    historical_scores = security_context.get("historical_scores", [])
    if historical_scores:
        history_adjustment = 0.02 * (1 - (sum(historical_scores) / len(historical_scores)))
    else:
        history_adjustment = 0
    
    # Adjust based on risk factors
    risk_level = security_context.get("risk_level", "low")
    risk_adjustment = {
        "low": 0,
        "medium": 0.03,
        "high": 0.07,
        "critical": 0.1
    }.get(risk_level, 0)
    
    # Calculate final threshold
    threshold = base_threshold + level_adjustment + history_adjustment + risk_adjustment
    
    # Ensure threshold is within reasonable bounds
    return max(0.8, min(0.98, threshold))

def create_rotated_signature(previous_signature_data: str, rotation_count: int) -> str:
    """
    Create a slightly modified version of the previous signature
    to account for natural changes in neural patterns
    """
    try:
        # Decode the previous signature
        previous_vector = np.frombuffer(base64.b64decode(previous_signature_data), dtype=np.float32)
        
        # Calculate adaptation factor - lower for higher rotation counts
        adaptation_factor = min(0.05, 0.02 + (0.005 * rotation_count))
        
        # Add small controlled variations to adapt to changing patterns
        # More sophisticated implementations would use neural data drift models
        noise = np.random.normal(0, adaptation_factor, size=previous_vector.shape)
        
        # Add the noise but maintain the general pattern
        new_vector = previous_vector + noise
        
        # Renormalize
        new_vector = new_vector / np.linalg.norm(new_vector)
        
        # Encode back to base64
        return base64.b64encode(new_vector.astype(np.float32).tobytes()).decode('utf-8')
    except Exception as e:
        logger.error(f"Error creating rotated signature: {e}")
        return previous_signature_data

def rotate_neural_signature(agent_id: str) -> bool:
    """Generate a new neural signature to replace the existing one"""
    # Get current signature
    current_signature = get_active_neural_signature(agent_id)
    if not current_signature:
        logger.error(f"No active neural signature found for agent {agent_id}")
        return False
    
    # Update rotation count
    rotation_count = current_signature.rotation_count + 1
    
    # Create rotated signature data
    new_signature_data = create_rotated_signature(
        current_signature.signature_data,
        rotation_count
    )
    
    # Create new signature record
    signature_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    expires_at = created_at + timedelta(days=NEURAL_SIGNATURE_EXPIRY_DAYS)
    
    # Set the old signature to expire sooner (transition period)
    transition_expiry = created_at + timedelta(days=NEURAL_SIGNATURE_ROTATION_TRANSITION_DAYS)
    
    if supabase:
        try:
            supabase.table("neural_signatures")\
                .update({"expires_at": transition_expiry.isoformat()})\
                .eq("signature_id", current_signature.signature_id)\
                .execute()
        except Exception as e:
            logger.error(f"Error updating old signature expiry: {e}")
    
    # Create and store new signature
    new_signature = NeuralSignatureData(
        signature_id=signature_id,
        agent_id=agent_id,
        signature_data=new_signature_data,
        created_at=created_at,
        expires_at=expires_at,
        rotation_count=rotation_count,
        previous_signature_id=current_signature.signature_id,
        metadata={
            "rotation_date": created_at.isoformat(),
            "rotation_reason": "scheduled",
            "previous_signature_id": current_signature.signature_id
        }
    )
    
    return store_neural_signature(new_signature)

def verify_neural_signature(stored_signature: str, provided_signature: str) -> bool:
    """Simple neural signature verification using cosine similarity"""
    if not stored_signature or not provided_signature:
        return False
    
    try:
        # Decode base64 signatures to feature vectors
        stored_vector = np.frombuffer(base64.b64decode(stored_signature), dtype=np.float32)
        provided_vector = np.frombuffer(base64.b64decode(provided_signature), dtype=np.float32)
        
        # Check vector dimensions
        if stored_vector.shape != provided_vector.shape:
            logger.warning("Neural signature dimension mismatch")
            return False
        
        # Calculate cosine similarity
        dot_product = np.dot(stored_vector, provided_vector)
        norm_stored = np.linalg.norm(stored_vector)
        norm_provided = np.linalg.norm(provided_vector)
        
        similarity = dot_product / (norm_stored * norm_provided)
        
        # Basic threshold
        return similarity > 0.85
    except Exception as e:
        logger.error(f"Neural signature verification error: {e}")
        return False

def verify_neural_signature_advanced(agent_id: str, provided_signature: str, security_context: Dict[str, Any] = None) -> bool:
    """
    Advanced neural signature verification with zero-knowledge approach and
    support for signature rotation
    """
    if not agent_id or not provided_signature:
        return False
    
    if security_context is None:
        security_context = {
            "clearance_level": 3,
            "risk_level": "medium",
            "historical_scores": []
        }
    
    try:
        # Get current active signature
        current_signature = get_active_neural_signature(agent_id)
        if not current_signature:
            logger.error(f"No active neural signature found for agent {agent_id}")
            return False
        
        # Decode provided signature
        try:
            provided_vector = np.frombuffer(base64.b64decode(provided_signature), dtype=np.float32)
        except Exception as e:
            logger.error(f"Error decoding provided signature: {e}")
            return False
        
        # Decode stored signature
        stored_vector = np.frombuffer(base64.b64decode(current_signature.signature_data), dtype=np.float32)
        
        # Check vector dimensions
        if stored_vector.shape != provided_vector.shape:
            logger.warning(f"Neural signature dimension mismatch for agent {agent_id}")
            return False
        
        # Calculate primary similarity score (cosine similarity)
        dot_product = np.dot(stored_vector, provided_vector)
        norm_stored = np.linalg.norm(stored_vector)
        norm_provided = np.linalg.norm(provided_vector)
        
        primary_similarity = dot_product / (norm_stored * norm_provided)
        
        # Get adaptive threshold based on security context
        threshold = calculate_adaptive_threshold(agent_id, security_context)
        
        # Check against primary threshold
        if primary_similarity >= threshold:
            # Successful verification with current signature
            return True
        
        # If primary verification fails but is close, check previous signatures
        # This handles transition periods during signature rotation
        if primary_similarity >= (threshold - 0.1):
            # Check previous signatures (during transition period)
            previous_signatures = get_previous_signatures(agent_id)
            
            for prev_sig in previous_signatures:
                # Only check recent previous signatures (within transition period)
                age_days = (datetime.utcnow() - prev_sig.created_at).days
                if age_days > 14:  # Only check signatures less than 14 days old
                    continue
                
                try:
                    prev_vector = np.frombuffer(base64.b64decode(prev_sig.signature_data), dtype=np.float32)
                    
                    if prev_vector.shape != provided_vector.shape:
                        continue
                    
                    prev_similarity = np.dot(prev_vector, provided_vector) / (np.linalg.norm(prev_vector) * norm_provided)
                    
                    # Use a slightly lower threshold for previous signatures
                    if prev_similarity >= (threshold - 0.05):
                        logger.info(f"Verified agent {agent_id} using previous signature {prev_sig.signature_id}")
                        
                        # Consider rotating signature if using previous one frequently
                        if age_days > 3:  # If using a signature more than 3 days old
                            # Schedule a signature rotation (could be done asynchronously)
                            logger.info(f"Scheduling signature rotation for agent {agent_id}")
                        
                        return True
                except Exception as e:
                    logger.error(f"Error checking previous signature: {e}")
                    continue
        
        # Verification failed
        return False
        
    except Exception as e:
        logger.error(f"Error in neural signature verification: {e}")
        return False

# ==============================
# Session Management Functions
# ==============================

def create_session(agent_id: str, clearance_level: int, request: Request) -> Session:
    """Create a new session for an authenticated agent"""
    session_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    expires_at = created_at + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    session = Session(
        session_id=session_id,
        agent_id=agent_id,
        clearance_level=clearance_level,
        created_at=created_at,
        expires_at=expires_at,
        last_activity=created_at,
        ip_address=request.client.host,
        user_agent=request.headers.get("User-Agent", "Unknown")
    )
    
    # Store session in Redis
    if redis_client:
        session_key = f"session:{session_id}"
        session_data = session.dict()
        
        # Convert datetime objects to ISO format strings for Redis storage
        session_data["created_at"] = session_data["created_at"].isoformat()
        session_data["expires_at"] = session_data["expires_at"].isoformat()
        session_data["last_activity"] = session_data["last_activity"].isoformat()
        
        # Convert dict to JSON string
        if isinstance(session_data["metadata"], dict):
            session_data["metadata"] = json.dumps(session_data["metadata"])
        
        redis_client.hset(session_key, mapping=session_data)
        redis_client.expire(session_key, int(timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds()))
        
        # Add to agent sessions index for easier retrieval
        redis_client.sadd(f"agent_sessions:{agent_id}", session_id)
    
    return session

def get_session(session_id: str) -> Optional[Session]:
    """Retrieve an active session by ID"""
    if not redis_client:
        # Fallback for testing
        logger.warning(f"No Redis connection, returning dummy session for ID {session_id}")
        return Session(
            session_id=session_id,
            agent_id="test123",
            clearance_level=3,
            created_at=datetime.utcnow() - timedelta(minutes=5),
            expires_at=datetime.utcnow() + timedelta(minutes=25),
            last_activity=datetime.utcnow() - timedelta(minutes=2),
            ip_address="127.0.0.1",
            user_agent="Test Agent"
        )
    
    session_key = f"session:{session_id}"
    session_data = redis_client.hgetall(session_key)
    
    if not session_data:
        return None
    
    try:
        # Convert string timestamps back to datetime
        session_data["created_at"] = datetime.fromisoformat(session_data["created_at"])
        session_data["expires_at"] = datetime.fromisoformat(session_data["expires_at"])
        session_data["last_activity"] = datetime.fromisoformat(session_data["last_activity"])
        
        # Convert string boolean to actual boolean
        session_data["is_active"] = session_data["is_active"].lower() == "true"
        
        # Convert clearance level to int
        session_data["clearance_level"] = int(session_data["clearance_level"])
        
        # Convert metadata JSON string to dict
        if "metadata" in session_data and isinstance(session_data["metadata"], str):
            try:
                session_data["metadata"] = json.loads(session_data["metadata"])
            except:
                session_data["metadata"] = {}
        
        return Session(**session_data)
    except Exception as e:
        logger.error(f"Error parsing session data: {e}")
        return None

def update_session_activity(session_id: str) -> bool:
    """Update the last activity timestamp for a session"""
    if not redis_client:
        logger.warning(f"No Redis connection, session activity not updated for ID {session_id}")
        return True
    
    session_key = f"session:{session_id}"
    now = datetime.utcnow()
    
    # Check if session exists
    if not redis_client.exists(session_key):
        return False
    
    # Update last activity timestamp
    redis_client.hset(session_key, "last_activity", now.isoformat())
    
    # Reset expiration time
    redis_client.expire(session_key, int(timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds()))
    
    return True

def terminate_session(session_id: str) -> bool:
    """Terminate an active session"""
    if not redis_client:
        logger.warning(f"No Redis connection, session not terminated for ID {session_id}")
        return True
    
    session_key = f"session:{session_id}"
    
    # Check if session exists
    if not redis_client.exists(session_key):
        return False
    
    # Get agent ID before deleting session
    agent_id = redis_client.hget(session_key, "agent_id")
    
    # Delete the session
    redis_client.delete(session_key)
    
    # Remove from agent sessions index
    if agent_id:
        redis_client.srem(f"agent_sessions:{agent_id}", session_id)
    
    return True

def get_active_sessions_for_agent(agent_id: str) -> List[Session]:
    """Get all active sessions for an agent"""
    if not redis_client:
        logger.warning(f"No Redis connection, returning empty session list for agent {agent_id}")
        return []
    
    sessions = []
    
    # Use the agent sessions index for efficient retrieval
    session_ids = redis_client.smembers(f"agent_sessions:{agent_id}")
    
    for session_id in session_ids:
        session = get_session(session_id)
        if session and session.is_active:
            sessions.append(session)
    
    return sessions

# ==============================
# Token Blacklisting Functions
# ==============================

def blacklist_token(token_jti: str, token_exp: int) -> bool:
    """Add a token to the blacklist"""
    if not redis_client:
        logger.warning(f"No Redis connection, token {token_jti} not blacklisted")
        return True
    
    blacklist_key = f"blacklist:{token_jti}"
    
    # Calculate TTL (seconds until expiration)
    now = time.time()
    ttl = max(1, int(token_exp - now))  # Ensure positive TTL
    
    redis_client.setex(blacklist_key, ttl, "1")
    return True

def is_token_blacklisted(token_jti: str) -> bool:
    """Check if a token is blacklisted"""
    if not redis_client:
        logger.warning(f"No Redis connection, assuming token {token_jti} is not blacklisted")
        return False
    
    blacklist_key = f"blacklist:{token_jti}"
    return redis_client.exists(blacklist_key) > 0

# ==============================
# Security Event Logging
# ==============================

def log_security_event(
    event_type: str,
    details: Dict[str, Any] = {},
    agent_id: Optional[str] = None,
    severity: str = "info"
) -> bool:
    """Log a security event to the database"""
    try:
        event = SecurityEvent(
            event_type=event_type,
            details=details,
            agent_id=agent_id,
            severity=severity
        )
        
        if not supabase:
            # Log to console instead of database when testing
            logger_method = getattr(logger, severity, logger.info)
            logger_method(f"SECURITY EVENT: {event_type} - Agent: {agent_id or 'unknown'} - Details: {details}")
            return True
        
        # Convert to dict for storage
        event_dict = event.dict()
        event_dict["timestamp"] = event_dict["timestamp"].isoformat()
        
        supabase.table("security_events").insert(event_dict).execute()
        return True
    except Exception as e:
        logger.error(f"Error logging security event: {e}")
        return False

# ==============================
# Rate Limiting Functions
# ==============================

def check_rate_limit(key: str, limit: int, period: int) -> bool:
    """
    Check if a rate limit has been exceeded
    
    Args:
        key: Rate limit key (e.g., "login:{ip}" or "login:{username}")
        limit: Maximum number of attempts allowed
        period: Time period in seconds
        
    Returns:
        True if rate limit is not exceeded, False otherwise
    """
    if not redis_client:
        logger.warning(f"No Redis connection, rate limiting disabled for {key}")
        return True
    
    current_count = redis_client.get(key)
    
    if current_count is None:
        # First attempt, set counter to 1 with expiration
        redis_client.setex(key, period, 1)
        return True
    
    # Increment counter
    new_count = redis_client.incr(key)
    
    # If this is the first increment, set expiration
    if int(current_count) == 0:
        redis_client.expire(key, period)
    
    # Check if limit exceeded
    if int(new_count) > limit:
        return False
        
    return True

def determine_risk_level(agent_id: str, request: Request) -> str:
    """
    Determine the risk level for the current authentication attempt
    based on contextual factors
    """
    # Get IP address and check if it's unusual for this agent
    ip_address = request.client.host
    unusual_ip = check_unusual_ip(agent_id, ip_address)
    
    # Get time of day and check if it's unusual
    current_hour = datetime.utcnow().hour
    unusual_time = current_hour >= 1 and current_hour <= 4  # 1 AM to 4 AM UTC
    
    # Check for unusual user agent
    user_agent = request.headers.get("User-Agent", "Unknown")
    unusual_agent = check_unusual_user_agent(agent_id, user_agent)
    
    # Check for recent security events
    recent_security_events = check_recent_security_events(agent_id)
    
    # Calculate risk level
    if unusual_ip and (unusual_time or unusual_agent) and recent_security_events:
        return "critical"
    elif unusual_ip and (unusual_time or unusual_agent):
        return "high"
    elif unusual_ip or unusual_time or unusual_agent:
        return "medium"
    else:
        return "low"

# These are placeholder functions that would need real implementations
def check_unusual_ip(agent_id: str, ip_address: str) -> bool:
    # In a real implementation, check if this IP has been used by the agent before
    # For now, return a placeholder value
    return False

def check_unusual_user_agent(agent_id: str, user_agent: str) -> bool:
    # Check if this user agent is unusual for this agent
    # For now, return a placeholder value
    return False

def check_recent_security_events(agent_id: str) -> bool:
    # Check for recent security events related to this agent
    # For now, return a placeholder value
    return False

# ==============================
# Authentication Middleware
# ==============================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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
        
        # Check for required fields
        agent_id = payload.get("agent_id")
        clearance_level = payload.get("clearance_level")
        codename = payload.get("codename")
        session_id = payload.get("session_id")
        jti = payload.get("jti")
        exp = payload.get("exp")
        
        if not all([agent_id, clearance_level, codename, session_id, jti, exp]):
            raise credentials_exception
        
        # Check if token is blacklisted
        if is_token_blacklisted(jti):
            raise credentials_exception
        
        # Create TokenData object
        token_data = TokenData(
            agent_id=agent_id,
            clearance_level=clearance_level,
            codename=codename,
            session_id=session_id,
            jti=jti,
            exp=exp
        )
        
        # Update session activity
        update_session_activity(session_id)
        
        return token_data
        
    except jwt.PyJWTError as e:
        logger.error(f"JWT verification error: {e}")
        raise credentials_exception

async def verify_internal_api_key(api_key: str = Header(..., alias="X-API-Key")) -> bool:
    """Verify that the request is coming from an internal service"""
    if api_key != INTERNAL_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return True

# ==============================
# API Endpoints
# ==============================

@app.post("/token", response_model=Token)
async def login_for_access_token(login_data: LoginRequest, request: Request, background_tasks: BackgroundTasks):
    """Authenticate agent and issue access token"""
    # Check IP-based rate limiting (10 attempts per minute)
    ip_rate_key = f"rate:login:ip:{request.client.host}"
    if not check_rate_limit(ip_rate_key, 10, 60):
        log_security_event(
            event_type="rate_limit_exceeded",
            details={"ip": request.client.host, "username": login_data.username},
            severity="warning"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts from this IP"
        )
    
    # Check username-based rate limiting (5 attempts per minute)
    username_rate_key = f"rate:login:username:{login_data.username}"
    if not check_rate_limit(username_rate_key, 5, 60):
        log_security_event(
            event_type="rate_limit_exceeded",
            details={"ip": request.client.host, "username": login_data.username},
            severity="warning"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts for this username"
        )
    
    # Get agent from database
    agent = get_agent_by_username(login_data.username)
    if not agent:
        # Log failed login attempt
        log_security_event(
            event_type="failed_login_attempt",
            details={"reason": "user_not_found", "ip": request.client.host, "username": login_data.username},
            severity="warning"
        )
        # Return same error as failed password to prevent username enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Check if account is active
    if not agent.is_active:
        log_security_event(
            event_type="failed_login_attempt",
            details={"reason": "account_disabled", "ip": request.client.host},
            agent_id=agent.id,
            severity="warning"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )
    
    # Check if account is locked
    if agent.locked_until and agent.locked_until > datetime.utcnow():
        lockout_remaining = (agent.locked_until - datetime.utcnow()).total_seconds() / 60
        log_security_event(
            event_type="login_attempt_while_locked",
            details={"ip": request.client.host, "lockout_remaining_minutes": int(lockout_remaining)},
            agent_id=agent.id,
            severity="warning"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Account is locked for {int(lockout_remaining)} more minutes"
        )
    
    # Verify password
    if not verify_password(login_data.password, agent.hashed_password, agent.salt):
        # Increment failed attempts
        new_attempts = agent.failed_login_attempts + 1
        now = datetime.utcnow()
        
        # Log failed login attempt
        log_security_event(
            event_type="failed_login_attempt",
            details={"reason": "invalid_password", "ip": request.client.host, "attempt_number": new_attempts},
            agent_id=agent.id,
            severity="warning"
        )
        
        # Check if we should lock the account
        if new_attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            lock_agent_account(agent.id, locked_until)
            
            log_security_event(
                event_type="account_locked",
                details={"reason": "max_failed_attempts", "ip": request.client.host, "locked_until": locked_until.isoformat()},
                agent_id=agent.id,
                severity="warning"
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to too many failed attempts"
            )
        
        # Update failed attempts
        update_agent_failed_attempts(agent.id, new_attempts, now)
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # For level 3+ agents, verify TOTP
    if agent.clearance_level >= 3:
        if not agent.totp_secret:
            # This should not happen - all Level 3+ agents should have TOTP set up
            logger.error(f"Level {agent.clearance_level} agent {agent.id} missing TOTP secret")
            log_security_event(
                event_type="missing_totp_secret",
                details={"ip": request.client.host},
                agent_id=agent.id,
                severity="error"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication configuration error"
            )
        
        if not login_data.totp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOTP code required for this clearance level"
            )
        
        if not verify_totp(agent.totp_secret, login_data.totp_code):
            # Update failed attempts
            new_attempts = agent.failed_login_attempts + 1
            now = datetime.utcnow()
            update_agent_failed_attempts(agent.id, new_attempts, now)
            
            # Log failed TOTP verification
            log_security_event(
                event_type="failed_totp_verification",
                details={"ip": request.client.host},
                agent_id=agent.id,
                severity="warning"
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TOTP code"
            )
    
    # For level 5 agents, verify neural signature
    if agent.clearance_level >= 5:
        if not login_data.neural_signature_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Neural signature required for this clearance level"
            )
        
        # Create security context for advanced verification
        security_context = {
            "clearance_level": agent.clearance_level,
            "risk_level": determine_risk_level(agent.id, request),
            "login_attempt": True,
            "ip_address": request.client.host,
            "user_agent": request.headers.get("User-Agent", "Unknown")
        }
        
        # Use the advanced neural signature verification
        if not verify_neural_signature_advanced(
            agent.id, 
            login_data.neural_signature_data, 
            security_context
        ):
            # Update failed attempts
            new_attempts = agent.failed_login_attempts + 1
            now = datetime.utcnow()
            update_agent_failed_attempts(agent.id, new_attempts, now)
            
            # Log failed neural signature verification
            log_security_event(
                event_type="failed_neural_signature_verification",
                details={"ip": request.client.host, "risk_level": security_context["risk_level"]},
                agent_id=agent.id,
                severity="warning"
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Neural signature verification failed"
            )
        
        # Check if signature needs rotation (every 30 days or based on security policy)
        current_signature = get_active_neural_signature(agent.id)
        if current_signature and current_signature.created_at < datetime.utcnow() - timedelta(days=30):
            # Schedule signature rotation in the background
            background_tasks.add_task(rotate_neural_signature, agent.id)
            logger.info(f"Scheduled neural signature rotation for agent {agent.id}")
    
    # Authentication successful - reset failed attempts
    reset_agent_failed_attempts(agent.id)
    
    # Create session
    session = create_session(agent.id, agent.clearance_level, request)
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "agent_id": agent.id,
            "clearance_level": agent.clearance_level,
            "codename": agent.codename,
            "session_id": session.session_id
        },
        expires_delta=access_token_expires
    )
    
    # Create refresh token
    refresh_token = create_refresh_token(agent.id)
    
    # Log successful login
    log_security_event(
        event_type="successful_login",
        details={"ip": request.client.host, "session_id": session.session_id},
        agent_id=agent.id,
        severity="info"
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "clearance_level": agent.clearance_level,
        "codename": agent.codename
    }

@app.post("/refresh", response_model=Token)
async def refresh_access_token(refresh_request: RefreshTokenRequest, request: Request):
    """Get a new access token using a refresh token"""
    try:
        # Decode refresh token
        payload = jwt.decode(refresh_request.refresh_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # Validate token type
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        # Extract token data
        agent_id = payload.get("sub")
        jti = payload.get("jti")
        
        if not agent_id or not jti:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Check if token is in Redis (valid and not revoked)
        if redis_client:
            redis_key = f"refresh_token:{jti}"
            stored_agent_id = redis_client.get(redis_key)
            
            if not stored_agent_id or stored_agent_id != agent_id:
                log_security_event(
                    event_type="invalid_refresh_token",
                    details={"ip": request.client.host, "reason": "token_not_found_or_mismatch"},
                    agent_id=agent_id,
                    severity="warning"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or revoked token"
                )
        
        # Get agent from database
        agent = get_agent_by_id(agent_id)
        if not agent or not agent.is_active:
            log_security_event(
                event_type="refresh_token_denied",
                details={"ip": request.client.host, "reason": "agent_not_found_or_inactive"},
                agent_id=agent_id,
                severity="warning"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Agent not found or inactive"
            )
        
        # Create new session
        session = create_session(agent.id, agent.clearance_level, request)
        
        # Create new access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "agent_id": agent.id,
                "clearance_level": agent.clearance_level,
                "codename": agent.codename,
                "session_id": session.session_id
            },
            expires_delta=access_token_expires
        )
        
        # Create new refresh token
        new_refresh_token = create_refresh_token(agent.id)
        
        # Revoke old refresh token
        if redis_client:
            redis_key = f"refresh_token:{jti}"
            redis_client.delete(redis_key)
        
        # Log successful token refresh
        log_security_event(
            event_type="token_refresh",
            details={"ip": request.client.host, "new_session_id": session.session_id},
            agent_id=agent.id,
            severity="info"
        )
        
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "clearance_level": agent.clearance_level,
            "codename": agent.codename
        }
        
    except jwt.PyJWTError as e:
        log_security_event(
            event_type="invalid_refresh_token",
            details={"ip": request.client.host, "reason": "jwt_error", "error": str(e)},
            severity="warning"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

@app.post("/revoke")
async def revoke_token(revoke_request: RevokeTokenRequest, token_data: TokenData = Depends(verify_token)):
    """Revoke an access or refresh token"""
    try:
        if revoke_request.token_type == "access":
            # Decode token to get JTI
            payload = jwt.decode(revoke_request.token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_signature": True})
            jti = payload.get("jti")
            exp = payload.get("exp")
            
            if not jti or not exp:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid token"
                )
            
            # Blacklist the token
            blacklist_token(jti, exp)
            
            # If there's a session ID, terminate the session
            session_id = payload.get("session_id")
            if session_id:
                terminate_session(session_id)
            
            # Log token revocation
            log_security_event(
                event_type="token_revoked",
                details={"token_type": "access", "jti": jti},
                agent_id=token_data.agent_id,
                severity="info"
            )
            
        elif revoke_request.token_type == "refresh":
            # Decode refresh token
            payload = jwt.decode(revoke_request.token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_signature": True})
            
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Not a refresh token"
                )
            
            jti = payload.get("jti")
            if not jti:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid token"
                )
            
            # Delete from Redis
            if redis_client:
                redis_key = f"refresh_token:{jti}"
                redis_client.delete(redis_key)
            
            # Log token revocation
            log_security_event(
                event_type="token_revoked",
                details={"token_type": "refresh", "jti": jti},
                agent_id=token_data.agent_id,
                severity="info"
            )
        
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type"
            )
        
        return {"status": "success", "message": "Token revoked"}
        
    except jwt.PyJWTError as e:
        log_security_event(
            event_type="token_revocation_failed",
            details={"error": str(e)},
            agent_id=token_data.agent_id,
            severity="warning"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token"
        )

@app.post("/logout")
async def logout(token_data: TokenData = Depends(verify_token)):
    """Log out an agent and terminate their session"""
    # Blacklist the current token
    blacklist_token(token_data.jti, token_data.exp)
    
    # Terminate the session
    terminate_session(token_data.session_id)
    
    # Log logout
    log_security_event(
        event_type="logout",
        details={"session_id": token_data.session_id},
        agent_id=token_data.agent_id,
        severity="info"
    )
    
    return {"status": "success", "message": "Successfully logged out"}

@app.post("/change-password")
async def change_password(
    password_request: PasswordChangeRequest,
    token_data: TokenData = Depends(verify_token)
):
    """Change an agent's password"""
    # Get agent from database
    agent = get_agent_by_id(token_data.agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    
    # Verify current password
    if not verify_password(password_request.current_password, agent.hashed_password, agent.salt):
        # Log failed password change attempt
        log_security_event(
            event_type="password_change_failed",
            details={"reason": "incorrect_current_password"},
            agent_id=token_data.agent_id,
            severity="warning"
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )
    
    # Generate new password hash
    new_hash, new_salt = get_password_hash(password_request.new_password)
    
    # Update password in database
    success = update_agent_password(agent.id, new_hash, new_salt)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password"
        )
    
    # Terminate all other sessions for this agent
    # In a real implementation, you might want to keep the current session active
    active_sessions = get_active_sessions_for_agent(agent.id)
    for session in active_sessions:
        if session.session_id != token_data.session_id:
            terminate_session(session.session_id)
    
    # Log successful password change
    log_security_event(
        event_type="password_changed",
        details={"terminated_sessions": len(active_sessions) - 1},
        agent_id=token_data.agent_id,
        severity="info"
    )
    
    return {"status": "success", "message": "Password changed successfully"}

@app.get("/active-sessions")
async def get_sessions(token_data: TokenData = Depends(verify_token)):
    """Get all active sessions for the current agent"""
    sessions = get_active_sessions_for_agent(token_data.agent_id)
    
    # Convert sessions to dictionary for response
    session_list = []
    for session in sessions:
        session_dict = session.dict()
        # Add "current" flag to indicate the current session
        session_dict["is_current"] = session.session_id == token_data.session_id
        session_list.append(session_dict)
    
    return {"sessions": session_list}

@app.post("/terminate-session/{session_id}")
async def terminate_other_session(
    session_id: str,
    token_data: TokenData = Depends(verify_token)
):
    """Terminate another session for the current agent"""
    # Get the session
    session = get_session(session_id)
    
    # Check if session exists and belongs to the current agent
    if not session or session.agent_id != token_data.agent_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Prevent terminating the current session through this endpoint
    if session.session_id == token_data.session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot terminate current session through this endpoint. Use /logout instead."
        )
    
    # Terminate the session
    success = terminate_session(session_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to terminate session"
        )
    
    # Log session termination
    log_security_event(
        event_type="session_terminated",
        details={"terminated_session_id": session_id},
        agent_id=token_data.agent_id,
        severity="info"
    )
    
    return {"status": "success", "message": "Session terminated"}

@app.get("/verify")
async def verify_authentication(token_data: TokenData = Depends(verify_token)):
    """Verify a token is valid and return agent info"""
    # Update session activity
    update_session_activity(token_data.session_id)
    
    return {
        "agent_id": token_data.agent_id,
        "clearance_level": token_data.clearance_level,
        "codename": token_data.codename
    }

# ==============================
# Neural Signature Endpoints
# ==============================

@app.post("/neural-signatures/register/{agent_id}")
async def register_agent_neural_signature(
    agent_id: str,
    request: Request,
    token_data: TokenData = Depends(verify_token)
):
    """Register a new neural signature for an agent"""
    # Security check - only allow administrators or the agent themselves
    if token_data.agent_id != agent_id and token_data.clearance_level < 4:
        log_security_event(
            event_type="unauthorized_neural_signature_registration",
            details={"target_agent_id": agent_id},
            agent_id=token_data.agent_id,
            severity="warning"
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to register neural signatures for other agents"
        )
    
    # Get raw signature data from request
    raw_data = await request.body()
    
    # Register new signature
    signature = register_neural_signature(agent_id, raw_data)
    
    # Log successful registration
    log_security_event(
        event_type="neural_signature_registered",
        details={"signature_id": signature.signature_id},
        agent_id=agent_id,
        severity="info"
    )
    
    return {
        "status": "success",
        "message": "Neural signature registered successfully",
        "signature_id": signature.signature_id,
        "expires_at": signature.expires_at
    }

@app.post("/neural-signatures/rotate/{agent_id}")
async def rotate_agent_neural_signature(
    agent_id: str,
    token_data: TokenData = Depends(verify_token)
):
    """Rotate an agent's neural signature"""
    # Security check - only allow administrators or the agent themselves
    if token_data.agent_id != agent_id and token_data.clearance_level < 4:
        log_security_event(
            event_type="unauthorized_neural_signature_rotation",
            details={"target_agent_id": agent_id},
            agent_id=token_data.agent_id,
            severity="warning"
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to rotate neural signatures for other agents"
        )
    
    # Rotate the signature
    success = rotate_neural_signature(agent_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate neural signature"
        )
    
    # Log successful rotation
    log_security_event(
        event_type="neural_signature_rotated",
        agent_id=agent_id,
        severity="info"
    )
    
    return {
        "status": "success",
        "message": "Neural signature rotated successfully"
    }

@app.get("/neural-signatures/status/{agent_id}")
async def get_neural_signature_status(
    agent_id: str,
    token_data: TokenData = Depends(verify_token)
):
    """Get the status of an agent's neural signature"""
    # Security check - only allow administrators or the agent themselves
    if token_data.agent_id != agent_id and token_data.clearance_level < 4:
        log_security_event(
            event_type="unauthorized_neural_signature_status_check",
            details={"target_agent_id": agent_id},
            agent_id=token_data.agent_id,
            severity="warning"
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view neural signature status for other agents"
        )
    
    # Get current signature
    current_signature = get_active_neural_signature(agent_id)
    
    if not current_signature:
        return {
            "status": "not_found",
            "message": "No active neural signature found"
        }
    
    # Calculate days until expiration
    days_valid = (current_signature.expires_at - datetime.utcnow()).days if current_signature.expires_at else 0
    
    return {
        "status": "active",
        "signature_id": current_signature.signature_id,
        "created_at": current_signature.created_at,
        "expires_at": current_signature.expires_at,
        "days_valid": days_valid,
        "rotation_count": current_signature.rotation_count
    }

@app.post("/neural-signatures/verify/{agent_id}")
async def verify_agent_neural_signature(
    agent_id: str,
    request: Request,
    api_key: bool = Depends(verify_internal_api_key)
):
    """Verify a neural signature (internal API for other services)"""
    try:
        # Extract request data
        data = await request.json()
        neural_signature_data = data.get("neural_signature_data")
        security_context = data.get("security_context", {})
        
        if not neural_signature_data:
            return {"verified": False, "error": "Missing neural signature data"}
        
        # Verify the signature
        verified = verify_neural_signature_advanced(
            agent_id, 
            neural_signature_data, 
            security_context
        )
        
        # Log verification attempt
        log_security_event(
            event_type="neural_signature_verification",
            details={
                "verified": verified, 
                "source": request.client.host,
                "security_context": {k: v for k, v in security_context.items() if k != "historical_scores"}
            },
            agent_id=agent_id,
            severity="info" if verified else "warning"
        )
        
        return {"verified": verified}
    except Exception as e:
        logger.error(f"Error in neural signature verification: {e}")
        return {"verified": False, "error": str(e)}

# ==============================
# Health and Monitoring Endpoints
# ==============================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Check Redis connection
    redis_health = True
    if redis_client:
        try:
            redis_client.ping()
        except:
            redis_health = False
    else:
        redis_health = False
    
    # Check database connection
    db_health = True
    if supabase:
        try:
            # Just run a simple query to check connection
            supabase.table("agents").select("id").limit(1).execute()
        except:
            db_health = False
    else:
        db_health = False
    
    health_status = "healthy" if redis_health and db_health else "degraded" if (redis_health or db_health) else "unhealthy"
    
    return {
        "status": health_status,
        "redis": redis_health,
        "database": db_health,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@app.get("/metrics", dependencies=[Depends(verify_internal_api_key)])
async def get_metrics():
    """Get basic service metrics (internal use only)"""
    metrics = {
        "active_sessions": 0,
        "agents_online": 0,
        "failed_login_attempts_24h": 0,
        "successful_logins_24h": 0
    }
    
    if redis_client:
        try:
            # Count active sessions
            session_keys = redis_client.keys("session:*")
            metrics["active_sessions"] = len(session_keys)
            
            # Count unique agents with active sessions
            agent_ids = set()
            for key in session_keys:
                agent_id = redis_client.hget(key, "agent_id")
                if agent_id:
                    agent_ids.add(agent_id)
            metrics["agents_online"] = len(agent_ids)
        except Exception as e:
            logger.error(f"Error getting Redis metrics: {e}")
    
    if supabase:
        try:
            # Get login metrics for the last 24 hours
            now = datetime.utcnow()
            yesterday = (now - timedelta(days=1)).isoformat()
            
            # Failed logins
            failed_logins = supabase.table("security_events")\
                .select("count", count="exact")\
                .eq("event_type", "failed_login_attempt")\
                .gte("timestamp", yesterday)\
                .execute()
            
            if failed_logins.count:
                metrics["failed_login_attempts_24h"] = failed_logins.count
            
            # Successful logins
            successful_logins = supabase.table("security_events")\
                .select("count", count="exact")\
                .eq("event_type", "successful_login")\
                .gte("timestamp", yesterday)\
                .execute()
            
            if successful_logins.count:
                metrics["successful_logins_24h"] = successful_logins.count
        except Exception as e:
            logger.error(f"Error getting database metrics: {e}")
    
    return metrics

# ==============================
# Startup and Shutdown Events
# ==============================

@app.on_event("startup")
async def startup_event():
    """Run tasks when the service starts up"""
    logger.info("Authentication Service starting up")
    
    # Check if Redis is available
    if redis_client:
        try:
            redis_client.ping()
            logger.info("Redis connection successful")
        except redis.ConnectionError:
            logger.warning("Redis connection failed - running with limited functionality")
    else:
        logger.warning("Redis client not initialized - running with limited functionality")
    
    # Check if Supabase is available
    if supabase:
        try:
            supabase.table("agents").select("id").limit(1).execute()
            logger.info("Supabase connection successful")
        except Exception as e:
            logger.warning(f"Supabase connection failed - running with limited functionality: {e}")
    else:
        logger.warning("Supabase client not initialized - running with limited functionality")

@app.on_event("shutdown")
async def shutdown_event():
    """Run tasks when the service shuts down"""
    logger.info("Authentication Service shutting down")
    
    # Close Redis connection if it exists
    if redis_client:
        redis_client.close()

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment or use default
    port = int(os.getenv("PORT", 8001))
    
    # Configure uvicorn server
    uvicorn.run(
        "authentication_service:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("ENVIRONMENT") != "production",
        log_level="info"
    )