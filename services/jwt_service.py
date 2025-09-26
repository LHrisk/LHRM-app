"""
JWT authentication service for access and refresh tokens
Handles token creation, validation, and refresh token management
"""

import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import secrets
import hashlib
from config import settings
from models import UserRole
import logging
import warnings

logger = logging.getLogger(__name__)

# Suppress all bcrypt-related warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*bcrypt.*")
warnings.filterwarnings("ignore", message=".*trapped.*")

# Try to initialize passlib, fallback to raw bcrypt if it fails
pwd_context = None
use_raw_bcrypt = False

try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(
        schemes=["bcrypt"], 
        deprecated="auto",
        bcrypt__rounds=12,
        bcrypt__truncate_error=False
    )
    logger.info("Using passlib CryptContext for password hashing")
except Exception as e:
    logger.warning(f"Passlib initialization failed: {e}, falling back to raw bcrypt")
    use_raw_bcrypt = True
    try:
        import bcrypt
        logger.info("Using raw bcrypt for password hashing")
    except ImportError:
        logger.error("Neither passlib nor bcrypt is available!")
        raise ImportError("No bcrypt implementation available")
class JWTService:
    """JWT token management service"""
    
    def __init__(self):
        self.secret_key = settings.SECRET_KEY
        self.algorithm = settings.ALGORITHM
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.REFRESH_TOKEN_EXPIRE_DAYS
    
    def create_access_token(self, data: Dict[str, Any]) -> str:
        """
        Create JWT access token
        
        Args:
            data: Payload data to encode
            
        Returns:
            JWT access token string
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire, "type": "access"})
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(self, user_id: str) -> str:
        """
        Create JWT refresh token
        
        Args:
            user_id: User ID to encode
            
        Returns:
            JWT refresh token string
        """
        to_encode = {
            "user_id": user_id,
            "type": "refresh",
            "exp": datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        }
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token
        
        Args:
            token: JWT token string
            token_type: Expected token type ('access' or 'refresh')
            
        Returns:
            Decoded payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get("type") != token_type:
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.JWTError:
            logger.warning("Invalid token")
            return None
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt with dynamic fallback strategy"""
        try:
            # Strategy 1: Try with raw bcrypt if flag is set
            if use_raw_bcrypt:
                return self._hash_with_raw_bcrypt(password)
            
            # Strategy 2: Try with passlib first, fallback to raw bcrypt if it fails
            try:
                # Truncate password to 72 bytes if necessary for passlib
                processed_password = password
                if len(password.encode('utf-8')) > 72:
                    logger.warning("Password too long for passlib, truncating to 72 bytes")
                    processed_password = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
                
                return pwd_context.hash(processed_password)
            except Exception as passlib_error:
                logger.warning(f"Passlib hashing failed: {passlib_error}, trying raw bcrypt")
                return self._hash_with_raw_bcrypt(password)
                
        except Exception as e:
            logger.error(f"All password hashing strategies failed: {e}")
            raise ValueError(f"Password hashing failed: {str(e)}")
    
    def _hash_with_raw_bcrypt(self, password: str) -> str:
        """Hash password using raw bcrypt with 72-byte handling"""
        try:
            import bcrypt
            
            # Ensure password is within bcrypt's 72-byte limit
            password_bytes = password.encode('utf-8')
            if len(password_bytes) > 72:
                logger.info(f"Truncating password from {len(password_bytes)} to 72 bytes for bcrypt hashing")
                password_bytes = password_bytes[:72]
            
            salt = bcrypt.gensalt(rounds=12)
            hash_bytes = bcrypt.hashpw(password_bytes, salt)
            return hash_bytes.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Raw bcrypt hashing failed: {e}")
            raise ValueError(f"Raw bcrypt hashing failed: {str(e)}")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash with multiple fallback strategies"""
        try:
            # Strategy 1: Try with raw bcrypt if flag is set or if passlib fails
            if use_raw_bcrypt:
                return self._verify_with_raw_bcrypt(plain_password, hashed_password)
            
            # Strategy 2: Try with passlib first
            try:
                return pwd_context.verify(plain_password, hashed_password)
            except Exception as passlib_error:
                logger.warning(f"Passlib verification failed: {passlib_error}, trying raw bcrypt")
                return self._verify_with_raw_bcrypt(plain_password, hashed_password)
                
        except Exception as e:
            logger.error(f"All password verification strategies failed: {e}")
            return False
    
    def _verify_with_raw_bcrypt(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password using raw bcrypt with 72-byte handling"""
        try:
            import bcrypt
            
            # Ensure password is within bcrypt's 72-byte limit
            password_bytes = plain_password.encode('utf-8')
            if len(password_bytes) > 72:
                logger.info(f"Truncating password from {len(password_bytes)} to 72 bytes for bcrypt")
                password_bytes = password_bytes[:72]
            
            # Convert hash string back to bytes if needed
            if isinstance(hashed_password, str):
                hash_bytes = hashed_password.encode('utf-8')
            else:
                hash_bytes = hashed_password
            
            return bcrypt.checkpw(password_bytes, hash_bytes)
            
        except Exception as e:
            logger.error(f"Raw bcrypt verification failed: {e}")
            return False
    
    def generate_otp(self) -> str:
        """Generate a 6-digit OTP"""
        return f"{secrets.randbelow(1000000):06d}"
    
    def hash_otp(self, otp: str) -> str:
        """Hash OTP for secure storage"""
        return hashlib.sha256(otp.encode()).hexdigest()
    
    def verify_otp(self, plain_otp: str, hashed_otp: str) -> bool:
        """Verify OTP against hash"""
        return hashlib.sha256(plain_otp.encode()).hexdigest() == hashed_otp
    
    def generate_refresh_token_hash(self, refresh_token: str) -> str:
        """Generate hash for refresh token storage"""
        return hashlib.sha256(refresh_token.encode()).hexdigest()


# Global JWT service instance
jwt_service = JWTService()
