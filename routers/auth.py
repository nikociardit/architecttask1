from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import logging

from config.database import get_db
from config.security import security
from models.user import User, UserRole, UserStatus
from models.audit import AuditLog

router = APIRouter()
security_scheme = HTTPBearer()
logger = logging.getLogger(__name__)

# Pydantic models for requests/responses
from pydantic import BaseModel, EmailStr
from typing import Optional

class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class TokenValidationResponse(BaseModel):
    valid: bool
    user_id: Optional[int] = None
    username: Optional[str] = None
    role: Optional[str] = None

@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """User login endpoint"""
    try:
        # Get user by username
        user = db.query(User).filter(User.username == login_data.username.lower()).first()
        
        if not user:
            # Log failed login attempt
            AuditLog.log_action(
                action="login_failed",
                description=f"Failed login attempt for unknown user: {login_data.username}",
                ip_address=getattr(request.client, 'host', None),
                db=db
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Check if account is active
        if not user.is_active or user.status != "active":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is disabled"
            )
        
        # Verify password
        if not security.verify_password(login_data.password, user.password_hash):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.status = "locked"
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.commit()
            
            # Log failed login
            AuditLog.log_action(
                action="login_failed",
                description=f"Failed login attempt for user: {user.username}",
                user_id=user.id,
                ip_address=getattr(request.client, 'host', None),
                db=db
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Reset failed login attempts on successful login
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()
        user.locked_until = None
        db.commit()
        
        # Generate JWT token
        token_data = {"sub": str(user.id), "username": user.username, "role": user.role}
        access_token = security.create_access_token(data=token_data)
        
        # Log successful login
        AuditLog.log_action(
            action="login",
            description=f"User {user.username} logged in successfully",
            user_id=user.id,
            ip_address=getattr(request.client, 'host', None),
            db=db
        )
        
        return LoginResponse(
            access_token=access_token,
            expires_in=30 * 60,  # 30 minutes
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    try:
        payload = security.verify_token(credentials.credentials)
        user_id = int(payload.get("sub"))
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        
        return user
        
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """User logout endpoint"""
    try:
        # Log logout
        AuditLog.log_action(
            action="logout",
            description=f"User {current_user.username} logged out",
            user_id=current_user.id,
            ip_address=getattr(request.client, 'host', None),
            db=db
        )
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/change-password")
async def change_password(
    request: Request,
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    try:
        # Verify current password
        if not security.verify_password(password_data.current_password, current_user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Validate new password strength
        if len(password_data.new_password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters long"
            )
        
        # Update password
        current_user.password_hash = security.get_password_hash(password_data.new_password)
        current_user.password_changed_at = datetime.utcnow()
        db.commit()
        
        # Log password change
        AuditLog.log_action(
            action="password_changed",
            description=f"User {current_user.username} changed password",
            user_id=current_user.id,
            ip_address=getattr(request.client, 'host', None),
            db=db
        )
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Change password error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/validate", response_model=TokenValidationResponse)
async def validate_token(
    current_user: User = Depends(get_current_user)
):
    """Validate access token"""
    return TokenValidationResponse(
        valid=True,
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role
    )

@router.get("/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "mfa_enabled": current_user.mfa_enabled,
        "vpn_enabled": current_user.vpn_enabled
    }
