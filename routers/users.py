from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from typing import List, Optional
import logging

from config.database import get_db
from config.security import security
from models.user import User, UserRole, UserStatus
from models.audit import AuditLog
from routers.auth import get_current_user

router = APIRouter()
logger = logging.getLogger(__name__)

# Pydantic models
from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    full_name: str
    role: str = "technician"
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    status: Optional[str] = None
    is_active: Optional[bool] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    status: str
    is_active: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    mfa_enabled: bool
    vpn_enabled: bool

class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int
    page: int
    per_page: int

def require_admin(current_user: User = Depends(get_current_user)):
    """Require admin role"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List users with pagination and filtering"""
    try:
        # Check permissions - admin can see all, others only themselves
        if current_user.role != "admin":
            # Non-admin users can only see their own info
            user_data = UserResponse(
                id=current_user.id,
                username=current_user.username,
                email=current_user.email,
                full_name=current_user.full_name,
                role=current_user.role,
                status=current_user.status,
                is_active=current_user.is_active,
                last_login=current_user.last_login,
                created_at=current_user.created_at,
                mfa_enabled=current_user.mfa_enabled,
                vpn_enabled=current_user.vpn_enabled
            )
            return UserListResponse(
                users=[user_data],
                total=1,
                page=1,
                per_page=per_page
            )
        
        # Admin can see all users
        query = db.query(User)
        
        # Apply search filter
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    User.username.ilike(search_term),
                    User.email.ilike(search_term),
                    User.full_name.ilike(search_term)
                )
            )
        
        # Apply role filter
        if role:
            query = query.filter(User.role == role)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        users = query.offset(offset).limit(per_page).all()
        
        # Convert to response format
        user_responses = []
        for user in users:
            user_responses.append(UserResponse(
                id=user.id,
                username=user.username,
                email=user.email,
                full_name=user.full_name,
                role=user.role,
                status=user.status,
                is_active=user.is_active,
                last_login=user.last_login,
                created_at=user.created_at,
                mfa_enabled=user.mfa_enabled,
                vpn_enabled=user.vpn_enabled
            ))
        
        return UserListResponse(
            users=user_responses,
            total=total,
            page=page,
            per_page=per_page
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/", response_model=UserResponse)
async def create_user(
    request: Request,
    user_data: UserCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create new user (admin only)"""
    try:
        # Check if username already exists
        existing_user = db.query(User).filter(User.username == user_data.username.lower()).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        
        # Check if email already exists
        existing_email = db.query(User).filter(User.email == user_data.email).first()
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already exists"
            )
        
        # Validate password
        if len(user_data.password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters long"
            )
        
        # Create new user
        new_user = User(
            username=user_data.username.lower(),
            email=user_data.email,
            full_name=user_data.full_name,
            role=user_data.role,
            status="active",
            is_active=True,
            password_hash=security.get_password_hash(user_data.password),
            created_at=datetime.utcnow()
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Log user creation
        AuditLog.log_action(
            action="user_created",
            description=f"User {new_user.username} created by {current_user.username}",
            user_id=current_user.id,
            ip_address=getattr(request.client, 'host', None),
            db=db
        )
        
        return UserResponse(
            id=new_user.id,
            username=new_user.username,
            email=new_user.email,
            full_name=new_user.full_name,
            role=new_user.role,
            status=new_user.status,
            is_active=new_user.is_active,
            last_login=new_user.last_login,
            created_at=new_user.created_at,
            mfa_enabled=new_user.mfa_enabled,
            vpn_enabled=new_user.vpn_enabled
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user by ID"""
    try:
        # Users can view their own profile, admins can view any
        if user_id != current_user.id and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            status=user.status,
            is_active=user.is_active,
            last_login=user.last_login,
            created_at=user.created_at,
            mfa_enabled=user.mfa_enabled,
            vpn_enabled=user.vpn_enabled
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request,
    user_id: int,
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update user"""
    try:
        # Users can update their own profile (limited), admins can update any
        if user_id != current_user.id and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Update allowed fields
        if user_data.email is not None:
            # Check if email already exists
            existing_email = db.query(User).filter(
                User.email == user_data.email,
                User.id != user_id
            ).first()
            if existing_email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already exists"
                )
            user.email = user_data.email
        
        if user_data.full_name is not None:
            user.full_name = user_data.full_name
        
        # Only admin can change role and status
        if current_user.role == "admin":
            if user_data.role is not None:
                user.role = user_data.role
            if user_data.status is not None:
                user.status = user_data.status
            if user_data.is_active is not None:
                user.is_active = user_data.is_active
        
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        
        # Log user update
        AuditLog.log_action(
            action="user_updated",
            description=f"User {user.username} updated by {current_user.username}",
            user_id=current_user.id,
            ip_address=getattr(request.client, 'host', None),
            db=db
        )
        
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            status=user.status,
            is_active=user.is_active,
            last_login=user.last_login,
            created_at=user.created_at,
            mfa_enabled=user.mfa_enabled,
            vpn_enabled=user.vpn_enabled
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.delete("/{user_id}")
async def delete_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete user (admin only)"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prevent self-deletion
        if user_id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account"
            )
        
        # Soft delete - disable instead of actual deletion
        user.status = "disabled"
        user.is_active = False
        user.updated_at = datetime.utcnow()
        db.commit()
        
        # Log user deletion
        AuditLog.log_action(
            action="user_deleted",
            description=f"User {user.username} deleted by {current_user.username}",
            user_id=current_user.id,
            ip_address=getattr(request.client, 'host', None),
            db=db
        )
        
        return {"message": "User deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/stats/summary")
async def get_user_stats(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get user statistics (admin only)"""
    try:
        total_users = db.query(User).count()
        active_users = db.query(User).filter(User.status == "active").count()
        admin_users = db.query(User).filter(User.role == "admin").count()
        technician_users = db.query(User).filter(User.role == "technician").count()
        auditor_users = db.query(User).filter(User.role == "auditor").count()
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": total_users - active_users,
            "admin_users": admin_users,
            "technician_users": technician_users,
            "auditor_users": auditor_users
        }
        
    except Exception as e:
        logger.error(f"Error getting user stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
