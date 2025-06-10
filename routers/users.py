from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from config.database import get_db
from schemas.user import (
    UserCreate, UserUpdate, UserResponse, UserListResponse,
    UserVPNConfigResponse, UserProfileUpdate, UserPasswordUpdate,
    UserStatsResponse
)
from services.auth_service import AuthService
from services.user_service import UserService
from models.audit import AuditLog, AuditAction
from models.user import UserRole
from utils.exceptions import AuthenticationError, ValidationError, PermissionError

router = APIRouter()
security_scheme = HTTPBearer()
logger = logging.getLogger(__name__)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
):
    """Get current authenticated user"""
    auth_service = AuthService(db)
    return await auth_service.get_current_user(credentials.credentials)

async def require_admin(current_user = Depends(get_current_user)):
    """Require admin role"""
    if current_user.role != UserRole.ADMIN:
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
    role: Optional[UserRole] = Query(None),
    status: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List users with pagination and filtering"""
    try:
        # Check permissions
        if not current_user.has_permission("user.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        user_service = UserService(db)
        result = await user_service.list_users(
            page=page,
            per_page=per_page,
            search=search,
            role=role,
            status=status
        )
        
        return UserListResponse(**result)
    
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )

@router.post("/", response_model=UserResponse)
async def create_user(
    request: Request,
    user_data: UserCreate,
    current_user = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create new user"""
    try:
        user_service = UserService(db)
        user = await user_service.create_user(user_data, created_by=current_user.id)
        
        # Log user creation
        AuditLog.log_action(
            action=AuditAction.USER_CREATED.value,
            description=f"User {user.username} created by {current_user.username}",
            user_id=current_user.id,
            metadata={"created_user_id": user.id},
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return UserResponse.from_orm(user)
    
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user by ID"""
    try:
        # Users can view their own profile, admins can view any
        if user_id != current_user.id and not current_user.has_permission("user.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        user_service = UserService(db)
        user = await user_service.get_user_by_id(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserResponse.from_orm(user)
    
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request,
    user_id: int,
    user_data: UserUpdate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update user"""
    try:
        # Users can update their own profile (limited), admins can update any
        if user_id != current_user.id and not current_user.has_permission("user.manage"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        user_service = UserService(db)
        user = await user_service.update_user(user_id, user_data, updated_by=current_user.id)
        
        # Log user update
        AuditLog.log_action(
            action=AuditAction.USER_UPDATED.value,
            description=f"User {user.username} updated by {current_user.username}",
            user_id=current_user.id,
            metadata={"updated_user_id": user.id},
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return UserResponse.from_orm(user)
    
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.delete("/{user_id}")
async def delete_user(
    request: Request,
    user_id: int,
    current_user = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete user"""
    try:
        user_service = UserService(db)
        user = await user_service.get_user_by_id(user_id)
        
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
        
        await user_service.delete_user(user_id)
        
        # Log user deletion
        AuditLog.log_action(
            action=AuditAction.USER_DELETED.value,
            description=f"User {user.username} deleted by {current_user.username}",
            user_id=current_user.id,
            metadata={"deleted_user_id": user_id},
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return {"message": "User deleted successfully"}
    
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/{user_id}/disable")
async def disable_user(
    request: Request,
    user_id: int,
    current_user = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Disable user account"""
    try:
        if user_id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot disable your own account"
            )
        
        user_service = UserService(db)
        user = await user_service.disable_user(user_id)
        
        # Log user disable
        AuditLog.log_action(
            action=AuditAction.USER_DISABLED.value,
            description=f"User {user.username} disabled by {current_user.username}",
            user_id=current_user.id,
            metadata={"disabled_user_id": user_id},
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return {"message": "User disabled successfully"}
    
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/{user_id}/enable")
async def enable_user(
    request: Request,
    user_id: int,
    current_user = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Enable user account"""
    try:
        user_service = UserService(db)
        user = await user_service.enable_user(user_id)
        
        # Log user enable
        AuditLog.log_action(
            action=AuditAction.USER_ENABLED.value,
            description=f"User {user.username} enabled by {current_user.username}",
            user_id=current_user.id,
            metadata={"enabled_user_id": user_id},
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return {"message": "User enabled successfully"}
    
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/{user_id}/vpn-config", response_model=UserVPNConfigResponse)
async def get_user_vpn_config(
    user_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user VPN configuration"""
    try:
        # Users can get their own VPN config, admins can get any
        if user_id != current_user.id and not current_user.has_permission("vpn.manage"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        user_service = UserService(db)
        config = await user_service.get_user_vpn_config(user_id)
        
        return UserVPNConfigResponse(**config)
    
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/{user_id}/regenerate-vpn")
async def regenerate_vpn_config(
    request: Request,
    user_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Regenerate VPN configuration for user"""
    try:
        # Users can regenerate their own VPN config, admins can regenerate any
        if user_id != current_user.id and not current_user.has_permission("vpn.manage"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        user_service = UserService(db)
        config = await user_service.regenerate_vpn_config(user_id)
        
        # Log VPN config regeneration
        AuditLog.log_action(
            action=AuditAction.VPN_CONFIG_GENERATED.value,
            description=f"VPN config regenerated for user {user_id}",
            user_id=current_user.id,
            metadata={"target_user_id": user_id},
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return UserVPNConfigResponse(**config)
    
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/stats", response_model=UserStatsResponse)
async def get_user_stats(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user statistics"""
    try:
        if not current_user.has_permission("user.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        user_service = UserService(db)
        stats = await user_service.get_user_stats()
        
        return UserStatsResponse(**stats)
    
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )

@router.put("/profile", response_model=UserResponse)
async def update_profile(
    request: Request,
    profile_data: UserProfileUpdate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user's profile"""
    try:
        user_service = UserService(db)
        user = await user_service.update_user_profile(current_user.id, profile_data)
        
        return UserResponse.from_orm(user)
    
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
