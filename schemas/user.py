from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List
from datetime import datetime
from models.user import UserRole, UserStatus

class UserBase(BaseModel):
    """Base user schema"""
    username: str
    email: EmailStr
    full_name: str
    role: UserRole
    phone: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None

class UserCreate(UserBase):
    """User creation schema"""
    password: str
    confirm_password: str
    manager_id: Optional[int] = None
    expires_at: Optional[datetime] = None
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('passwords do not match')
        return v
    
    @validator('username')
    def username_valid(cls, v):
        if len(v) < 3:
            raise ValueError('username must be at least 3 characters')
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('username can only contain letters, numbers, hyphens, and underscores')
        return v.lower()

class UserUpdate(BaseModel):
    """User update schema"""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None
    phone: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    manager_id: Optional[int] = None
    expires_at: Optional[datetime] = None
    vpn_enabled: Optional[bool] = None
    permissions: Optional[List[str]] = None

class UserResponse(UserBase):
    """User response schema"""
    id: int
    status: UserStatus
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    vpn_enabled: bool
    vpn_ip_address: Optional[str] = None
    mfa_enabled: bool
    ad_username: Optional[str] = None
    manager_id: Optional[int] = None
    
    class Config:
        from_attributes = True

class UserListResponse(BaseModel):
    """User list response schema"""
    users: List[UserResponse]
    total: int
    page: int
    per_page: int
    pages: int

class UserVPNConfigResponse(BaseModel):
    """User VPN configuration response"""
    config: str
    private_key: str
    public_key: str
    ip_address: str
    server_endpoint: str
    
class UserProfileUpdate(BaseModel):
    """User profile update schema (self-service)"""
    full_name: Optional[str] = None
    phone: Optional[str] = None
    
class UserPasswordUpdate(BaseModel):
    """User password update schema"""
    current_password: str
    new_password: str
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('passwords do not match')
        return v

class UserStatsResponse(BaseModel):
    """User statistics response"""
    total_users: int
    active_users: int
    inactive_users: int
    admin_users: int
    technician_users: int
    auditor_users: int
    vpn_enabled_users: int
    mfa_enabled_users: int
    ad_synced_users: int
