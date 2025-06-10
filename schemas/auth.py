from pydantic import BaseModel, EmailStr, validator
from typing import Optional
from datetime import datetime

class LoginRequest(BaseModel):
    """Login request schema"""
    username: str
    password: str
    mfa_code: Optional[str] = None
    remember_me: bool = False

class LoginResponse(BaseModel):
    """Login response schema"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

class RefreshTokenRequest(BaseModel):
    """Refresh token request schema"""
    refresh_token: str

class RefreshTokenResponse(BaseModel):
    """Refresh token response schema"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class ChangePasswordRequest(BaseModel):
    """Change password request schema"""
    current_password: str
    new_password: str
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('passwords do not match')
        return v

class ResetPasswordRequest(BaseModel):
    """Reset password request schema"""
    email: EmailStr

class ResetPasswordConfirmRequest(BaseModel):
    """Reset password confirmation schema"""
    token: str
    new_password: str
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('passwords do not match')
        return v

class TokenValidationResponse(BaseModel):
    """Token validation response schema"""
    valid: bool
    user_id: Optional[int] = None
    username: Optional[str] = None
    role: Optional[str] = None
    expires_at: Optional[datetime] = None

class MFASetupRequest(BaseModel):
    """MFA setup request schema"""
    password: str

class MFASetupResponse(BaseModel):
    """MFA setup response schema"""
    secret: str
    qr_code: str
    backup_codes: list[str]

class MFAVerifyRequest(BaseModel):
    """MFA verification request schema"""
    code: str

class MFADisableRequest(BaseModel):
    """MFA disable request schema"""
    password: str
    code: str
