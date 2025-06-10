from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import secrets
import pyotp
import qrcode
import io
import base64
import logging

from models.user import User, UserStatus
from config.security import security
from config.settings import settings
from utils.exceptions import AuthenticationError, ValidationError

logger = logging.getLogger(__name__)

class AuthService:
    """Authentication service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def authenticate_user(
        self, 
        username: str, 
        password: str, 
        mfa_code: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """Authenticate user and return tokens"""
        
        # Get user
        user = self.db.query(User).filter(
            User.username == username.lower()
        ).first()
        
        if not user:
            raise AuthenticationError("Invalid username or password")
        
        # Check account status
        if not user.is_account_active():
            raise AuthenticationError("Account is disabled or expired")
        
        # Verify password
        if not security.verify_password(password, user.hashed_password):
            # Increment failed login attempts
            user.failed_login_attempts += 1
            self.db.commit()
            raise AuthenticationError("Invalid username or password")
        
        # Check MFA if enabled
        if user.mfa_enabled:
            if not mfa_code:
                raise AuthenticationError("MFA code required")
            
            if not await self.verify_mfa(user, mfa_code):
                raise AuthenticationError("Invalid MFA code")
        
        # Reset failed login attempts
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()
        self.db.commit()
        
        # Generate tokens
        token_data = {"sub": str(user.id), "username": user.username}
        access_token = security.create_access_token(data=token_data)
        refresh_token = security.create_refresh_token(data=token_data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role.value,
                "permissions": self._get_user_permissions(user)
            }
        }
    
    async def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token using refresh token"""
        
        try:
            payload = security.verify_token(refresh_token, "refresh")
            user_id = int(payload.get("sub"))
            
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user or not user.is_account_active():
                raise AuthenticationError("Invalid refresh token")
            
            # Generate new access token
            token_data = {"sub": str(user.id), "username": user.username}
            access_token = security.create_access_token(data=token_data)
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
            
        except Exception:
            raise AuthenticationError("Invalid refresh token")
    
    async def get_current_user(self, token: str) -> User:
        """Get current user from access token"""
        
        try:
            payload = security.verify_token(token, "access")
            user_id = int(payload.get("sub"))
            
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user or not user.is_account_active():
                raise AuthenticationError("Invalid token")
            
            return user
            
        except Exception:
            raise AuthenticationError("Invalid token")
    
    async def logout_user(self, token: str) -> bool:
        """Logout user (invalidate token if blacklist is implemented)"""
        # For now, just validate the token
        # In production, add token to blacklist
        try:
            await self.get_current_user(token)
            return True
        except:
            return False
    
    async def change_password(
        self, 
        user: User, 
        current_password: str, 
        new_password: str
    ) -> bool:
        """Change user password"""
        
        # Verify current password
        if not security.verify_password(current_password, user.hashed_password):
            raise AuthenticationError("Current password is incorrect")
        
        # Validate new password strength
        is_strong, message = security.validate_password_strength(new_password)
        if not is_strong:
            raise ValidationError(message)
        
        # Update password
        user.hashed_password = security.get_password_hash(new_password)
        user.password_changed_at = datetime.utcnow()
        self.db.commit()
        
        return True
    
    async def request_password_reset(self, email: str) -> bool:
        """Request password reset (send email)"""
        
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            # Don't reveal if email exists
            return True
        
        # Generate reset token
        reset_token = security.generate_secure_token(32)
        
        # Store reset token (implement reset token table)
        # For now, just log it
        logger.info(f"Password reset token for {email}: {reset_token}")
        
        # Send email (implement email service)
        # await email_service.send_password_reset_email(email, reset_token)
        
        return True
    
    async def confirm_password_reset(self, token: str, new_password: str) -> bool:
        """Confirm password reset with token"""
        
        # Validate token (implement reset token table)
        # For now, just validate password strength
        is_strong, message = security.validate_password_strength(new_password)
        if not is_strong:
            raise ValidationError(message)
        
        # This would normally look up the token and get the user
        # user = get_user_by_reset_token(token)
        # user.hashed_password = security.get_password_hash(new_password)
        # user.password_changed_at = datetime.utcnow()
        # delete_reset_token(token)
        # self.db.commit()
        
        return True
    
    async def setup_mfa(self, user: User, password: str) -> Dict[str, Any]:
        """Setup MFA for user"""
        
        # Verify password
        if not security.verify_password(password, user.hashed_password):
            raise AuthenticationError("Invalid password")
        
        # Generate MFA secret
        secret = pyotp.random_base32()
        
        # Create provisioning URI
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="Windows Endpoint Management"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = [security.generate_secure_token(8) for _ in range(10)]
        
        # Store secret (not yet enabled)
        user.mfa_secret = secret
        user.mfa_backup_codes = ",".join(backup_codes)
        self.db.commit()
        
        return {
            "secret": secret,
            "qr_code": f"data:image/png;base64,{img_str}",
            "backup_codes": backup_codes
        }
    
    async def verify_mfa(self, user: User, code: str) -> bool:
        """Verify MFA code"""
        
        if not user.mfa_secret:
            return False
        
        # Verify TOTP code
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code, valid_window=1):
            return True
        
        # Check backup codes
        if user.mfa_backup_codes:
            backup_codes = user.mfa_backup_codes.split(",")
            if code in backup_codes:
                # Remove used backup code
                backup_codes.remove(code)
                user.mfa_backup_codes = ",".join(backup_codes)
                self.db.commit()
                return True
        
        return False
    
    async def enable_mfa(self, user: User, code: str) -> bool:
        """Enable MFA after verification"""
        
        if await self.verify_mfa(user, code):
            user.mfa_enabled = True
            self.db.commit()
            return True
        return False
    
    async def disable_mfa(self, user: User, password: str, code: str) -> bool:
        """Disable MFA for user"""
        
        # Verify password
        if not security.verify_password(password, user.hashed_password):
            raise AuthenticationError("Invalid password")
        
        # Verify MFA code
        if not await self.verify_mfa(user, code):
            raise AuthenticationError("Invalid MFA code")
        
        # Disable MFA
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_backup_codes = None
        self.db.commit()
        
        return True
    
    def _get_user_permissions(self, user: User) -> list:
        """Get user permissions based on role"""
        
        base_permissions = []
        
        if user.role.value == "admin":
            base_permissions = [
                "user.read", "user.create", "user.update", "user.delete", "user.manage",
                "client.read", "client.create", "client.update", "client.delete", "client.manage",
                "task.read", "task.create", "task.update", "task.delete", "task.execute",
                "vpn.read", "vpn.manage", "vpn.generate",
                "screen.view", "screen.control", "screen.record", "screen.manage",
                "audit.read", "audit.export",
                "system.configure", "system.manage"
            ]
        elif user.role.value == "technician":
            base_permissions = [
                "client.read", "client.manage",
                "task.read", "task.create", "task.execute",
                "vpn.read",
                "screen.view", "screen.control", "screen.record",
                "audit.read"
            ]
        elif user.role.value == "auditor":
            base_permissions = [
                "client.read",
                "task.read",
                "screen.view",
                "audit.read", "audit.export"
            ]
        
        # Add specific permissions if any
        if user.permissions:
            try:
                import json
                specific_permissions = json.loads(user.permissions)
                base_permissions.extend(specific_permissions)
            except:
                pass
        
        return list(set(base_permissions))  # Remove duplicates
