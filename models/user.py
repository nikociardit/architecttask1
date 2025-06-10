from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import enum
import secrets
import hashlib

from config.database import Base
from config.security import security

class UserRole(enum.Enum):
    """User roles with different permission levels"""
    ADMIN = "admin"
    TECHNICIAN = "technician"
    AUDITOR = "auditor"

class UserStatus(enum.Enum):
    """User account status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"
    LOCKED = "locked"

class User(Base):
    """User model with authentication and authorization"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(200), nullable=False)
    
    # Authentication
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    role = Column(String(20), default=UserRole.TECHNICIAN.value)
    status = Column(String(20), default=UserStatus.ACTIVE.value)
    
    # Password policy
    password_expires_at = Column(DateTime)
    password_changed_at = Column(DateTime)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    
    # Multi-factor authentication
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32))  # TOTP secret
    mfa_backup_codes = Column(JSON)  # List of backup codes
    
    # VPN Configuration
    vpn_enabled = Column(Boolean, default=False)
    vpn_public_key = Column(String(255))
    vpn_private_key = Column(String(255))
    vpn_ip_address = Column(String(15))  # VPN IP assignment
    
    # Active Directory Integration
    ad_guid = Column(String(36))  # Active Directory GUID
    ad_domain = Column(String(100))
    ad_sync_enabled = Column(Boolean, default=False)
    ad_last_sync = Column(DateTime)
    
    # Session Management
    last_login = Column(DateTime)
    last_logout = Column(DateTime)
    current_session_token = Column(String(255))
    session_expires_at = Column(DateTime)
    
    # Preferences and Settings
    timezone = Column(String(50), default="UTC")
    language = Column(String(10), default="en")
    notifications_enabled = Column(Boolean, default=True)
    preferences = Column(JSON)  # User preferences as JSON
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
    
    def set_password(self, password: str):
        """Set user password with hashing"""
        self.password_hash = security.get_password_hash(password)
        self.password_changed_at = datetime.utcnow()
        self.password_expires_at = datetime.utcnow() + timedelta(days=90)  # 90-day expiry
    
    def verify_password(self, password: str) -> bool:
        """Verify password against hash"""
        return security.verify_password(password, self.password_hash)
    
    def is_password_expired(self) -> bool:
        """Check if password has expired"""
        if not self.password_expires_at:
            return False
        return datetime.utcnow() > self.password_expires_at
    
    def is_account_locked(self) -> bool:
        """Check if account is locked"""
        if self.status == UserStatus.LOCKED.value:
            return True
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False
    
    def increment_failed_login(self):
        """Increment failed login attempts and lock if threshold exceeded"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Lock after 5 failed attempts
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
            self.status = UserStatus.LOCKED.value
    
    def reset_failed_login(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        if self.status == UserStatus.LOCKED.value:
            self.status = UserStatus.ACTIVE.value
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission"""
        role_permissions = {
            UserRole.ADMIN.value: [
                "user.create", "user.read", "user.update", "user.delete", "user.manage",
                "client.create", "client.read", "client.update", "client.delete", "client.manage",
                "task.create", "task.read", "task.update", "task.delete", "task.execute",
                "vpn.create", "vpn.read", "vpn.update", "vpn.delete", "vpn.manage",
                "screen.create", "screen.read", "screen.update", "screen.delete", "screen.record", "screen.view", "screen.manage",
                "audit.read", "audit.export", "audit.manage",
                "system.configure", "system.manage"
            ],
            UserRole.TECHNICIAN.value: [
                "client.read", "client.update", "client.manage",
                "task.create", "task.read", "task.execute",
                "vpn.read", "vpn.manage",
                "screen.read", "screen.view", "screen.record",
                "audit.read"
            ],
            UserRole.AUDITOR.value: [
                "client.read",
                "task.read",
                "screen.read",
                "audit.read", "audit.export"
            ]
        }
        
        user_permissions = role_permissions.get(self.role, [])
        return permission in user_permissions
    
    def get_vpn_config(self) -> str:
        """Generate WireGuard VPN configuration"""
        if not self.vpn_enabled or not self.vpn_private_key:
            return None
        
        config = f"""[Interface]
PrivateKey = {self.vpn_private_key}
Address = {self.vpn_ip_address}/24
DNS = 8.8.8.8

[Peer]
PublicKey = SERVER_PUBLIC_KEY_PLACEHOLDER
Endpoint = SERVER_ENDPOINT_PLACEHOLDER:51820
AllowedIPs = 0.0.0.0/0
"""
        return config
    
    def update_session(self, token: str, expires_in: int = 3600):
        """Update user session information"""
        self.current_session_token = token
        self.session_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        self.last_login = datetime.utcnow()
    
    def clear_session(self):
        """Clear user session"""
        self.current_session_token = None
        self.session_expires_at = None
        self.last_logout = datetime.utcnow()
    
    def is_session_valid(self) -> bool:
        """Check if current session is valid"""
        if not self.current_session_token or not self.session_expires_at:
            return False
        return datetime.utcnow() < self.session_expires_at
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert user to dictionary"""
        user_dict = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "status": self.status,
            "is_active": self.is_active,
            "mfa_enabled": self.mfa_enabled,
            "vpn_enabled": self.vpn_enabled,
            "vpn_ip_address": self.vpn_ip_address,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
        
        if include_sensitive:
            user_dict.update({
                "password_expires_at": self.password_expires_at.isoformat() if self.password_expires_at else None,
                "failed_login_attempts": self.failed_login_attempts,
                "locked_until": self.locked_until.isoformat() if self.locked_until else None
            })
        
        return user_dict
