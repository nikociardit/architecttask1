from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from datetime import datetime, timedelta
import enum

from config.database import Base

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
    """User model - clean version without relationships"""
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
    mfa_secret = Column(String(32))
    mfa_backup_codes = Column(JSON)
    
    # VPN Configuration
    vpn_enabled = Column(Boolean, default=False)
    vpn_public_key = Column(String(255))
    vpn_private_key = Column(String(255))
    vpn_ip_address = Column(String(15))
    
    # Session Management
    last_login = Column(DateTime)
    last_logout = Column(DateTime)
    current_session_token = Column(String(255))
    session_expires_at = Column(DateTime)
    
    # Preferences
    timezone = Column(String(50), default="UTC")
    language = Column(String(10), default="en")
    preferences = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
