from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from config.database import Base

class UserRole(enum.Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    TECHNICIAN = "technician"
    AUDITOR = "auditor"

class UserStatus(enum.Enum):
    """User account status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"
    EXPIRED = "expired"

class User(Base):
    """User model for authentication and authorization"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    
    # Authentication
    hashed_password = Column(String(255), nullable=False)
    password_changed_at = Column(DateTime, default=datetime.utcnow)
    failed_login_attempts = Column(Integer, default=0)
    last_login = Column(DateTime)
    
    # Authorization
    role = Column(Enum(UserRole), default=UserRole.TECHNICIAN, nullable=False)
    permissions = Column(Text)  # JSON string of specific permissions
    
    # Account status
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Active Directory integration
    ad_username = Column(String(100))
    ad_domain = Column(String(100))
    ad_sync_enabled = Column(Boolean, default=False)
    ad_last_sync = Column(DateTime)
    
    # MFA settings
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32))
    mfa_backup_codes = Column(Text)  # JSON array of backup codes
    
    # VPN settings
    vpn_enabled = Column(Boolean, default=True)
    vpn_private_key = Column(String(255))
    vpn_public_key = Column(String(255))
    vpn_ip_address = Column(String(15))  # Static VPN IP
    vpn_config = Column(Text)  # WireGuard config
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = Column(DateTime)  # Account expiration
    
    # Profile
    phone = Column(String(20))
    department = Column(String(100))
    job_title = Column(String(100))
    manager_id = Column(Integer)
    
    # Relationships
    managed_clients = relationship("Client", back_populates="assigned_user")
    created_tasks = relationship("Task", back_populates="created_by_user")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role.value}')>"
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission"""
        # Admin has all permissions
        if self.role == UserRole.ADMIN:
            return True
        
        # Check role-based permissions
        role_permissions = {
            UserRole.TECHNICIAN: [
                "client.read", "client.manage", "task.create", "task.read",
                "vpn.read", "screen.view", "screen.control", "screen.record"
            ],
            UserRole.AUDITOR: [
                "client.read", "task.read", "audit.read", "screen.view"
            ]
        }
        
        base_permissions = role_permissions.get(self.role, [])
        
        # Check specific permissions (if any)
        if self.permissions:
            import json
            try:
                specific_permissions = json.loads(self.permissions)
                base_permissions.extend(specific_permissions)
            except:
                pass
        
        return permission in base_permissions
    
    def is_account_active(self) -> bool:
        """Check if account is active and not expired"""
        if not self.is_active or self.status != UserStatus.ACTIVE:
            return False
        
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        
        return True
    
    def get_vpn_config(self) -> str:
        """Get WireGuard VPN configuration"""
        if not self.vpn_enabled or not self.vpn_private_key:
            return ""
        
        from config.settings import settings
        
        config = f"""[Interface]
PrivateKey = {self.vpn_private_key}
Address = {self.vpn_ip_address}/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {settings.VPN_SERVER_PUBLIC_KEY}
Endpoint = {settings.VPN_SERVER_ENDPOINT}:{settings.VPN_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
        return config
