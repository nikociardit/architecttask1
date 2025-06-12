from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, ForeignKey
from datetime import datetime
import enum
import logging

from config.database import Base

logger = logging.getLogger(__name__)

class AuditAction(enum.Enum):
    """Audit action types"""
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    CLIENT_REGISTERED = "client_registered"
    CLIENT_UPDATED = "client_updated"
    TASK_CREATED = "task_created"
    TASK_EXECUTED = "task_executed"
    VPN_CONNECTED = "vpn_connected"
    VPN_DISCONNECTED = "vpn_disconnected"
    SCREEN_SESSION_STARTED = "screen_session_started"
    SCREEN_SESSION_ENDED = "screen_session_ended"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERMISSION_DENIED = "permission_denied"
    SECURITY_VIOLATION = "security_violation"
    PASSWORD_CHANGED = "password_changed"
    USER_DISABLED = "user_disabled"
    USER_ENABLED = "user_enabled"

class AuditSeverity(enum.Enum):
    """Audit log severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class AuditLog(Base):
    """Audit log model - clean version"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Action Information
    action = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default=AuditSeverity.INFO.value, index=True)
    
    # Context
    user_id = Column(Integer, ForeignKey("users.id"))
    client_id = Column(Integer, ForeignKey("clients.id"))
    task_id = Column(String(50))
    
    # Request Information
    ip_address = Column(String(45))
    user_agent = Column(Text)
    request_method = Column(String(10))
    request_path = Column(String(500))
    response_status = Column(Integer)
    
    # Additional Data
    audit_data = Column(JSON)  # Renamed from metadata
    
    # Timestamp
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}', timestamp='{self.timestamp}')>"
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": self.id,
            "action": self.action,
            "description": self.description,
            "severity": self.severity,
            "user_id": self.user_id,
            "client_id": self.client_id,
            "task_id": self.task_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "request_method": self.request_method,
            "request_path": self.request_path,
            "response_status": self.response_status,
            "audit_data": self.audit_data,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }
    
    @staticmethod
    def log_action(
        action: str,
        description: str,
        db,
        user_id: int = None,
        client_id: int = None,
        task_id: str = None,
        severity: str = AuditSeverity.INFO.value,
        ip_address: str = None,
        user_agent: str = None,
        audit_data: dict = None
    ):
        """Create audit log entry (static method for easy access)"""
        
        try:
            audit_log = AuditLog(
                action=action,
                description=description,
                severity=severity,
                user_id=user_id,
                client_id=client_id,
                task_id=task_id,
                ip_address=ip_address,
                user_agent=user_agent,
                audit_data=audit_data,
                timestamp=datetime.utcnow()
            )
            
            db.add(audit_log)
            db.commit()
            
            logger.debug(f"Audit log created: {action} - {description}")
            return audit_log
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create audit log: {e}")
            # Don't raise exception to avoid breaking main functionality
            return None
