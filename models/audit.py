from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from config.database import Base

class AuditAction(enum.Enum):
    """Audit action types"""
    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET = "password_reset"
    
    # User Management
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_DISABLED = "user_disabled"
    USER_ENABLED = "user_enabled"
    
    # Client Management
    CLIENT_REGISTERED = "client_registered"
    CLIENT_UPDATED = "client_updated"
    CLIENT_DELETED = "client_deleted"
    CLIENT_HEARTBEAT = "client_heartbeat"
    
    # Task Management
    TASK_CREATED = "task_created"
    TASK_EXECUTED = "task_executed"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_CANCELLED = "task_cancelled"
    
    # VPN Management
    VPN_CONFIG_GENERATED = "vpn_config_generated"
    VPN_CONFIG_DOWNLOADED = "vpn_config_downloaded"
    VPN_CONNECTED = "vpn_connected"
    VPN_DISCONNECTED = "vpn_disconnected"
    
    # Screen Management
    SCREEN_SESSION_STARTED = "screen_session_started"
    SCREEN_SESSION_ENDED = "screen_session_ended"
    SCREEN_RECORDING_STARTED = "screen_recording_started"
    SCREEN_RECORDING_STOPPED = "screen_recording_stopped"
    SCREEN_RECORDING_DOWNLOADED = "screen_recording_downloaded"
    
    # File Operations
    FILE_UPLOADED = "file_uploaded"
    FILE_DOWNLOADED = "file_downloaded"
    FILE_DELETED = "file_deleted"
    
    # Configuration
    CONFIG_CHANGED = "config_changed"
    POLICY_APPLIED = "policy_applied"
    
    # Security
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERMISSION_DENIED = "permission_denied"
    SECURITY_VIOLATION = "security_violation"

class AuditSeverity(enum.Enum):
    """Audit log severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class AuditLog(Base):
    """Audit log model for tracking all system activities"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Action Information
    action = Column(String(50), nullable=False)
    severity = Column(String(20), default=AuditSeverity.INFO.value)
    description = Column(Text, nullable=False)
    
    # Context
    user_id = Column(Integer, ForeignKey("users.id"))
    client_id = Column(Integer, ForeignKey("clients.id"))
    task_id = Column(String(50))
    session_id = Column(String(100))
    
    # Request Information
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(String(500))
    request_method = Column(String(10))
    request_path = Column(String(500))
    request_body = Column(Text)
    
    # Response Information
    response_status = Column(Integer)
    response_time_ms = Column(Integer)
    
    # Additional Data
    metadata = Column(JSON)  # Additional context data
    tags = Column(String(500))  # Comma-separated tags
    
    # System Information
    hostname = Column(String(100))
    process_id = Column(Integer)
    thread_id = Column(Integer)
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Remove relationships for now - can be accessed via queries
    # user = relationship("User", back_populates="audit_logs")
    # client = relationship("Client", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}', timestamp='{self.timestamp}')>"
    
    @classmethod
    def log_action(
        cls,
        action: str,
        description: str,
        user_id: int = None,
        client_id: int = None,
        task_id: str = None,
        severity: str = AuditSeverity.INFO.value,
        metadata: dict = None,
        ip_address: str = None,
        user_agent: str = None,
        **kwargs
    ):
        """Create audit log entry"""
        from config.database import get_db_session
        
        audit_log = cls(
            action=action,
            description=description,
            severity=severity,
            user_id=user_id,
            client_id=client_id,
            task_id=task_id,
            metadata=metadata,
            ip_address=ip_address,
            user_agent=user_agent,
            **kwargs
        )
        
        db = get_db_session()
        try:
            db.add(audit_log)
            db.commit()
        except Exception as e:
            db.rollback()
            # Log to file as fallback
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to create audit log: {e}")
        finally:
            db.close()
        
        return audit_log
    
    def get_formatted_timestamp(self) -> str:
        """Get formatted timestamp"""
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    def get_severity_color(self) -> str:
        """Get color code for severity level"""
        colors = {
            AuditSeverity.INFO.value: "blue",
            AuditSeverity.WARNING.value: "yellow",
            AuditSeverity.ERROR.value: "red",
            AuditSeverity.CRITICAL.value: "purple"
        }
        return colors.get(self.severity, "gray")
    
    def to_dict(self) -> dict:
        """Convert audit log to dictionary"""
        return {
            "id": self.id,
            "action": self.action,
            "severity": self.severity,
            "description": self.description,
            "user_id": self.user_id,
            "client_id": self.client_id,
            "task_id": self.task_id,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }
