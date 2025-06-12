from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey, BigInteger
from datetime import datetime
import enum

from config.database import Base

class RecordingStatus(enum.Enum):
    """Screen recording status"""
    SCHEDULED = "scheduled"
    RECORDING = "recording"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class RecordingTrigger(enum.Enum):
    """Recording trigger types"""
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    APPLICATION = "application"
    USER_LOGIN = "user_login"

class SessionStatus(enum.Enum):
    """Screen session status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    TERMINATED = "terminated"
    ERROR = "error"

class ScreenRecording(Base):
    """Screen recording model - clean version"""
    __tablename__ = "screen_recordings"
    
    id = Column(Integer, primary_key=True, index=True)
    recording_id = Column(String(50), unique=True, index=True, nullable=False)
    
    # Recording Details
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500))
    file_size = Column(BigInteger, default=0)
    duration = Column(Integer, default=0)
    format = Column(String(20), default="mp4")
    quality = Column(String(20), default="medium")
    
    # Status and Timing
    status = Column(String(20), default=RecordingStatus.SCHEDULED.value)
    trigger = Column(String(20), nullable=False)
    scheduled_at = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Target Information
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    target_user = Column(String(100))
    
    # Management
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    requires_approval = Column(Boolean, default=False)
    
    # Configuration
    record_audio = Column(Boolean, default=False)
    show_cursor = Column(Boolean, default=True)
    
    # Storage
    expires_at = Column(DateTime)
    auto_delete = Column(Boolean, default=True)
    
    # Additional Data
    recording_data = Column(JSON)  # Renamed from metadata
    error_message = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ScreenRecording(id={self.id}, recording_id='{self.recording_id}')>"

class ScreenSession(Base):
    """Live screen session model - clean version"""
    __tablename__ = "screen_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(50), unique=True, index=True, nullable=False)
    
    # Session Details
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Configuration
    control_enabled = Column(Boolean, default=False)
    audio_enabled = Column(Boolean, default=False)
    quality = Column(String(20), default="medium")
    
    # Status
    status = Column(String(20), default=SessionStatus.ACTIVE.value)
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime)
    
    # Additional Data
    session_data = Column(JSON)  # Renamed from metadata
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ScreenSession(id={self.id}, session_id='{self.session_id}')>"

class RecordingPolicy(Base):
    """Recording policy model - clean version"""
    __tablename__ = "recording_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    
    # Policy Rules
    enabled = Column(Boolean, default=True)
    trigger_rules = Column(JSON)
    recording_settings = Column(JSON)
    
    # Management
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    priority = Column(Integer, default=100)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<RecordingPolicy(id={self.id}, name='{self.name}')>"
