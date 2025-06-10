from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, BigInteger
from sqlalchemy.orm import relationship
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
    UPLOADING = "uploading"

class RecordingTrigger(enum.Enum):
    """Recording trigger types"""
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    APPLICATION = "application"
    USER_LOGIN = "user_login"
    SECURITY_EVENT = "security_event"

class SessionStatus(enum.Enum):
    """Screen session status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    TERMINATED = "terminated"
    ERROR = "error"

class ScreenRecording(Base):
    """Screen recording model"""
    __tablename__ = "screen_recordings"
    
    id = Column(Integer, primary_key=True, index=True)
    recording_id = Column(String(50), unique=True, index=True, nullable=False)
    
    # Recording Details
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500))
    file_size = Column(BigInteger, default=0)  # bytes
    duration = Column(Integer, default=0)  # seconds
    format = Column(String(20), default="mp4")  # mp4, webm
    quality = Column(String(20), default="medium")  # low, medium, high
    resolution = Column(String(20))  # 1920x1080
    fps = Column(Integer, default=30)
    
    # Status and Timing
    status = Column(String(20), default=RecordingStatus.SCHEDULED.value)
    trigger = Column(String(20), nullable=False)
    scheduled_at = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Target Information
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    target_user = Column(String(100))  # Windows username being recorded
    target_application = Column(String(200))  # Specific application if applicable
    
    # Management
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    approved_by_user_id = Column(Integer, ForeignKey("users.id"))
    requires_approval = Column(Boolean, default=False)
    
    # Configuration
    record_audio = Column(Boolean, default=False)
    record_microphone = Column(Boolean, default=False)
    record_webcam = Column(Boolean, default=False)
    show_cursor = Column(Boolean, default=True)
    
    # Upload and Storage
    uploaded = Column(Boolean, default=False)
    upload_path = Column(String(500))
    encrypted = Column(Boolean, default=True)
    encryption_key = Column(String(255))
    
    # Retention
    expires_at = Column(DateTime)
    auto_delete = Column(Boolean, default=True)
    
    # Metadata
    metadata = Column(JSON)  # Additional recording metadata
    error_message = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ScreenRecording(id={self.id}, recording_id='{self.recording_id}', status='{self.status}')>"
    
    def is_active(self) -> bool:
        """Check if recording is currently active"""
        return self.status == RecordingStatus.RECORDING.value
    
    def is_completed(self) -> bool:
        """Check if recording has completed"""
        return self.status in [
            RecordingStatus.COMPLETED.value,
            RecordingStatus.FAILED.value,
            RecordingStatus.CANCELLED.value
        ]
    
    def get_duration_formatted(self) -> str:
        """Get formatted duration string"""
        if not self.duration:
            return "00:00:00"
        
        hours = self.duration // 3600
        minutes = (self.duration % 3600) // 60
        seconds = self.duration % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def get_file_size_formatted(self) -> str:
        """Get formatted file size"""
        if not self.file_size:
            return "0 B"
        
        size = float(self.file_size)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def is_expired(self) -> bool:
        """Check if recording has expired"""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def can_download(self, user_id: int) -> bool:
        """Check if user can download this recording"""
        # Created by user can always download
        if self.created_by_user_id == user_id:
            return True
        
        # Admin/Auditor users can download (simplified check)
        return True  # Will be properly implemented with user role check

class ScreenSession(Base):
    """Live screen session model"""
    __tablename__ = "screen_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(50), unique=True, index=True, nullable=False)
    
    # Session Details
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Session Configuration
    control_enabled = Column(Boolean, default=False)
    audio_enabled = Column(Boolean, default=False)
    quality = Column(String(20), default="medium")
    max_fps = Column(Integer, default=30)
    
    # Status and Timing
    status = Column(String(20), default=SessionStatus.ACTIVE.value)
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime)
    last_activity = Column(DateTime, default=datetime.utcnow)
    
    # Connection Information
    connection_id = Column(String(100))  # WebSocket/WebRTC connection ID
    peer_connection = Column(Text)  # WebRTC peer connection details
    
    # Statistics
    bytes_sent = Column(BigInteger, default=0)
    bytes_received = Column(BigInteger, default=0)
    frames_sent = Column(Integer, default=0)
    avg_latency_ms = Column(Integer, default=0)
    
    # Security
    client_consent = Column(Boolean, default=False)
    consent_timestamp = Column(DateTime)
    timeout_at = Column(DateTime)
    
    # Metadata
    metadata = Column(JSON)
    error_message = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ScreenSession(id={self.id}, session_id='{self.session_id}', status='{self.status}')>"
    
    def is_active(self) -> bool:
        """Check if session is currently active"""
        return self.status == SessionStatus.ACTIVE.value and not self.is_expired()
    
    def is_expired(self) -> bool:
        """Check if session has expired"""
        if not self.timeout_at:
            return False
        return datetime.utcnow() > self.timeout_at
    
    def get_duration(self) -> int:
        """Get session duration in seconds"""
        end_time = self.ended_at or datetime.utcnow()
        return int((end_time - self.started_at).total_seconds())
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()

class RecordingPolicy(Base):
    """Recording policy configuration"""
    __tablename__ = "recording_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    
    # Policy Rules
    enabled = Column(Boolean, default=True)
    trigger_rules = Column(JSON)  # Time, user, application rules
    recording_settings = Column(JSON)  # Quality, format, etc.
    
    # Targeting
    client_filter = Column(JSON)  # Which clients this applies to
    user_filter = Column(JSON)  # Which users this applies to
    
    # Management
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    priority = Column(Integer, default=100)  # Higher number = higher priority
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<RecordingPolicy(id={self.id}, name='{self.name}')>"
