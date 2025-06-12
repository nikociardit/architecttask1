from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey
from datetime import datetime
import enum

from config.database import Base

class TaskType(enum.Enum):
    """Task execution types"""
    POWERSHELL = "powershell"
    CMD = "cmd"
    EXECUTABLE = "executable"
    SCRIPT = "script"

class TaskStatus(enum.Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TaskPriority(enum.Enum):
    """Task priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"

class Task(Base):
    """Task execution model - clean version"""
    __tablename__ = "tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String(50), unique=True, index=True, nullable=False)
    
    # Task Details
    name = Column(String(200), nullable=False)
    description = Column(Text)
    task_type = Column(String(20), nullable=False)
    command = Column(Text, nullable=False)
    arguments = Column(Text)
    
    # Execution Settings
    timeout_seconds = Column(Integer, default=300)
    priority = Column(String(20), default=TaskPriority.NORMAL.value)
    run_as_admin = Column(Boolean, default=False)
    
    # Target
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Scheduling
    scheduled_at = Column(DateTime)
    
    # Execution Results
    status = Column(String(20), default=TaskStatus.PENDING.value, index=True)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    exit_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)
    error_message = Column(Text)
    
    # Retry Logic
    max_retries = Column(Integer, default=0)
    retry_count = Column(Integer, default=0)
    retry_delay = Column(Integer, default=60)
    
    # Additional Data
    task_data = Column(JSON)  # Renamed from metadata
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Task(id={self.id}, task_id='{self.task_id}', status='{self.status}')>"

class TaskTemplate(Base):
    """Task template model"""
    __tablename__ = "task_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    category = Column(String(100))
    
    # Template Content
    task_type = Column(String(20), nullable=False)
    command_template = Column(Text, nullable=False)
    arguments_template = Column(Text)
    
    # Default Settings
    default_timeout = Column(Integer, default=300)
    requires_approval = Column(Boolean, default=False)
    run_as_admin = Column(Boolean, default=False)
    
    # Template Parameters
    parameters = Column(JSON)
    
    # Management
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    usage_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<TaskTemplate(id={self.id}, name='{self.name}')>"
