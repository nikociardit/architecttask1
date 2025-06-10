from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from config.database import Base

class TaskType(enum.Enum):
    """Task execution types"""
    POWERSHELL = "powershell"
    CMD = "cmd"
    EXECUTABLE = "executable"
    SCRIPT = "script"
    UPDATE = "update"
    RESTART = "restart"

class TaskStatus(enum.Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class TaskPriority(enum.Enum):
    """Task priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"

class Task(Base):
    """Task model for remote command execution"""
    __tablename__ = "tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String(50), unique=True, index=True, nullable=False)
    
    # Task Definition
    name = Column(String(200), nullable=False)
    description = Column(Text)
    task_type = Column(String(20), nullable=False)
    command = Column(Text, nullable=False)
    arguments = Column(Text)
    working_directory = Column(String(500))
    
    # Scheduling
    scheduled_at = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    timeout_seconds = Column(Integer, default=300)  # 5 minutes default
    
    # Status and Results
    status = Column(String(20), default=TaskStatus.PENDING.value)
    priority = Column(String(20), default=TaskPriority.NORMAL.value)
    exit_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)
    error_message = Column(Text)
    
    # Execution Context
    run_as_user = Column(String(100))
    run_as_admin = Column(Boolean, default=False)
    environment_variables = Column(JSON)
    
    # Targeting
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    target_group = Column(String(100))  # For group targeting
    target_filter = Column(JSON)  # Advanced filtering criteria
    
    # Management
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    approved_by_user_id = Column(Integer, ForeignKey("users.id"))
    requires_approval = Column(Boolean, default=False)
    approved_at = Column(DateTime)
    
    # Retry Logic
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=0)
    retry_delay = Column(Integer, default=60)  # seconds
    
    # File Operations
    input_files = Column(JSON)  # Files to upload before execution
    output_files = Column(JSON)  # Files to download after execution
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    client = relationship("Client", back_populates="tasks")
    created_by_user = relationship("User", foreign_keys=[created_by_user_id], back_populates="created_tasks")
    approved_by_user = relationship("User", foreign_keys=[approved_by_user_id])
    
    def __repr__(self):
        return f"<Task(id={self.id}, name='{self.name}', status='{self.status}')>"
    
    def is_pending(self) -> bool:
        """Check if task is pending execution"""
        return self.status == TaskStatus.PENDING.value
    
    def is_running(self) -> bool:
        """Check if task is currently running"""
        return self.status == TaskStatus.RUNNING.value
    
    def is_completed(self) -> bool:
        """Check if task has completed (success or failure)"""
        return self.status in [
            TaskStatus.COMPLETED.value,
            TaskStatus.FAILED.value,
            TaskStatus.CANCELLED.value,
            TaskStatus.TIMEOUT.value
        ]
    
    def is_successful(self) -> bool:
        """Check if task completed successfully"""
        return (
            self.status == TaskStatus.COMPLETED.value and
            (self.exit_code is None or self.exit_code == 0)
        )
    
    def can_retry(self) -> bool:
        """Check if task can be retried"""
        return (
            self.status in [TaskStatus.FAILED.value, TaskStatus.TIMEOUT.value] and
            self.retry_count < self.max_retries
        )
    
    def get_duration(self) -> int:
        """Get task execution duration in seconds"""
        if not self.started_at:
            return 0
        
        end_time = self.completed_at or datetime.utcnow()
        return int((end_time - self.started_at).total_seconds())
    
    def get_formatted_command(self) -> str:
        """Get formatted command with arguments"""
        if self.arguments:
            return f"{self.command} {self.arguments}"
        return self.command
    
    def needs_approval(self) -> bool:
        """Check if task needs approval"""
        return (
            self.requires_approval and
            not self.approved_by_user_id
        )
    
    def to_execution_dict(self) -> dict:
        """Convert task to execution dictionary for client"""
        return {
            "task_id": self.task_id,
            "type": self.task_type,
            "command": self.command,
            "arguments": self.arguments,
            "working_directory": self.working_directory,
            "timeout": self.timeout_seconds,
            "run_as_user": self.run_as_user,
            "run_as_admin": self.run_as_admin,
            "environment_variables": self.environment_variables or {},
            "input_files": self.input_files or [],
            "output_files": self.output_files or []
        }

class TaskTemplate(Base):
    """Task template for reusable tasks"""
    __tablename__ = "task_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    category = Column(String(100))
    
    # Template Definition
    task_type = Column(String(20), nullable=False)
    command_template = Column(Text, nullable=False)
    arguments_template = Column(Text)
    default_timeout = Column(Integer, default=300)
    
    # Parameters
    parameters = Column(JSON)  # Parameter definitions
    requires_approval = Column(Boolean, default=False)
    run_as_admin = Column(Boolean, default=False)
    
    # Management
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    usage_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    created_by_user = relationship("User", foreign_keys=[created_by_user_id])
    
    def __repr__(self):
        return f"<TaskTemplate(id={self.id}, name='{self.name}')>"
