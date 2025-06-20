# models/__init__.py
"""Database models module - completely clean version"""

from config.database import Base

# Import all models
from .user import User, UserRole, UserStatus
from .client import Client, ClientStatus, ClientType  
from .audit import AuditLog, AuditAction, AuditSeverity
from .task import Task, TaskTemplate, TaskType, TaskStatus, TaskPriority
from .screen import ScreenRecording, ScreenSession, RecordingPolicy, RecordingStatus, RecordingTrigger, SessionStatus

__all__ = [
    "Base",
    "User", "UserRole", "UserStatus",
    "Client", "ClientStatus", "ClientType", 
    "Task", "TaskTemplate", "TaskType", "TaskStatus", "TaskPriority",
    "AuditLog", "AuditAction", "AuditSeverity",
    "ScreenRecording", "ScreenSession", "RecordingPolicy", 
    "RecordingStatus", "RecordingTrigger", "SessionStatus"
]
