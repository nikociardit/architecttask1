from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from models.task import TaskType, TaskStatus, TaskPriority

class TaskBase(BaseModel):
    """Base task schema"""
    name: str
    description: Optional[str] = None
    task_type: TaskType
    command: str
    arguments: Optional[str] = None
    working_directory: Optional[str] = None
    timeout_seconds: int = 300
    priority: TaskPriority = TaskPriority.NORMAL
    run_as_admin: bool = False

class TaskCreate(TaskBase):
    """Task creation schema"""
    client_id: Optional[int] = None
    client_ids: Optional[List[int]] = None
    target_group: Optional[str] = None
    target_filter: Optional[Dict[str, Any]] = None
    scheduled_at: Optional[datetime] = None
    run_as_user: Optional[str] = None
    environment_variables: Optional[Dict[str, str]] = None
    input_files: Optional[List[str]] = None
    output_files: Optional[List[str]] = None
    max_retries: int = 0
    retry_delay: int = 60
    requires_approval: bool = False
    
    @validator('command')
    def command_not_empty(cls, v):
        if not v.strip():
            raise ValueError('command cannot be empty')
        return v.strip()
    
    @validator('timeout_seconds')
    def timeout_valid(cls, v):
        if v < 1 or v > 3600:  # 1 second to 1 hour
            raise ValueError('timeout must be between 1 and 3600 seconds')
        return v

class TaskUpdate(BaseModel):
    """Task update schema"""
    name: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[TaskPriority] = None
    scheduled_at: Optional[datetime] = None
    timeout_seconds: Optional[int] = None
    max_retries: Optional[int] = None

class TaskExecutionResult(BaseModel):
    """Task execution result schema"""
    task_id: str
    status: TaskStatus
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

class TaskResponse(TaskBase):
    """Task response schema"""
    id: int
    task_id: str
    status: TaskStatus
    client_id: int
    created_by_user_id: int
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class TaskDetailResponse(TaskResponse):
    """Detailed task response schema"""
    target_group: Optional[str] = None
    target_filter: Optional[Dict[str, Any]] = None
    run_as_user: Optional[str] = None
    environment_variables: Optional[Dict[str, str]] = None
    input_files: Optional[List[str]] = None
    output_files: Optional[List[str]] = None
    max_retries: int = 0
    retry_delay: int = 60
    requires_approval: bool = False
    approved_by_user_id: Optional[int] = None
    approved_at: Optional[datetime] = None
    client_hostname: Optional[str] = None
    created_by_username: Optional[str] = None

class TaskListResponse(BaseModel):
    """Task list response schema"""
    tasks: List[TaskResponse]
    total: int
    page: int
    per_page: int
    pages: int

class TaskStatsResponse(BaseModel):
    """Task statistics response"""
    total_tasks: int
    pending_tasks: int
    running_tasks: int
    completed_tasks: int
    failed_tasks: int
    cancelled_tasks: int
    success_rate: float
    avg_execution_time: float

class TaskTemplateBase(BaseModel):
    """Base task template schema"""
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    task_type: TaskType
    command_template: str
    arguments_template: Optional[str] = None
    default_timeout: int = 300
    requires_approval: bool = False
    run_as_admin: bool = False

class TaskTemplateCreate(TaskTemplateBase):
    """Task template creation schema"""
    parameters: Optional[Dict[str, Any]] = None

class TaskTemplateUpdate(BaseModel):
    """Task template update schema"""
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    command_template: Optional[str] = None
    arguments_template: Optional[str] = None
    default_timeout: Optional[int] = None
    parameters: Optional[Dict[str, Any]] = None
    requires_approval: Optional[bool] = None
    run_as_admin: Optional[bool] = None
    is_active: Optional[bool] = None

class TaskTemplateResponse(TaskTemplateBase):
    """Task template response schema"""
    id: int
    parameters: Optional[Dict[str, Any]] = None
    created_by_user_id: int
    is_active: bool = True
    usage_count: int = 0
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class TaskFromTemplateRequest(BaseModel):
    """Create task from template request"""
    template_id: int
    parameter_values: Dict[str, Any] = {}
    client_id: Optional[int] = None
    client_ids: Optional[List[int]] = None
    target_group: Optional[str] = None
    scheduled_at: Optional[datetime] = None
    priority: TaskPriority = TaskPriority.NORMAL

class TaskApprovalRequest(BaseModel):
    """Task approval request"""
    approved: bool
    comments: Optional[str] = None

class TaskCancelRequest(BaseModel):
    """Task cancellation request"""
    reason: Optional[str] = None
