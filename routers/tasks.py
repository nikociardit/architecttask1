from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from config.database import get_db
from schemas.task import (
    TaskCreate, TaskUpdate, TaskExecutionResult, TaskResponse,
    TaskDetailResponse, TaskListResponse, TaskStatsResponse,
    TaskTemplateCreate, TaskTemplateUpdate, TaskTemplateResponse,
    TaskFromTemplateRequest, TaskApprovalRequest, TaskCancelRequest
)
from services.auth_service import AuthService
from services.task_service import TaskService
from models.audit import AuditLog, AuditAction

router = APIRouter()
security_scheme = HTTPBearer()
logger = logging.getLogger(__name__)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
):
    """Get current authenticated user"""
    auth_service = AuthService(db)
    return await auth_service.get_current_user(credentials.credentials)

@router.get("/", response_model=TaskListResponse)
async def list_tasks(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None),
    client_id: Optional[int] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List tasks with pagination and filtering"""
    try:
        if not current_user.has_permission("task.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        task_service = TaskService(db)
        result = await task_service.list_tasks(
            page=page,
            per_page=per_page,
            status=status,
            client_id=client_id,
            user_id=current_user.id if current_user.role.value != "admin" else None
        )
        
        return TaskListResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing tasks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/", response_model=TaskResponse)
async def create_task(
    request: Request,
    task_data: TaskCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new task"""
    try:
        if not current_user.has_permission("task.create"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        task_service = TaskService(db)
        task = await task_service.create_task(task_data, current_user.id)
        
        # Log task creation
        AuditLog.log_action(
            action=AuditAction.TASK_CREATED.value,
            description=f"Task '{task.name}' created by {current_user.username}",
            user_id=current_user.id,
            task_id=task.task_id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return TaskResponse.from_orm(task)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating task: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/{task_id}", response_model=TaskDetailResponse)
async def get_task(
    task_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get task details by ID"""
    try:
        if not current_user.has_permission("task.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        task_service = TaskService(db)
        task = await task_service.get_task_by_id(task_id)
        
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        # Check if user can view this task
        if (current_user.role.value != "admin" and 
            task.created_by_user_id != current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        return TaskDetailResponse.from_orm(task)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting task {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/{task_id}/cancel")
async def cancel_task(
    task_id: int,
    cancel_data: TaskCancelRequest,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cancel task"""
    try:
        if not current_user.has_permission("task.execute"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        task_service = TaskService(db)
        task = await task_service.cancel_task(task_id, current_user.id, cancel_data.reason)
        
        # Log task cancellation
        AuditLog.log_action(
            action=AuditAction.TASK_CANCELLED.value,
            description=f"Task '{task.name}' cancelled by {current_user.username}",
            user_id=current_user.id,
            task_id=task.task_id,
            metadata={"reason": cancel_data.reason},
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return {"message": "Task cancelled successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling task {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/{task_id}/result")
async def submit_task_result(
    task_id: str,
    result_data: TaskExecutionResult,
    request: Request,
    db: Session = Depends(get_db)
):
    """Submit task execution result (called by client)"""
    try:
        task_service = TaskService(db)
        task = await task_service.update_task_result(task_id, result_data)
        
        # Log task completion
        action = (AuditAction.TASK_COMPLETED.value if result_data.status.value == "completed" 
                 else AuditAction.TASK_FAILED.value)
        
        AuditLog.log_action(
            action=action,
            description=f"Task '{task.name}' {result_data.status.value}",
            client_id=task.client_id,
            task_id=task.task_id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return {"message": "Task result submitted successfully"}
    
    except Exception as e:
        logger.error(f"Error submitting task result for {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/stats", response_model=TaskStatsResponse)
async def get_task_stats(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get task statistics"""
    try:
        if not current_user.has_permission("task.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        task_service = TaskService(db)
        stats = await task_service.get_task_stats()
        
        return TaskStatsResponse(**stats)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting task stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# Task Template endpoints
@router.get("/templates/", response_model=List[TaskTemplateResponse])
async def list_task_templates(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List task templates"""
    try:
        if not current_user.has_permission("task.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        task_service = TaskService(db)
        templates = await task_service.list_task_templates()
        
        return [TaskTemplateResponse.from_orm(t) for t in templates]
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing task templates: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/from-template/", response_model=TaskResponse)
async def create_task_from_template(
    request: Request,
    template_data: TaskFromTemplateRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create task from template"""
    try:
        if not current_user.has_permission("task.create"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        task_service = TaskService(db)
        task = await task_service.create_task_from_template(template_data, current_user.id)
        
        return TaskResponse.from_orm(task)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating task from template: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
