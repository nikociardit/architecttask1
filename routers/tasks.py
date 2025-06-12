from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from typing import List, Optional
import logging
from datetime import datetime
import uuid

from config.database import get_db
from models.task import Task, TaskTemplate, TaskStatus, TaskType, TaskPriority
from models.audit import AuditLog
from routers.auth import get_current_user
from models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)

# Pydantic models
from pydantic import BaseModel

class TaskCreate(BaseModel):
    name: str
    description: Optional[str] = None
    task_type: str = "powershell"
    command: str
    arguments: Optional[str] = None
    timeout_seconds: int = 300
    priority: str = "normal"
    client_id: int
    scheduled_at: Optional[datetime] = None
    run_as_admin: bool = False

class TaskResponse(BaseModel):
    id: int
    task_id: str
    name: str
    description: Optional[str] = None
    task_type: str
    command: str
    status: str
    client_id: int
    created_by_user_id: int
    created_at: datetime
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    exit_code: Optional[int] = None

class TaskExecutionResult(BaseModel):
    task_id: str
    status: str
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    error_message: Optional[str] = None

class TaskListResponse(BaseModel):
    tasks: List[TaskResponse]
    total: int
    page: int
    per_page: int

@router.get("/", response_model=TaskListResponse)
async def list_tasks(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None),
    client_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List tasks with pagination and filtering"""
    try:
        query = db.query(Task)
        
        # Non-admin users can only see their own tasks
        if current_user.role != "admin":
            query = query.filter(Task.created_by_user_id == current_user.id)
        
        # Apply filters
        if status:
            query = query.filter(Task.status == status)
        if client_id:
            query = query.filter(Task.client_id == client_id)
        
        # Order by creation time (newest first)
        query = query.order_by(Task.created_at.desc())
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        tasks = query.offset(offset).limit(per_page).all()
        
        # Convert to response format
        task_responses = []
        for task in tasks:
            task_responses.append(TaskResponse(
                id=task.id,
                task_id=task.task_id,
                name=task.name,
                description=task.description,
                task_type=task.task_type,
                command=task.command,
                status=task.status,
                client_id=task.client_id,
                created_by_user_id=task.created_by_user_id,
                created_at=task.created_at,
                scheduled_at=task.scheduled_at,
                started_at=task.started_at,
                completed_at=task.completed_at,
                exit_code=task.exit_code
            ))
        
        return TaskListResponse(
            tasks=task_responses,
            total=total,
            page=page,
            per_page=per_page
        )
        
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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new task"""
    try:
        # Check if user has permission to create tasks
        if current_user.role not in ["admin", "technician"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to create tasks"
            )
        
        # Validate command
        if not task_data.command.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Command cannot be empty"
            )
        
        # Check if client exists
        from models.client import Client
        client = db.query(Client).filter(Client.id == task_data.client_id).first()
        if not client:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Client not found"
            )
        
        # Generate unique task ID
        task_id = str(uuid.uuid4())[:8]
        
        # Create new task
        new_task = Task(
            task_id=task_id,
            name=task_data.name,
            description=task_data.description,
            task_type=task_data.task_type,
            command=task_data.command,
            arguments=task_data.arguments,
            timeout_seconds=task_data.timeout_seconds,
            priority=task_data.priority,
            client_id=task_data.client_id,
            created_by_user_id=current_user.id,
            scheduled_at=task_data.scheduled_at or datetime.utcnow(),
            run_as_admin=task_data.run_as_admin,
            status="pending",
            created_at=datetime.utcnow()
        )
        
        db.add(new_task)
        db.commit()
        db.refresh(new_task)
        
        # Log task creation
        AuditLog.log_action(
            action="task_created",
            description=f"Task '{new_task.name}' created by {current_user.username} for client {client.hostname}",
            user_id=current_user.id,
            client_id=client.id,
            task_id=new_task.task_id,
            ip_address=getattr(request.client, 'host', None),
            db=db
        )
        
        logger.info(f"Task {new_task.task_id} created by {current_user.username}")
        return TaskResponse(
            id=new_task.id,
            task_id=new_task.task_id,
            name=new_task.name,
            description=new_task.description,
            task_type=new_task.task_type,
            command=new_task.command,
            status=new_task.status,
            client_id=new_task.client_id,
            created_by_user_id=new_task.created_by_user_id,
            created_at=new_task.created_at,
            scheduled_at=new_task.scheduled_at,
            started_at=new_task.started_at,
            completed_at=new_task.completed_at,
            exit_code=new_task.exit_code
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating task: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/{task_id}")
async def get_task(
    task_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get task details by ID"""
    try:
        task = db.query(Task).filter(Task.id == task_id).first()
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        # Check permissions
        if current_user.role != "admin" and task.created_by_user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        return {
            "id": task.id,
            "task_id": task.task_id,
            "name": task.name,
            "description": task.description,
            "task_type": task.task_type,
            "command": task.command,
            "arguments": task.arguments,
            "timeout_seconds": task.timeout_seconds,
            "priority": task.priority,
            "run_as_admin": task.run_as_admin,
            "status": task.status,
            "client_id": task.client_id,
            "created_by_user_id": task.created_by_user_id,
            "scheduled_at": task.scheduled_at.isoformat() if task.scheduled_at else None,
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "exit_code": task.exit_code,
            "stdout": task.stdout,
            "stderr": task.stderr,
            "error_message": task.error_message,
            "max_retries": task.max_retries,
            "retry_count": task.retry_count,
            "created_at": task.created_at.isoformat(),
            "updated_at": task.updated_at.isoformat() if task.updated_at else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting task {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/client/{client_id}/pending")
async def get_pending_tasks_for_client(
    client_id: str,
    db: Session = Depends(get_db)
):
    """Get pending tasks for a specific client (called by client software)"""
    try:
        # Find client by client_id
        from models.client import Client
        client = db.query(Client).filter(Client.client_id == client_id).first()
        if not client:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Client not found"
            )
        
        # Get pending tasks for this client
        pending_tasks = db.query(Task).filter(
            Task.client_id == client.id,
            Task.status.in_(["pending", "scheduled"])
        ).order_by(Task.priority.desc(), Task.created_at.asc()).all()
        
        # Return task details for client execution
        tasks = []
        for task in pending_tasks:
            tasks.append({
                "task_id": task.task_id,
                "name": task.name,
                "task_type": task.task_type,
                "command": task.command,
                "arguments": task.arguments,
                "timeout_seconds": task.timeout_seconds,
                "run_as_admin": task.run_as_admin,
                "scheduled_at": task.scheduled_at.isoformat() if task.scheduled_at else None
            })
        
        return {
            "client_id": client_id,
            "pending_tasks": tasks,
            "count": len(tasks)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting pending tasks for client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/{task_id}/start")
async def start_task_execution(
    task_id: str,
    client_id: str,
    db: Session = Depends(get_db)
):
    """Mark task as started (called by client software)"""
    try:
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        # Update task status
        task.status = "running"
        task.started_at = datetime.utcnow()
        task.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"Task {task_id} started execution on client {client_id}")
        return {
            "status": "success",
            "message": "Task execution started",
            "task_id": task_id,
            "started_at": task.started_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting task {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/{task_id}/result")
async def submit_task_result(
    task_id: str,
    result_data: TaskExecutionResult,
    db: Session = Depends(get_db)
):
    """Submit task execution result (called by client software)"""
    try:
        task = db.query(Task).filter(Task.task_id == task_id).first()
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        # Update task with results
        task.status = result_data.status
        task.exit_code = result_data.exit_code
        task.stdout = result_data.stdout
        task.stderr = result_data.stderr
        task.error_message = result_data.error_message
        task.completed_at = datetime.utcnow()
        task.updated_at = datetime.utcnow()
        
        db.commit()
        
        # Log task completion
        AuditLog.log_action(
            action="task_executed",
            description=f"Task {task.name} completed with status: {result_data.status}",
            client_id=task.client_id,
            task_id=task.task_id,
            audit_data={
                "exit_code": result_data.exit_code,
                "status": result_data.status
            },
            db=db
        )
        
        logger.info(f"Task {task_id} completed with status: {result_data.status}")
        return {
            "status": "success",
            "message": "Task result recorded",
            "task_id": task_id,
            "final_status": result_data.status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting result for task {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/{task_id}/cancel")
async def cancel_task(
    request: Request,
    task_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cancel a task"""
    try:
        task = db.query(Task).filter(Task.id == task_id).first()
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        # Check permissions
        if current_user.role != "admin" and task.created_by_user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        # Can only cancel pending or running tasks
        if task.status not in ["pending", "scheduled", "running"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel task with status: {task.status}"
            )
        
        task.status = "cancelled"
        task.completed_at = datetime.utcnow()
        task.updated_at = datetime.utcnow()
        
        db.commit()
        
        # Log task cancellation
        AuditLog.log_action(
            action="task_cancelled",
            description=f"Task {task.name} cancelled by {current_user.username}",
            user_id=current_user.id,
            client_id=task.client_id,
            task_id=task.task_id,
            ip_address=getattr(request.client, 'host', None),
            db=db
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

@router.get("/stats/summary")
async def get_task_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get task statistics"""
    try:
        base_query = db.query(Task)
        
        # Non-admin users see only their tasks
        if current_user.role != "admin":
            base_query = base_query.filter(Task.created_by_user_id == current_user.id)
        
        total_tasks = base_query.count()
        pending_tasks = base_query.filter(Task.status == "pending").count()
        running_tasks = base_query.filter(Task.status == "running").count()
        completed_tasks = base_query.filter(Task.status == "completed").count()
        failed_tasks = base_query.filter(Task.status == "failed").count()
        cancelled_tasks = base_query.filter(Task.status == "cancelled").count()
        
        return {
            "total_tasks": total_tasks,
            "pending_tasks": pending_tasks,
            "running_tasks": running_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "cancelled_tasks": cancelled_tasks,
            "success_rate": round((completed_tasks / total_tasks * 100) if total_tasks > 0 else 0, 2)
        }
        
    except Exception as e:
        logger.error(f"Error getting task stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
