from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import logging
import uuid

from models.task import Task, TaskTemplate, TaskType, TaskStatus, TaskPriority
from models.client import Client
from models.user import User
from schemas.task import (
    TaskCreate, TaskUpdate, TaskExecutionResult, TaskTemplateCreate,
    TaskTemplateUpdate, TaskFromTemplateRequest
)
from config.settings import settings
from utils.exceptions import ValidationError, NotFoundError, ConflictError

logger = logging.getLogger(__name__)

class TaskService:
    """Task execution service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def create_task(self, task_data: TaskCreate, created_by: int) -> Task:
        """Create new task"""
        
        # Validate task data
        await self._validate_task_data(task_data)
        
        # Determine target clients
        target_client_ids = await self._resolve_target_clients(task_data)
        
        if not target_client_ids:
            raise ValidationError("No valid target clients found")
        
        # Create tasks for each target client
        tasks = []
        for client_id in target_client_ids:
            task = await self._create_single_task(task_data, client_id, created_by)
            tasks.append(task)
        
        # Return first task if single target, otherwise return summary
        if len(tasks) == 1:
            return tasks[0]
        else:
            # For multiple targets, return a summary task
            return tasks[0]  # Simplified - could create a parent task concept
    
    async def _create_single_task(
        self, 
        task_data: TaskCreate, 
        client_id: int, 
        created_by: int
    ) -> Task:
        """Create a single task for one client"""
        
        task_id = str(uuid.uuid4())[:8]  # Short unique ID
        
        task = Task(
            task_id=task_id,
            name=task_data.name,
            description=task_data.description,
            task_type=task_data.task_type.value,
            command=task_data.command,
            arguments=task_data.arguments,
            working_directory=task_data.working_directory,
            timeout_seconds=task_data.timeout_seconds,
            priority=task_data.priority.value,
            run_as_admin=task_data.run_as_admin,
            client_id=client_id,
            created_by_user_id=created_by,
            scheduled_at=task_data.scheduled_at,
            run_as_user=task_data.run_as_user,
            environment_variables=task_data.environment_variables,
            input_files=task_data.input_files,
            output_files=task_data.output_files,
            max_retries=task_data.max_retries,
            retry_delay=task_data.retry_delay,
            requires_approval=task_data.requires_approval,
            status=TaskStatus.PENDING.value,
            created_at=datetime.utcnow()
        )
        
        self.db.add(task)
        self.db.commit()
        self.db.refresh(task)
        
        logger.info(f"Task '{task.name}' ({task.task_id}) created for client {client_id}")
        return task
    
    async def _validate_task_data(self, task_data: TaskCreate):
        """Validate task creation data"""
        
        # Validate command based on task type
        if task_data.task_type == TaskType.POWERSHELL:
            if not task_data.command.strip():
                raise ValidationError("PowerShell command cannot be empty")
        
        elif task_data.task_type == TaskType.CMD:
            if not task_data.command.strip():
                raise ValidationError("CMD command cannot be empty")
        
        elif task_data.task_type == TaskType.EXECUTABLE:
            if not task_data.command.endswith(('.exe', '.msi', '.bat')):
                raise ValidationError("Executable must have valid extension (.exe, .msi, .bat)")
        
        # Validate timeout
        if task_data.timeout_seconds < 1 or task_data.timeout_seconds > 3600:
            raise ValidationError("Timeout must be between 1 and 3600 seconds")
        
        # Validate scheduled time
        if task_data.scheduled_at and task_data.scheduled_at < datetime.utcnow():
            raise ValidationError("Scheduled time cannot be in the past")
    
    async def _resolve_target_clients(self, task_data: TaskCreate) -> List[int]:
        """Resolve target clients based on task data"""
        
        client_ids = []
        
        # Single client target
        if task_data.client_id:
            client = self.db.query(Client).filter(Client.id == task_data.client_id).first()
            if client and client.can_execute_tasks():
                client_ids.append(client.id)
        
        # Multiple client targets
        elif task_data.client_ids:
            clients = self.db.query(Client).filter(
                Client.id.in_(task_data.client_ids)
            ).all()
            client_ids.extend([c.id for c in clients if c.can_execute_tasks()])
        
        # Group targeting
        elif task_data.target_group:
            # Implement group logic (could be based on domain, location, etc.)
            if task_data.target_group == "all":
                clients = self.db.query(Client).filter(
                    Client.task_execution_enabled == True
                ).all()
                client_ids.extend([c.id for c in clients if c.can_execute_tasks()])
            else:
                # Custom group logic
                clients = self.db.query(Client).filter(
                    and_(
                        Client.domain == task_data.target_group,
                        Client.task_execution_enabled == True
                    )
                ).all()
                client_ids.extend([c.id for c in clients if c.can_execute_tasks()])
        
        # Filter-based targeting
        elif task_data.target_filter:
            query = self.db.query(Client).filter(Client.task_execution_enabled == True)
            
            # Apply filters
            if "hostname" in task_data.target_filter:
                query = query.filter(Client.hostname.ilike(f"%{task_data.target_filter['hostname']}%"))
            
            if "domain" in task_data.target_filter:
                query = query.filter(Client.domain == task_data.target_filter["domain"])
            
            if "client_type" in task_data.target_filter:
                query = query.filter(Client.client_type == task_data.target_filter["client_type"])
            
            clients = query.all()
            client_ids.extend([c.id for c in clients if c.can_execute_tasks()])
        
        return list(set(client_ids))  # Remove duplicates
    
    async def get_task_by_id(self, task_id: int) -> Optional[Task]:
        """Get task by ID"""
        return self.db.query(Task).filter(Task.id == task_id).first()
    
    async def get_task_by_task_id(self, task_id: str) -> Optional[Task]:
        """Get task by task_id"""
        return self.db.query(Task).filter(Task.task_id == task_id).first()
    
    async def list_tasks(
        self,
        page: int = 1,
        per_page: int = 50,
        status: Optional[str] = None,
        client_id: Optional[int] = None,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """List tasks with pagination and filtering"""
        
        query = self.db.query(Task)
        
        # Apply filters
        if status:
            query = query.filter(Task.status == status)
        
        if client_id:
            query = query.filter(Task.client_id == client_id)
        
        if user_id:
            query = query.filter(Task.created_by_user_id == user_id)
        
        # Order by creation time (newest first)
        query = query.order_by(Task.created_at.desc())
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        tasks = query.offset(offset).limit(per_page).all()
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        
        return {
            "tasks": tasks,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages
        }
    
    async def update_task_result(
        self, 
        task_id: str, 
        result_data: TaskExecutionResult
    ) -> Task:
        """Update task with execution result"""
        
        task = await self.get_task_by_task_id(task_id)
        if not task:
            raise NotFoundError("Task not found")
        
        # Update task with results
        task.status = result_data.status.value
        task.exit_code = result_data.exit_code
        task.stdout = result_data.stdout
        task.stderr = result_data.stderr
        task.error_message = result_data.error_message
        
        if result_data.started_at:
            task.started_at = result_data.started_at
        
        if result_data.completed_at:
            task.completed_at = result_data.completed_at
        else:
            task.completed_at = datetime.utcnow()
        
        task.updated_at = datetime.utcnow()
        
        # Update client's last task info
        if task.client:
            task.client.last_task_id = task.id
            task.client.last_task_status = task.status
            task.client.last_task_completed_at = task.completed_at
        
        self.db.commit()
        self.db.refresh(task)
        
        logger.info(f"Task {task_id} completed with status: {result_data.status.value}")
        
        # Handle retry logic
        if (task.status == TaskStatus.FAILED.value and 
            task.can_retry()):
            await self._schedule_retry(task)
        
        return task
    
    async def _schedule_retry(self, task: Task):
        """Schedule task retry"""
        
        task.retry_count += 1
        task.status = TaskStatus.PENDING.value
        task.scheduled_at = datetime.utcnow() + timedelta(seconds=task.retry_delay)
        task.started_at = None
        task.completed_at = None
        task.exit_code = None
        task.stdout = None
        task.stderr = None
        task.error_message = None
        
        self.db.commit()
        
        logger.info(f"Task {task.task_id} scheduled for retry {task.retry_count}/{task.max_retries}")
    
    async def cancel_task(self, task_id: int, cancelled_by: int, reason: str = None) -> Task:
        """Cancel task"""
        
        task = await self.get_task_by_id(task_id)
        if not task:
            raise NotFoundError("Task not found")
        
        if task.is_completed():
            raise ValidationError("Cannot cancel completed task")
        
        task.status = TaskStatus.CANCELLED.value
        task.completed_at = datetime.utcnow()
        task.error_message = f"Cancelled by user {cancelled_by}" + (f": {reason}" if reason else "")
        task.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(task)
        
        logger.info(f"Task {task.task_id} cancelled by user {cancelled_by}")
        return task
    
    async def get_task_stats(self) -> Dict[str, Any]:
        """Get task statistics"""
        
        total_tasks = self.db.query(Task).count()
        
        pending_tasks = self.db.query(Task).filter(Task.status == TaskStatus.PENDING.value).count()
        running_tasks = self.db.query(Task).filter(Task.status == TaskStatus.RUNNING.value).count()
        completed_tasks = self.db.query(Task).filter(Task.status == TaskStatus.COMPLETED.value).count()
        failed_tasks = self.db.query(Task).filter(Task.status == TaskStatus.FAILED.value).count()
        cancelled_tasks = self.db.query(Task).filter(Task.status == TaskStatus.CANCELLED.value).count()
        
        # Calculate success rate
        finished_tasks = completed_tasks + failed_tasks
        success_rate = (completed_tasks / finished_tasks * 100) if finished_tasks > 0 else 0
        
        # Average execution time
        avg_execution_result = self.db.query(
            func.avg(
                func.extract('epoch', Task.completed_at - Task.started_at)
            )
        ).filter(
            and_(
                Task.started_at.isnot(None),
                Task.completed_at.isnot(None),
                Task.status == TaskStatus.COMPLETED.value
            )
        ).scalar()
        
        avg_execution_time = avg_execution_result if avg_execution_result else 0
        
        return {
            "total_tasks": total_tasks,
            "pending_tasks": pending_tasks,
            "running_tasks": running_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "cancelled_tasks": cancelled_tasks,
            "success_rate": round(success_rate, 2),
            "avg_execution_time": round(avg_execution_time, 2)
        }
    
    # Task Template Management
    async def create_task_template(
        self, 
        template_data: TaskTemplateCreate, 
        created_by: int
    ) -> TaskTemplate:
        """Create task template"""
        
        template = TaskTemplate(
            name=template_data.name,
            description=template_data.description,
            category=template_data.category,
            task_type=template_data.task_type.value,
            command_template=template_data.command_template,
            arguments_template=template_data.arguments_template,
            default_timeout=template_data.default_timeout,
            parameters=template_data.parameters,
            requires_approval=template_data.requires_approval,
            run_as_admin=template_data.run_as_admin,
            created_by_user_id=created_by,
            created_at=datetime.utcnow()
        )
        
        self.db.add(template)
        self.db.commit()
        self.db.refresh(template)
        
        logger.info(f"Task template '{template.name}' created by user {created_by}")
        return template
    
    async def list_task_templates(self, active_only: bool = True) -> List[TaskTemplate]:
        """List task templates"""
        
        query = self.db.query(TaskTemplate)
        
        if active_only:
            query = query.filter(TaskTemplate.is_active == True)
        
        return query.order_by(TaskTemplate.name).all()
    
    async def get_task_template(self, template_id: int) -> Optional[TaskTemplate]:
        """Get task template by ID"""
        return self.db.query(TaskTemplate).filter(TaskTemplate.id == template_id).first()
    
    async def create_task_from_template(
        self, 
        template_request: TaskFromTemplateRequest, 
        created_by: int
    ) -> Task:
        """Create task from template"""
        
        template = await self.get_task_template(template_request.template_id)
        if not template:
            raise NotFoundError("Task template not found")
        
        if not template.is_active:
            raise ValidationError("Task template is not active")
        
        # Process template with parameters
        command = await self._process_template_string(
            template.command_template, 
            template_request.parameter_values
        )
        
        arguments = None
        if template.arguments_template:
            arguments = await self._process_template_string(
                template.arguments_template, 
                template_request.parameter_values
            )
        
        # Create task data from template
        task_data = TaskCreate(
            name=f"{template.name} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
            description=template.description,
            task_type=TaskType(template.task_type),
            command=command,
            arguments=arguments,
            timeout_seconds=template.default_timeout,
            priority=template_request.priority,
            run_as_admin=template.run_as_admin,
            requires_approval=template.requires_approval,
            client_id=template_request.client_id,
            client_ids=template_request.client_ids,
            target_group=template_request.target_group,
            scheduled_at=template_request.scheduled_at
        )
        
        # Create task
        task = await self.create_task(task_data, created_by)
        
        # Update template usage count
        template.usage_count += 1
        self.db.commit()
        
        return task
    
    async def _process_template_string(
        self, 
        template_string: str, 
        parameters: Dict[str, Any]
    ) -> str:
        """Process template string with parameters"""
        
        processed = template_string
        
        # Simple parameter substitution
        for key, value in parameters.items():
            placeholder = f"{{{key}}}"
            processed = processed.replace(placeholder, str(value))
        
        return processed
    
    async def update_task_template(
        self, 
        template_id: int, 
        template_data: TaskTemplateUpdate, 
        updated_by: int
    ) -> TaskTemplate:
        """Update task template"""
        
        template = await self.get_task_template(template_id)
        if not template:
            raise NotFoundError("Task template not found")
        
        # Update fields
        if template_data.name is not None:
            template.name = template_data.name
        
        if template_data.description is not None:
            template.description = template_data.description
        
        if template_data.category is not None:
            template.category = template_data.category
        
        if template_data.command_template is not None:
            template.command_template = template_data.command_template
        
        if template_data.arguments_template is not None:
            template.arguments_template = template_data.arguments_template
        
        if template_data.default_timeout is not None:
            template.default_timeout = template_data.default_timeout
        
        if template_data.parameters is not None:
            template.parameters = template_data.parameters
        
        if template_data.requires_approval is not None:
            template.requires_approval = template_data.requires_approval
        
        if template_data.run_as_admin is not None:
            template.run_as_admin = template_data.run_as_admin
        
        if template_data.is_active is not None:
            template.is_active = template_data.is_active
        
        template.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(template)
        
        logger.info(f"Task template '{template.name}' updated by user {updated_by}")
        return template
    
    async def delete_task_template(self, template_id: int) -> bool:
        """Delete task template (soft delete)"""
        
        template = await self.get_task_template(template_id)
        if not template:
            raise NotFoundError("Task template not found")
        
        template.is_active = False
        template.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        logger.info(f"Task template '{template.name}' deleted (soft delete)")
        return True
    
    async def cleanup_old_tasks(self, days: int = 30) -> int:
        """Clean up old completed tasks"""
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        old_tasks = self.db.query(Task).filter(
            and_(
                Task.completed_at < cutoff_date,
                Task.status.in_([
                    TaskStatus.COMPLETED.value,
                    TaskStatus.FAILED.value,
                    TaskStatus.CANCELLED.value
                ])
            )
        ).all()
        
        for task in old_tasks:
            self.db.delete(task)
        
        self.db.commit()
        
        logger.info(f"Cleaned up {len(old_tasks)} old tasks")
        return len(old_tasks)
    
    async def get_task_history(
        self, 
        client_id: int, 
        days: int = 7
    ) -> List[Task]:
        """Get task history for client"""
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        tasks = self.db.query(Task).filter(
            and_(
                Task.client_id == client_id,
                Task.created_at >= start_date
            )
        ).order_by(Task.created_at.desc()).all()
        
        return tasks
