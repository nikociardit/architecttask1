from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from fastapi.responses import FileResponse
import logging
import uuid
import os
import json

from models.screen import (
    ScreenRecording, ScreenSession, RecordingPolicy,
    RecordingStatus, RecordingTrigger, SessionStatus
)
from models.client import Client
from models.user import User
from schemas.screen import (
    ScreenSessionCreate, ScreenSessionControl, ScreenRecordingCreate,
    ScreenRecordingUpdate
)
from config.settings import settings
from utils.exceptions import ValidationError, NotFoundError, PermissionError

logger = logging.getLogger(__name__)

class ScreenService:
    """Screen management service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    # Screen Session Management
    async def create_screen_session(
        self, 
        session_data: ScreenSessionCreate, 
        user_id: int
    ) -> ScreenSession:
        """Create new screen session"""
        
        # Validate client
        client = self.db.query(Client).filter(Client.id == session_data.client_id).first()
        if not client:
            raise NotFoundError("Client not found")
        
        if not client.can_screen_access():
            raise ValidationError("Screen access not available for this client")
        
        # Check for existing active session
        existing_session = self.db.query(ScreenSession).filter(
            and_(
                ScreenSession.client_id == session_data.client_id,
                ScreenSession.status == SessionStatus.ACTIVE.value
            )
        ).first()
        
        if existing_session:
            raise ValidationError("Active screen session already exists for this client")
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Calculate timeout
        timeout_at = datetime.utcnow() + timedelta(minutes=session_data.timeout_minutes)
        
        # Create session
        session = ScreenSession(
            session_id=session_id,
            client_id=session_data.client_id,
            user_id=user_id,
            control_enabled=session_data.control_enabled,
            audio_enabled=session_data.audio_enabled,
            quality=session_data.quality,
            max_fps=session_data.max_fps,
            status=SessionStatus.ACTIVE.value,
            timeout_at=timeout_at,
            started_at=datetime.utcnow(),
            last_activity=datetime.utcnow()
        )
        
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        
        # Update client session info
        client.screen_session_active = True
        client.screen_session_started_at = datetime.utcnow()
        client.screen_session_user_id = user_id
        self.db.commit()
        
        logger.info(f"Screen session {session_id} created for client {client.hostname}")
        return session
    
    async def get_screen_session(self, session_id: str) -> Optional[ScreenSession]:
        """Get screen session by ID"""
        return self.db.query(ScreenSession).filter(
            ScreenSession.session_id == session_id
        ).first()
    
    async def end_screen_session(self, session_id: str, user_id: int) -> bool:
        """End screen session"""
        
        session = await self.get_screen_session(session_id)
        if not session:
            raise NotFoundError("Screen session not found")
        
        # Check permissions
        if session.user_id != user_id:
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user or not user.has_permission("screen.manage"):
                raise PermissionError("Insufficient permissions to end this session")
        
        # End session
        session.status = SessionStatus.TERMINATED.value
        session.ended_at = datetime.utcnow()
        
        # Update client session info
        if session.client:
            session.client.screen_session_active = False
            session.client.screen_session_started_at = None
            session.client.screen_session_user_id = None
        
        self.db.commit()
        
        logger.info(f"Screen session {session_id} ended by user {user_id}")
        return True
    
    async def send_control_command(
        self, 
        session_id: str, 
        control_data: ScreenSessionControl, 
        user_id: int
    ) -> Dict[str, Any]:
        """Send control command to screen session"""
        
        session = await self.get_screen_session(session_id)
        if not session:
            raise NotFoundError("Screen session not found")
        
        if not session.is_active():
            raise ValidationError("Screen session is not active")
        
        if session.user_id != user_id:
            raise PermissionError("Not authorized for this session")
        
        if not session.control_enabled:
            raise ValidationError("Control is not enabled for this session")
        
        # Update last activity
        session.update_activity()
        self.db.commit()
        
        # In a real implementation, this would send the control command
        # to the client via WebSocket or similar real-time communication
        
        return {
            "status": "sent",
            "action": control_data.action,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    # Screen Recording Management
    async def create_recording(
        self, 
        recording_data: ScreenRecordingCreate, 
        created_by: int
    ) -> ScreenRecording:
        """Create new screen recording"""
        
        # Validate client
        client = self.db.query(Client).filter(Client.id == recording_data.client_id).first()
        if not client:
            raise NotFoundError("Client not found")
        
        if not client.screen_recording_enabled:
            raise ValidationError("Screen recording not enabled for this client")
        
        # Generate recording ID and filename
        recording_id = str(uuid.uuid4())[:12]
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"recording_{client.hostname}_{timestamp}.{recording_data.format}"
        
        # Calculate expiration date
        expires_at = None
        if recording_data.trigger == RecordingTrigger.MANUAL:
            expires_at = datetime.utcnow() + timedelta(days=settings.RECORDING_RETENTION_DAYS)
        
        # Create recording
                    recording = ScreenRecording(
            recording_id=recording_id,
            filename=filename,
            file_path=os.path.join(settings.SCREEN_RECORDING_DIR, filename),
            format=recording_data.format,
            quality=recording_data.quality,
            status=RecordingStatus.SCHEDULED.value,
            trigger=recording_data.trigger.value,
            client_id=recording_data.client_id,
            created_by_user_id=created_by,
            scheduled_at=recording_data.scheduled_at or datetime.utcnow(),
            target_user=recording_data.target_user,
            target_application=recording_data.target_application,
            record_audio=recording_data.record_audio,
            record_microphone=recording_data.record_microphone,
            record_webcam=recording_data.record_webcam,
            show_cursor=recording_data.show_cursor,
            requires_approval=recording_data.requires_approval,
            expires_at=expires_at,
            created_at=datetime.utcnow()
        )
        
        self.db.add(recording)
        self.db.commit()
        self.db.refresh(recording)
        
        logger.info(f"Screen recording {recording_id} created for client {client.hostname}")
        return recording
    
    async def get_recording(self, recording_id: int) -> Optional[ScreenRecording]:
        """Get screen recording by ID"""
        return self.db.query(ScreenRecording).filter(
            ScreenRecording.id == recording_id
        ).first()
    
    async def get_recording_by_recording_id(self, recording_id: str) -> Optional[ScreenRecording]:
        """Get screen recording by recording_id"""
        return self.db.query(ScreenRecording).filter(
            ScreenRecording.recording_id == recording_id
        ).first()
    
    async def list_recordings(
        self,
        page: int = 1,
        per_page: int = 50,
        client_id: Optional[int] = None,
        status: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """List screen recordings with pagination and filtering"""
        
        query = self.db.query(ScreenRecording)
        
        # Apply filters
        if client_id:
            query = query.filter(ScreenRecording.client_id == client_id)
        
        if status:
            query = query.filter(ScreenRecording.status == status)
        
        if user_id:
            query = query.filter(ScreenRecording.created_by_user_id == user_id)
        
        # Order by creation time (newest first)
        query = query.order_by(ScreenRecording.created_at.desc())
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        recordings = query.offset(offset).limit(per_page).all()
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        
        return {
            "recordings": recordings,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages
        }
    
    async def update_recording(
        self, 
        recording_id: str, 
        update_data: ScreenRecordingUpdate
    ) -> ScreenRecording:
        """Update recording (called by client)"""
        
        recording = await self.get_recording_by_recording_id(recording_id)
        if not recording:
            raise NotFoundError("Recording not found")
        
        # Update fields
        if update_data.status is not None:
            recording.status = update_data.status.value
            
            if update_data.status == RecordingStatus.RECORDING:
                recording.started_at = datetime.utcnow()
            elif update_data.status in [
                RecordingStatus.COMPLETED, 
                RecordingStatus.FAILED, 
                RecordingStatus.CANCELLED
            ]:
                recording.completed_at = datetime.utcnow()
        
        if update_data.file_size is not None:
            recording.file_size = update_data.file_size
        
        if update_data.duration is not None:
            recording.duration = update_data.duration
        
        if update_data.resolution is not None:
            recording.resolution = update_data.resolution
        
        if update_data.error_message is not None:
            recording.error_message = update_data.error_message
        
        recording.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(recording)
        
        return recording
    
    async def stop_recording(self, recording_id: int, stopped_by: int) -> ScreenRecording:
        """Stop active recording"""
        
        recording = await self.get_recording(recording_id)
        if not recording:
            raise NotFoundError("Recording not found")
        
        if not recording.is_active():
            raise ValidationError("Recording is not active")
        
        recording.status = RecordingStatus.COMPLETED.value
        recording.completed_at = datetime.utcnow()
        recording.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(recording)
        
        logger.info(f"Recording {recording.recording_id} stopped by user {stopped_by}")
        return recording
    
    async def download_recording(self, recording_id: int) -> FileResponse:
        """Download recording file"""
        
        recording = await self.get_recording(recording_id)
        if not recording:
            raise NotFoundError("Recording not found")
        
        if not recording.is_completed():
            raise ValidationError("Recording is not ready for download")
        
        if not os.path.exists(recording.file_path):
            raise NotFoundError("Recording file not found on disk")
        
        return FileResponse(
            path=recording.file_path,
            filename=recording.filename,
            media_type="application/octet-stream"
        )
    
    async def delete_recording(self, recording_id: int, deleted_by: int) -> bool:
        """Delete recording and file"""
        
        recording = await self.get_recording(recording_id)
        if not recording:
            raise NotFoundError("Recording not found")
        
        # Delete file from disk
        if os.path.exists(recording.file_path):
            try:
                os.remove(recording.file_path)
                logger.info(f"Recording file {recording.file_path} deleted from disk")
            except Exception as e:
                logger.error(f"Failed to delete recording file {recording.file_path}: {e}")
        
        # Delete from database
        self.db.delete(recording)
        self.db.commit()
        
        logger.info(f"Recording {recording.recording_id} deleted by user {deleted_by}")
        return True
    
    # Recording Policy Management
    async def create_recording_policy(
        self, 
        policy_data: Dict[str, Any], 
        created_by: int
    ) -> RecordingPolicy:
        """Create recording policy"""
        
        policy = RecordingPolicy(
            name=policy_data["name"],
            description=policy_data.get("description"),
            enabled=policy_data.get("enabled", True),
            trigger_rules=policy_data["trigger_rules"],
            recording_settings=policy_data["recording_settings"],
            client_filter=policy_data.get("client_filter"),
            user_filter=policy_data.get("user_filter"),
            priority=policy_data.get("priority", 100),
            created_by_user_id=created_by,
            created_at=datetime.utcnow()
        )
        
        self.db.add(policy)
        self.db.commit()
        self.db.refresh(policy)
        
        logger.info(f"Recording policy '{policy.name}' created by user {created_by}")
        return policy
    
    async def apply_recording_policies(self) -> int:
        """Apply recording policies and create scheduled recordings"""
        
        # Get active policies
        policies = self.db.query(RecordingPolicy).filter(
            RecordingPolicy.enabled == True
        ).order_by(RecordingPolicy.priority.desc()).all()
        
        recordings_created = 0
        
        for policy in policies:
            try:
                created = await self._apply_single_policy(policy)
                recordings_created += created
            except Exception as e:
                logger.error(f"Failed to apply policy {policy.name}: {e}")
        
        return recordings_created
    
    async def _apply_single_policy(self, policy: RecordingPolicy) -> int:
        """Apply a single recording policy"""
        
        # This is a simplified implementation
        # In production, this would have more sophisticated rule evaluation
        
        trigger_rules = policy.trigger_rules
        recording_settings = policy.recording_settings
        
        # Find matching clients
        query = self.db.query(Client).filter(Client.screen_recording_enabled == True)
        
        # Apply client filters
        if policy.client_filter:
            if "hostname_pattern" in policy.client_filter:
                pattern = policy.client_filter["hostname_pattern"]
                query = query.filter(Client.hostname.ilike(f"%{pattern}%"))
            
            if "domain" in policy.client_filter:
                query = query.filter(Client.domain == policy.client_filter["domain"])
        
        clients = query.all()
        recordings_created = 0
        
        # Create recordings based on trigger rules
        for client in clients:
            if await self._should_create_recording(client, trigger_rules):
                recording_data = ScreenRecordingCreate(
                    client_id=client.id,
                    trigger=RecordingTrigger.SCHEDULED,
                    quality=recording_settings.get("quality", "medium"),
                    format=recording_settings.get("format", "mp4"),
                    record_audio=recording_settings.get("record_audio", False),
                    show_cursor=recording_settings.get("show_cursor", True)
                )
                
                recording = await self.create_recording(recording_data, policy.created_by_user_id)
                recordings_created += 1
        
        return recordings_created
    
    async def _should_create_recording(
        self, 
        client: Client, 
        trigger_rules: Dict[str, Any]
    ) -> bool:
        """Check if recording should be created based on trigger rules"""
        
        # Time-based triggers
        if "time_schedule" in trigger_rules:
            schedule = trigger_rules["time_schedule"]
            current_time = datetime.utcnow()
            
            # Check if current time matches schedule
            if "hours" in schedule:
                if current_time.hour not in schedule["hours"]:
                    return False
            
            if "days_of_week" in schedule:
                if current_time.weekday() not in schedule["days_of_week"]:
                    return False
        
        # User-based triggers
        if "target_users" in trigger_rules and client.assigned_user_id:
            user = self.db.query(User).filter(User.id == client.assigned_user_id).first()
            if user and user.username not in trigger_rules["target_users"]:
                return False
        
        # Check if recording already exists for recent time period
        recent_threshold = datetime.utcnow() - timedelta(hours=1)
        existing_recording = self.db.query(ScreenRecording).filter(
            and_(
                ScreenRecording.client_id == client.id,
                ScreenRecording.created_at >= recent_threshold,
                ScreenRecording.trigger == RecordingTrigger.SCHEDULED.value
            )
        ).first()
        
        if existing_recording:
            return False
        
        return True
    
    async def get_screen_stats(self) -> Dict[str, Any]:
        """Get screen management statistics"""
        
        total_recordings = self.db.query(ScreenRecording).count()
        
        active_recordings = self.db.query(ScreenRecording).filter(
            ScreenRecording.status == RecordingStatus.RECORDING.value
        ).count()
        
        completed_recordings = self.db.query(ScreenRecording).filter(
            ScreenRecording.status == RecordingStatus.COMPLETED.value
        ).count()
        
        failed_recordings = self.db.query(ScreenRecording).filter(
            ScreenRecording.status == RecordingStatus.FAILED.value
        ).count()
        
        # Total size of recordings
        total_size_result = self.db.query(
            func.sum(ScreenRecording.file_size)
        ).filter(ScreenRecording.file_size.isnot(None)).scalar()
        
        total_size_bytes = total_size_result or 0
        
        # Active screen sessions
        active_sessions = self.db.query(ScreenSession).filter(
            ScreenSession.status == SessionStatus.ACTIVE.value
        ).count()
        
        # Sessions today
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        total_sessions_today = self.db.query(ScreenSession).filter(
            ScreenSession.started_at >= today_start
        ).count()
        
        # Average session duration
        avg_duration_result = self.db.query(
            func.avg(
                func.extract('epoch', ScreenSession.ended_at - ScreenSession.started_at)
            )
        ).filter(
            and_(
                ScreenSession.started_at.isnot(None),
                ScreenSession.ended_at.isnot(None)
            )
        ).scalar()
        
        avg_session_duration = avg_duration_result if avg_duration_result else 0
        
        # Average recording size
        avg_size_result = self.db.query(
            func.avg(ScreenRecording.file_size)
        ).filter(ScreenRecording.file_size.isnot(None)).scalar()
        
        avg_recording_size = avg_size_result if avg_size_result else 0
        
        return {
            "total_recordings": total_recordings,
            "active_recordings": active_recordings,
            "completed_recordings": completed_recordings,
            "failed_recordings": failed_recordings,
            "total_size_bytes": int(total_size_bytes),
            "active_sessions": active_sessions,
            "total_sessions_today": total_sessions_today,
            "avg_session_duration": round(avg_session_duration, 2),
            "avg_recording_size": round(avg_recording_size, 2)
        }
    
    async def cleanup_expired_recordings(self) -> int:
        """Clean up expired recordings"""
        
        expired_recordings = self.db.query(ScreenRecording).filter(
            and_(
                ScreenRecording.expires_at.isnot(None),
                ScreenRecording.expires_at < datetime.utcnow(),
                ScreenRecording.auto_delete == True
            )
        ).all()
        
        deleted_count = 0
        for recording in expired_recordings:
            try:
                if os.path.exists(recording.file_path):
                    os.remove(recording.file_path)
                
                self.db.delete(recording)
                deleted_count += 1
            except Exception as e:
                logger.error(f"Failed to delete expired recording {recording.recording_id}: {e}")
        
        if deleted_count > 0:
            self.db.commit()
            logger.info(f"Cleaned up {deleted_count} expired recordings")
        
        return deleted_count
    
    async def cleanup_old_sessions(self) -> int:
        """Clean up old inactive sessions"""
        
        # Clean up sessions older than 24 hours that are not active
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        old_sessions = self.db.query(ScreenSession).filter(
            and_(
                ScreenSession.started_at < cutoff_time,
                ScreenSession.status != SessionStatus.ACTIVE.value
            )
        ).all()
        
        for session in old_sessions:
            # Update client if session is still marked as active
            if session.client and session.client.screen_session_active:
                session.client.screen_session_active = False
                session.client.screen_session_user_id = None
                session.client.screen_session_started_at = None
            
            self.db.delete(session)
        
        if old_sessions:
            self.db.commit()
            logger.info(f"Cleaned up {len(old_sessions)} old screen sessions")
        
        return len(old_sessions)
