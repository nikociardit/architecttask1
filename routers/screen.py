from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from config.database import get_db
from schemas.screen import (
    ScreenSessionCreate, ScreenSessionResponse, ScreenSessionControl,
    ScreenRecordingCreate, ScreenRecordingUpdate, ScreenRecordingResponse,
    ScreenRecordingDetailResponse, ScreenRecordingListResponse,
    RecordingPolicyCreate, RecordingPolicyUpdate, RecordingPolicyResponse,
    ScreenStatsResponse
)
from services.auth_service import AuthService
from services.screen_service import ScreenService
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

# Screen Session Management
@router.post("/sessions/", response_model=ScreenSessionResponse)
async def create_screen_session(
    request: Request,
    session_data: ScreenSessionCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new screen session"""
    try:
        if not current_user.has_permission("screen.view"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        screen_service = ScreenService(db)
        session = await screen_service.create_screen_session(
            session_data, 
            current_user.id
        )
        
        # Log screen session start
        AuditLog.log_action(
            action=AuditAction.SCREEN_SESSION_STARTED.value,
            description=f"Screen session started by {current_user.username} for client {session_data.client_id}",
            user_id=current_user.id,
            client_id=session_data.client_id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return ScreenSessionResponse.from_orm(session)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating screen session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/sessions/{session_id}")
async def get_screen_session(
    session_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get screen session details"""
    try:
        if not current_user.has_permission("screen.view"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        screen_service = ScreenService(db)
        session = await screen_service.get_screen_session(session_id)
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Screen session not found"
            )
        
        return ScreenSessionResponse.from_orm(session)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting screen session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/sessions/{session_id}/control")
async def send_screen_control(
    session_id: str,
    control_data: ScreenSessionControl,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Send screen control command"""
    try:
        if not current_user.has_permission("screen.control"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        screen_service = ScreenService(db)
        result = await screen_service.send_control_command(
            session_id, 
            control_data, 
            current_user.id
        )
        
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending screen control to {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.delete("/sessions/{session_id}")
async def end_screen_session(
    session_id: str,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """End screen session"""
    try:
        if not current_user.has_permission("screen.view"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        screen_service = ScreenService(db)
        await screen_service.end_screen_session(session_id, current_user.id)
        
        # Log screen session end
        AuditLog.log_action(
            action=AuditAction.SCREEN_SESSION_ENDED.value,
            description=f"Screen session {session_id} ended by {current_user.username}",
            user_id=current_user.id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return {"message": "Screen session ended successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error ending screen session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# Screen Recording Management
@router.get("/recordings/", response_model=ScreenRecordingListResponse)
async def list_recordings(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    client_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List screen recordings"""
    try:
        if not current_user.has_permission("screen.view"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        screen_service = ScreenService(db)
        result = await screen_service.list_recordings(
            page=page,
            per_page=per_page,
            client_id=client_id,
            status=status,
            user_id=current_user.id if current_user.role.value != "admin" else None
        )
        
        return ScreenRecordingListResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing recordings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/recordings/", response_model=ScreenRecordingResponse)
async def create_recording(
    request: Request,
    recording_data: ScreenRecordingCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new screen recording"""
    try:
        if not current_user.has_permission("screen.record"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        screen_service = ScreenService(db)
        recording = await screen_service.create_recording(
            recording_data, 
            current_user.id
        )
        
        # Log recording creation
        AuditLog.log_action(
            action=AuditAction.SCREEN_RECORDING_STARTED.value,
            description=f"Screen recording started by {current_user.username} for client {recording_data.client_id}",
            user_id=current_user.id,
            client_id=recording_data.client_id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return ScreenRecordingResponse.from_orm(recording)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating recording: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/recordings/{recording_id}", response_model=ScreenRecordingDetailResponse)
async def get_recording(
    recording_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get screen recording details"""
    try:
        if not current_user.has_permission("screen.view"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        screen_service = ScreenService(db)
        recording = await screen_service.get_recording(recording_id)
        
        if not recording:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recording not found"
            )
        
        return ScreenRecordingDetailResponse.from_orm(recording)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting recording {recording_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/recordings/{recording_id}/stop")
async def stop_recording(
    recording_id: int,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Stop screen recording"""
    try:
        if not current_user.has_permission("screen.record"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        screen_service = ScreenService(db)
        recording = await screen_service.stop_recording(recording_id, current_user.id)
        
        # Log recording stop
        AuditLog.log_action(
            action=AuditAction.SCREEN_RECORDING_STOPPED.value,
            description=f"Screen recording {recording_id} stopped by {current_user.username}",
            user_id=current_user.id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return {"message": "Recording stopped successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping recording {recording_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/recordings/{recording_id}/download")
async def download_recording(
    recording_id: int,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download screen recording"""
    try:
        screen_service = ScreenService(db)
        recording = await screen_service.get_recording(recording_id)
        
        if not recording:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recording not found"
            )
        
        # Check permissions
        if not recording.can_download(current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        file_response = await screen_service.download_recording(recording_id)
        
        # Log recording download
        AuditLog.log_action(
            action=AuditAction.SCREEN_RECORDING_DOWNLOADED.value,
            description=f"Screen recording {recording_id} downloaded by {current_user.username}",
            user_id=current_user.id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return file_response
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading recording {recording_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/stats", response_model=ScreenStatsResponse)
async def get_screen_stats(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get screen management statistics"""
    try:
        if not current_user.has_permission("screen.view"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        screen_service = ScreenService(db)
        stats = await screen_service.get_screen_stats()
        
        return ScreenStatsResponse(**stats)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting screen stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
