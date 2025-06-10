from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from models.screen import RecordingStatus, RecordingTrigger, SessionStatus

class ScreenSessionCreate(BaseModel):
    """Screen session creation schema"""
    client_id: int
    control_enabled: bool = False
    audio_enabled: bool = False
    quality: str = "medium"
    max_fps: int = 30
    timeout_minutes: int = 60
    
    @validator('quality')
    def quality_valid(cls, v):
        if v not in ['low', 'medium', 'high']:
            raise ValueError('quality must be low, medium, or high')
        return v
    
    @validator('max_fps')
    def fps_valid(cls, v):
        if v < 1 or v > 60:
            raise ValueError('fps must be between 1 and 60')
        return v

class ScreenSessionResponse(BaseModel):
    """Screen session response schema"""
    id: int
    session_id: str
    client_id: int
    user_id: int
    status: SessionStatus
    control_enabled: bool
    audio_enabled: bool
    quality: str
    max_fps: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    last_activity: datetime
    timeout_at: Optional[datetime] = None
    client_consent: bool = False
    connection_id: Optional[str] = None
    
    class Config:
        from_attributes = True

class ScreenSessionControl(BaseModel):
    """Screen session control schema"""
    action: str  # mouse_move, mouse_click, key_press, etc.
    data: Dict[str, Any]
    
    @validator('action')
    def action_valid(cls, v):
        valid_actions = [
            'mouse_move', 'mouse_click', 'mouse_scroll',
            'key_press', 'key_release', 'key_combination'
        ]
        if v not in valid_actions:
            raise ValueError(f'action must be one of: {", ".join(valid_actions)}')
        return v

class ScreenRecordingCreate(BaseModel):
    """Screen recording creation schema"""
    client_id: int
    trigger: RecordingTrigger
    scheduled_at: Optional[datetime] = None
    duration_minutes: Optional[int] = None
    target_user: Optional[str] = None
    target_application: Optional[str] = None
    quality: str = "medium"
    format: str = "mp4"
    record_audio: bool = False
    record_microphone: bool = False
    record_webcam: bool = False
    show_cursor: bool = True
    requires_approval: bool = False
    
    @validator('quality')
    def quality_valid(cls, v):
        if v not in ['low', 'medium', 'high']:
            raise ValueError('quality must be low, medium, or high')
        return v
    
    @validator('format')
    def format_valid(cls, v):
        if v not in ['mp4', 'webm']:
            raise ValueError('format must be mp4 or webm')
        return v
    
    @validator('duration_minutes')
    def duration_valid(cls, v):
        if v is not None and (v < 1 or v > 480):  # 8 hours max
            raise ValueError('duration must be between 1 and 480 minutes')
        return v

class ScreenRecordingUpdate(BaseModel):
    """Screen recording update schema"""
    status: Optional[RecordingStatus] = None
    file_size: Optional[int] = None
    duration: Optional[int] = None
    resolution: Optional[str] = None
    error_message: Optional[str] = None

class ScreenRecordingResponse(BaseModel):
    """Screen recording response schema"""
    id: int
    recording_id: str
    filename: str
    file_size: int
    duration: int
    format: str
    quality: str
    resolution: Optional[str] = None
    status: RecordingStatus
    trigger: RecordingTrigger
    client_id: int
    created_by_user_id: int
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    uploaded: bool = False
    expires_at: Optional[datetime] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

class ScreenRecordingDetailResponse(ScreenRecordingResponse):
    """Detailed screen recording response schema"""
    file_path: Optional[str] = None
    target_user: Optional[str] = None
    target_application: Optional[str] = None
    record_audio: bool = False
    record_microphone: bool = False
    record_webcam: bool = False
    show_cursor: bool = True
    encrypted: bool = True
    auto_delete: bool = True
    metadata: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    client_hostname: Optional[str] = None
    created_by_username: Optional[str] = None

class ScreenRecordingListResponse(BaseModel):
    """Screen recording list response schema"""
    recordings: List[ScreenRecordingResponse]
    total: int
    page: int
    per_page: int
    pages: int

class RecordingPolicyCreate(BaseModel):
    """Recording policy creation schema"""
    name: str
    description: Optional[str] = None
    enabled: bool = True
    trigger_rules: Dict[str, Any]
    recording_settings: Dict[str, Any]
    client_filter: Optional[Dict[str, Any]] = None
    user_filter: Optional[Dict[str, Any]] = None
    priority: int = 100

class RecordingPolicyUpdate(BaseModel):
    """Recording policy update schema"""
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    trigger_rules: Optional[Dict[str, Any]] = None
    recording_settings: Optional[Dict[str, Any]] = None
    client_filter: Optional[Dict[str, Any]] = None
    user_filter: Optional[Dict[str, Any]] = None
    priority: Optional[int] = None

class RecordingPolicyResponse(BaseModel):
    """Recording policy response schema"""
    id: int
    name: str
    description: Optional[str] = None
    enabled: bool
    trigger_rules: Dict[str, Any]
    recording_settings: Dict[str, Any]
    client_filter: Optional[Dict[str, Any]] = None
    user_filter: Optional[Dict[str, Any]] = None
    priority: int
    created_by_user_id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class ScreenStatsResponse(BaseModel):
    """Screen management statistics response"""
    total_recordings: int
    active_recordings: int
    completed_recordings: int
    failed_recordings: int
    total_size_bytes: int
    active_sessions: int
    total_sessions_today: int
    avg_session_duration: float
    avg_recording_size: float
