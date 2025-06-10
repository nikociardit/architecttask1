from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from models.client import ClientStatus, ClientType

class ClientBase(BaseModel):
    """Base client schema"""
    hostname: str
    client_type: ClientType = ClientType.WORKSTATION
    location: Optional[str] = None
    asset_tag: Optional[str] = None

class ClientRegister(BaseModel):
    """Client registration schema"""
    client_id: str
    hostname: str
    os_version: str
    os_build: str
    architecture: str
    domain: Optional[str] = None
    cpu_info: Optional[str] = None
    memory_total: Optional[int] = None
    disk_total: Optional[int] = None
    mac_address: Optional[str] = None
    client_version: str
    
    @validator('client_id')
    def client_id_valid(cls, v):
        if len(v) < 10:
            raise ValueError('client_id must be at least 10 characters')
        return v

class ClientUpdate(BaseModel):
    """Client update schema"""
    hostname: Optional[str] = None
    client_type: Optional[ClientType] = None
    location: Optional[str] = None
    asset_tag: Optional[str] = None
    assigned_user_id: Optional[int] = None
    rdp_enabled: Optional[bool] = None
    rdp_username: Optional[str] = None
    rdp_password: Optional[str] = None
    rdp_domain: Optional[str] = None
    screen_access_enabled: Optional[bool] = None
    screen_recording_enabled: Optional[bool] = None
    task_execution_enabled: Optional[bool] = None
    configuration: Optional[Dict[str, Any]] = None

class ClientHeartbeat(BaseModel):
    """Client heartbeat schema"""
    client_id: str
    ip_address: Optional[str] = None
    vpn_ip_address: Optional[str] = None
    vpn_connected: bool = False
    uptime: int = 0
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    antivirus_status: Optional[str] = None
    firewall_enabled: Optional[bool] = None
    last_task_id: Optional[int] = None
    last_task_status: Optional[str] = None

class ClientResponse(ClientBase):
    """Client response schema"""
    id: int
    client_id: str
    status: str
    os_version: Optional[str] = None
    os_build: Optional[str] = None
    architecture: Optional[str] = None
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    vpn_ip_address: Optional[str] = None
    vpn_connected: bool = False
    client_version: Optional[str] = None
    last_heartbeat: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    uptime: int = 0
    assigned_user_id: Optional[int] = None
    rdp_enabled: bool = True
    screen_access_enabled: bool = True
    screen_recording_enabled: bool = True
    task_execution_enabled: bool = True
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class ClientDetailResponse(ClientResponse):
    """Detailed client response schema"""
    cpu_info: Optional[str] = None
    memory_total: Optional[int] = None
    disk_total: Optional[int] = None
    mac_address: Optional[str] = None
    rdp_username: Optional[str] = None
    rdp_domain: Optional[str] = None
    antivirus_status: Optional[str] = None
    firewall_enabled: Optional[bool] = None
    windows_updates_status: Optional[str] = None
    encryption_status: Optional[str] = None
    configuration: Optional[Dict[str, Any]] = None
    policies: Optional[Dict[str, Any]] = None
    screen_session_active: bool = False
    screen_session_user_id: Optional[int] = None
    last_task_id: Optional[int] = None
    last_task_status: Optional[str] = None
    last_task_completed_at: Optional[datetime] = None

class ClientListResponse(BaseModel):
    """Client list response schema"""
    clients: List[ClientResponse]
    total: int
    page: int
    per_page: int
    pages: int

class ClientStatsResponse(BaseModel):
    """Client statistics response"""
    total_clients: int
    online_clients: int
    offline_clients: int
    vpn_connected_clients: int
    workstations: int
    laptops: int
    servers: int
    virtual_machines: int
    avg_uptime_hours: float
    total_tasks_executed: int

class ClientConfigResponse(BaseModel):
    """Client configuration response"""
    client_id: str
    vpn_config: Optional[str] = None
    policies: Dict[str, Any] = {}
    settings: Dict[str, Any] = {}
    server_endpoint: str
    heartbeat_interval: int = 60
    task_poll_interval: int = 30

class ClientTaskPoll(BaseModel):
    """Client task polling response"""
    tasks: List[Dict[str, Any]] = []
    config_updated: bool = False
    commands: List[Dict[str, Any]] = []

class ClientRDPCredentials(BaseModel):
    """Client RDP credentials response"""
    username: str
    password: str
    domain: Optional[str] = None
    port: int = 3389
