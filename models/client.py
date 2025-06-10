from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from config.database import Base

class ClientStatus(enum.Enum):
    """Client connection status"""
    ONLINE = "online"
    OFFLINE = "offline"
    CONNECTING = "connecting"
    ERROR = "error"

class ClientType(enum.Enum):
    """Client type/category"""
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    SERVER = "server"
    VIRTUAL = "virtual"

class Client(Base):
    """Client/Endpoint model for managed Windows devices"""
    __tablename__ = "clients"
    
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(50), unique=True, index=True, nullable=False)  # Unique client identifier
    hostname = Column(String(100), nullable=False)
    
    # System Information
    os_version = Column(String(100))
    os_build = Column(String(50))
    architecture = Column(String(20))  # x64, x86
    domain = Column(String(100))
    
    # Hardware Information
    cpu_info = Column(Text)
    memory_total = Column(Integer)  # MB
    disk_total = Column(Integer)  # GB
    
    # Network Information
    ip_address = Column(String(15))
    mac_address = Column(String(17))
    vpn_ip_address = Column(String(15))
    
    # Client software
    client_version = Column(String(20))
    client_path = Column(String(500))
    auto_update_enabled = Column(Boolean, default=True)
    
    # Status and monitoring
    status = Column(String(20), default=ClientStatus.OFFLINE.value)
    last_heartbeat = Column(DateTime)
    last_seen = Column(DateTime)
    uptime = Column(Integer, default=0)  # seconds
    
    # VPN Status
    vpn_connected = Column(Boolean, default=False)
    vpn_last_connected = Column(DateTime)
    vpn_bytes_sent = Column(Integer, default=0)
    vpn_bytes_received = Column(Integer, default=0)
    
    # RDP Configuration
    rdp_enabled = Column(Boolean, default=True)
    rdp_port = Column(Integer, default=3389)
    rdp_username = Column(String(100))
    rdp_password = Column(String(255))  # Encrypted
    rdp_domain = Column(String(100))
    
    # Screen Management
    screen_access_enabled = Column(Boolean, default=True)
    screen_recording_enabled = Column(Boolean, default=True)
    screen_recording_quality = Column(String(20), default="medium")
    screen_session_active = Column(Boolean, default=False)
    screen_session_started_at = Column(DateTime)
    screen_session_user_id = Column(Integer, ForeignKey("users.id"))
    
    # Task Execution
    task_execution_enabled = Column(Boolean, default=True)
    last_task_id = Column(Integer)
    last_task_status = Column(String(20))
    last_task_completed_at = Column(DateTime)
    
    # Security and Compliance
    antivirus_status = Column(String(50))
    firewall_enabled = Column(Boolean)
    windows_updates_status = Column(String(50))
    encryption_status = Column(String(50))
    
    # Management
    client_type = Column(String(20), default=ClientType.WORKSTATION.value)
    assigned_user_id = Column(Integer, ForeignKey("users.id"))
    location = Column(String(200))
    asset_tag = Column(String(50))
    
    # Configuration
    configuration = Column(JSON)  # Client-specific settings
    policies = Column(JSON)  # Applied policies
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_config_update = Column(DateTime)
    
    # Relationships
    assigned_user = relationship("User", back_populates="managed_clients")
    screen_session_user = relationship("User", foreign_keys=[screen_session_user_id])
    tasks = relationship("Task", back_populates="client")
    screen_recordings = relationship("ScreenRecording", back_populates="client")
    audit_logs = relationship("AuditLog", back_populates="client")
    
    def __repr__(self):
        return f"<Client(id={self.id}, hostname='{self.hostname}', status='{self.status}')>"
    
    def is_online(self) -> bool:
        """Check if client is currently online"""
        if not self.last_heartbeat:
            return False
        
        from config.settings import settings
        threshold = datetime.utcnow().timestamp() - settings.CLIENT_OFFLINE_THRESHOLD
        return self.last_heartbeat.timestamp() > threshold
    
    def get_status_display(self) -> str:
        """Get human-readable status"""
        if self.is_online():
            return "Online"
        elif self.status == ClientStatus.ERROR.value:
            return "Error"
        elif self.status == ClientStatus.CONNECTING.value:
            return "Connecting"
        else:
            return "Offline"
    
    def get_system_info(self) -> dict:
        """Get formatted system information"""
        return {
            "hostname": self.hostname,
            "os": f"{self.os_version} ({self.os_build})",
            "architecture": self.architecture,
            "domain": self.domain,
            "cpu": self.cpu_info,
            "memory": f"{self.memory_total} MB" if self.memory_total else "Unknown",
            "disk": f"{self.disk_total} GB" if self.disk_total else "Unknown",
            "ip_address": self.ip_address,
            "vpn_ip": self.vpn_ip_address,
            "client_version": self.client_version
        }
    
    def update_heartbeat(self):
        """Update heartbeat timestamp"""
        self.last_heartbeat = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        if self.status != ClientStatus.ONLINE.value:
            self.status = ClientStatus.ONLINE.value
    
    def can_execute_tasks(self) -> bool:
        """Check if client can execute tasks"""
        return (
            self.is_online() and 
            self.task_execution_enabled and
            self.vpn_connected
        )
    
    def can_screen_access(self) -> bool:
        """Check if screen access is available"""
        return (
            self.is_online() and 
            self.screen_access_enabled and
            self.vpn_connected
        )
