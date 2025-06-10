from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey, BigInteger
from datetime import datetime, timedelta
import enum
import uuid

from config.database import Base

class ClientStatus(enum.Enum):
    """Client connection status"""
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    ERROR = "error"

class ClientType(enum.Enum):
    """Type of client device"""
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    SERVER = "server"
    VIRTUAL = "virtual"

class Client(Base):
    """Client endpoint model"""
    __tablename__ = "clients"
    
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(50), unique=True, index=True, nullable=False)  # UUID from client
    
    # System Information
    hostname = Column(String(255), nullable=False, index=True)
    os_version = Column(String(100))
    os_build = Column(String(50))
    architecture = Column(String(20))  # x64, x86, ARM64
    domain = Column(String(100), index=True)
    
    # Hardware Information
    cpu_info = Column(Text)
    memory_total = Column(BigInteger)  # Total RAM in bytes
    disk_total = Column(BigInteger)  # Total disk space in bytes
    mac_address = Column(String(17))
    
    # Network Information
    ip_address = Column(String(45), index=True)  # IPv4 or IPv6
    vpn_ip_address = Column(String(15))  # VPN assigned IP
    vpn_connected = Column(Boolean, default=False)
    vpn_last_connected = Column(DateTime)
    vpn_bytes_sent = Column(BigInteger, default=0)
    vpn_bytes_received = Column(BigInteger, default=0)
    
    # Client Software
    client_version = Column(String(20))  # Version of our client software
    
    # Status and Health
    status = Column(String(20), default=ClientStatus.OFFLINE.value, index=True)
    last_heartbeat = Column(DateTime, index=True)
    last_seen = Column(DateTime, index=True)
    uptime = Column(Integer)  # Uptime in seconds
    
    # Classification and Assignment
    client_type = Column(String(20), default=ClientType.WORKSTATION.value)
    location = Column(String(200))  # Physical location
    asset_tag = Column(String(50))  # Asset tag number
    assigned_user_id = Column(Integer, ForeignKey("users.id"))  # Assigned technician
    
    # RDP Configuration
    rdp_enabled = Column(Boolean, default=False)
    rdp_port = Column(Integer, default=3389)
    rdp_username = Column(String(100))
    rdp_password = Column(String(255))  # Encrypted in production
    rdp_domain = Column(String(100))
    
    # Screen Management
    screen_access_enabled = Column(Boolean, default=False)
    screen_recording_enabled = Column(Boolean, default=False)
    screen_session_active = Column(Boolean, default=False)
    screen_session_started_at = Column(DateTime)
    screen_session_user_id = Column(Integer, ForeignKey("users.id"))
    
    # Task Execution
    task_execution_enabled = Column(Boolean, default=True)
    last_task_id = Column(Integer)
    last_task_status = Column(String(20))
    last_task_completed_at = Column(DateTime)
    
    # Security and Monitoring
    antivirus_status = Column(String(50))  # Status of antivirus software
    firewall_enabled = Column(Boolean)
    last_security_scan = Column(DateTime)
    
    # Configuration and Policies
    policies = Column(JSON)  # Applied policies
    configuration = Column(JSON)  # Client configuration
    client_metadata = Column(JSON)  # Additional metadata (renamed from metadata)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Client(id={self.id}, hostname='{self.hostname}', status='{self.status}')>"
    
    def is_online(self) -> bool:
        """Check if client is currently online based on heartbeat"""
        if not self.last_heartbeat:
            return False
        
        # Consider online if heartbeat within last 5 minutes
        threshold = datetime.utcnow() - timedelta(minutes=5)
        return self.last_heartbeat > threshold
    
    def get_uptime_formatted(self) -> str:
        """Get formatted uptime string"""
        if not self.uptime:
            return "Unknown"
        
        days = self.uptime // 86400
        hours = (self.uptime % 86400) // 3600
        minutes = (self.uptime % 3600) // 60
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    
    def can_execute_tasks(self) -> bool:
        """Check if client can execute tasks"""
        return (
            self.task_execution_enabled and 
            self.is_online() and 
            self.status == ClientStatus.ONLINE.value
        )
    
    def can_screen_access(self) -> bool:
        """Check if screen access is available"""
        return (
            self.screen_access_enabled and 
            self.is_online() and 
            self.status == ClientStatus.ONLINE.value
        )
    
    def can_rdp_access(self) -> bool:
        """Check if RDP access is available"""
        return (
            self.rdp_enabled and 
            self.rdp_username and 
            self.is_online() and 
            self.status == ClientStatus.ONLINE.value
        )
    
    def update_heartbeat(self, heartbeat_data: dict = None):
        """Update client heartbeat and status"""
        self.last_heartbeat = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        self.status = ClientStatus.ONLINE.value
        
        if heartbeat_data:
            if 'uptime' in heartbeat_data:
                self.uptime = heartbeat_data['uptime']
            if 'ip_address' in heartbeat_data:
                self.ip_address = heartbeat_data['ip_address']
            if 'vpn_connected' in heartbeat_data:
                self.vpn_connected = heartbeat_data['vpn_connected']
            if 'vpn_ip_address' in heartbeat_data:
                self.vpn_ip_address = heartbeat_data['vpn_ip_address']
        
        self.updated_at = datetime.utcnow()
    
    def get_memory_formatted(self) -> str:
        """Get formatted memory size"""
        if not self.memory_total:
            return "Unknown"
        
        size = float(self.memory_total)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def get_disk_formatted(self) -> str:
        """Get formatted disk size"""
        if not self.disk_total:
            return "Unknown"
        
        size = float(self.disk_total)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def get_network_usage_formatted(self) -> dict:
        """Get formatted network usage"""
        def format_bytes(size):
            if not size:
                return "0 B"
            size = float(size)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} PB"
        
        return {
            "bytes_sent": format_bytes(self.vpn_bytes_sent),
            "bytes_received": format_bytes(self.vpn_bytes_received),
            "total": format_bytes((self.vpn_bytes_sent or 0) + (self.vpn_bytes_received or 0))
        }
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert client to dictionary"""
        client_dict = {
            "id": self.id,
            "client_id": self.client_id,
            "hostname": self.hostname,
            "os_version": self.os_version,
            "os_build": self.os_build,
            "architecture": self.architecture,
            "domain": self.domain,
            "ip_address": self.ip_address,
            "vpn_ip_address": self.vpn_ip_address,
            "vpn_connected": self.vpn_connected,
            "client_version": self.client_version,
            "status": self.status,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "uptime": self.uptime,
            "uptime_formatted": self.get_uptime_formatted(),
            "client_type": self.client_type,
            "location": self.location,
            "asset_tag": self.asset_tag,
            "memory_total": self.memory_total,
            "memory_formatted": self.get_memory_formatted(),
            "disk_total": self.disk_total,
            "disk_formatted": self.get_disk_formatted(),
            "task_execution_enabled": self.task_execution_enabled,
            "screen_access_enabled": self.screen_access_enabled,
            "screen_recording_enabled": self.screen_recording_enabled,
            "rdp_enabled": self.rdp_enabled,
            "is_online": self.is_online(),
            "can_execute_tasks": self.can_execute_tasks(),
            "can_screen_access": self.can_screen_access(),
            "can_rdp_access": self.can_rdp_access(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
        
        if include_sensitive:
            client_dict.update({
                "rdp_username": self.rdp_username,
                "rdp_domain": self.rdp_domain,
                "assigned_user_id": self.assigned_user_id,
                "policies": self.policies,
                "configuration": self.configuration
            })
        
        return client_dict
