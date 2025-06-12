from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey, BigInteger
from datetime import datetime, timedelta
import enum

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
    """Client endpoint model - clean version without relationships"""
    __tablename__ = "clients"
    
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(50), unique=True, index=True, nullable=False)
    
    # System Information
    hostname = Column(String(255), nullable=False, index=True)
    os_version = Column(String(100))
    os_build = Column(String(50))
    architecture = Column(String(20))
    domain = Column(String(100), index=True)
    
    # Hardware Information
    cpu_info = Column(Text)
    memory_total = Column(BigInteger)
    disk_total = Column(BigInteger)
    mac_address = Column(String(17))
    
    # Network Information
    ip_address = Column(String(45), index=True)
    vpn_ip_address = Column(String(15))
    vpn_connected = Column(Boolean, default=False)
    
    # Client Software
    client_version = Column(String(20))
    
    # Status and Health
    status = Column(String(20), default=ClientStatus.OFFLINE.value, index=True)
    last_heartbeat = Column(DateTime, index=True)
    last_seen = Column(DateTime, index=True)
    uptime = Column(Integer)
    
    # Classification
    client_type = Column(String(20), default=ClientType.WORKSTATION.value)
    location = Column(String(200))
    assigned_user_id = Column(Integer, ForeignKey("users.id"))
    
    # Features
    rdp_enabled = Column(Boolean, default=False)
    screen_access_enabled = Column(Boolean, default=False)
    task_execution_enabled = Column(Boolean, default=True)
    
    # Configuration
    policies = Column(JSON)
    configuration = Column(JSON)
    extra_data = Column(JSON)  # Renamed from metadata
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Client(id={self.id}, hostname='{self.hostname}', status='{self.status}')>"
    
    def is_online(self):
        """Check if client is online"""
        if not self.last_heartbeat:
            return False
        threshold = datetime.utcnow() - timedelta(minutes=5)
        return self.last_heartbeat > threshold
