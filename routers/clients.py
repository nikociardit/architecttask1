from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_
from typing import List, Optional
from datetime import datetime, timedelta
import logging

from config.database import get_db
from models.client import Client, ClientStatus, ClientType
from models.audit import AuditLog
from routers.auth import get_current_user
from models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)

# Pydantic models
from pydantic import BaseModel

class ClientRegister(BaseModel):
    client_id: str
    hostname: str
    os_version: Optional[str] = None
    os_build: Optional[str] = None
    architecture: Optional[str] = None
    domain: Optional[str] = None
    cpu_info: Optional[str] = None
    memory_total: Optional[int] = None
    disk_total: Optional[int] = None
    mac_address: Optional[str] = None
    client_version: Optional[str] = None

class ClientHeartbeat(BaseModel):
    client_id: str
    ip_address: Optional[str] = None
    vpn_ip_address: Optional[str] = None
    vpn_connected: bool = False
    uptime: Optional[int] = None

class ClientUpdate(BaseModel):
    hostname: Optional[str] = None
    location: Optional[str] = None
    assigned_user_id: Optional[int] = None
    rdp_enabled: Optional[bool] = None
    screen_access_enabled: Optional[bool] = None
    task_execution_enabled: Optional[bool] = None

class ClientResponse(BaseModel):
    id: int
    client_id: str
    hostname: str
    status: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    vpn_connected: bool = False
    last_heartbeat: Optional[datetime] = None
    client_type: str
    location: Optional[str] = None
    created_at: datetime

class ClientListResponse(BaseModel):
    clients: List[ClientResponse]
    total: int
    page: int
    per_page: int

@router.get("/", response_model=ClientListResponse)
async def list_clients(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    search: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List clients with pagination and filtering"""
    try:
        query = db.query(Client)
        
        # Apply search filter
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Client.hostname.ilike(search_term),
                    Client.client_id.ilike(search_term),
                    Client.ip_address.ilike(search_term),
                    Client.domain.ilike(search_term)
                )
            )
        
        # Apply status filter
        if status:
            if status == "online":
                # Clients with recent heartbeat
                threshold = datetime.utcnow() - timedelta(minutes=5)
                query = query.filter(Client.last_heartbeat > threshold)
            elif status == "offline":
                # Clients with old or no heartbeat
                threshold = datetime.utcnow() - timedelta(minutes=5)
                query = query.filter(
                    or_(
                        Client.last_heartbeat.is_(None),
                        Client.last_heartbeat <= threshold
                    )
                )
            else:
                query = query.filter(Client.status == status)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        clients = query.offset(offset).limit(per_page).all()
        
        # Convert to response format and update status
        client_responses = []
        for client in clients:
            # Update online/offline status based on heartbeat
            if client.last_heartbeat:
                threshold = datetime.utcnow() - timedelta(minutes=5)
                is_online = client.last_heartbeat > threshold
                client.status = "online" if is_online else "offline"
            else:
                client.status = "offline"
            
            client_responses.append(ClientResponse(
                id=client.id,
                client_id=client.client_id,
                hostname=client.hostname,
                status=client.status,
                os_version=client.os_version,
                ip_address=client.ip_address,
                vpn_connected=client.vpn_connected,
                last_heartbeat=client.last_heartbeat,
                client_type=client.client_type,
                location=client.location,
                created_at=client.created_at
            ))
        
        return ClientListResponse(
            clients=client_responses,
            total=total,
            page=page,
            per_page=per_page
        )
        
    except Exception as e:
        logger.error(f"Error listing clients: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/register", response_model=ClientResponse)
async def register_client(
    request: Request,
    client_data: ClientRegister,
    db: Session = Depends(get_db)
):
    """Register new client (called by client software)"""
    try:
        # Check if client already exists
        existing_client = db.query(Client).filter(
            Client.client_id == client_data.client_id
        ).first()
        
        if existing_client:
            # Update existing client registration
            existing_client.hostname = client_data.hostname
            existing_client.os_version = client_data.os_version
            existing_client.os_build = client_data.os_build
            existing_client.architecture = client_data.architecture
            existing_client.domain = client_data.domain
            existing_client.cpu_info = client_data.cpu_info
            existing_client.memory_total = client_data.memory_total
            existing_client.disk_total = client_data.disk_total
            existing_client.mac_address = client_data.mac_address
            existing_client.client_version = client_data.client_version
            existing_client.ip_address = getattr(request.client, 'host', None)
            existing_client.last_heartbeat = datetime.utcnow()
            existing_client.last_seen = datetime.utcnow()
            existing_client.status = "online"
            existing_client.updated_at = datetime.utcnow()
            
            db.commit()
            db.refresh(existing_client)
            
            logger.info(f"Client {existing_client.hostname} re-registered")
            return ClientResponse(
                id=existing_client.id,
                client_id=existing_client.client_id,
                hostname=existing_client.hostname,
                status=existing_client.status,
                os_version=existing_client.os_version,
                ip_address=existing_client.ip_address,
                vpn_connected=existing_client.vpn_connected,
                last_heartbeat=existing_client.last_heartbeat,
                client_type=existing_client.client_type,
                location=existing_client.location,
                created_at=existing_client.created_at
            )
        
        # Create new client
        new_client = Client(
            client_id=client_data.client_id,
            hostname=client_data.hostname,
            os_version=client_data.os_version,
            os_build=client_data.os_build,
            architecture=client_data.architecture,
            domain=client_data.domain,
            cpu_info=client_data.cpu_info,
            memory_total=client_data.memory_total,
            disk_total=client_data.disk_total,
            mac_address=client_data.mac_address,
            client_version=client_data.client_version,
            ip_address=getattr(request.client, 'host', None),
            status="online",
            last_heartbeat=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            created_at=datetime.utcnow()
        )
        
        db.add(new_client)
        db.commit()
        db.refresh(new_client)
        
        # Log client registration
        AuditLog.log_action(
            action="client_registered",
            description=f"Client {new_client.hostname} registered from {getattr(request.client, 'host', 'unknown')}",
            client_id=new_client.id,
            ip_address=getattr(request.client, 'host', None),
            db=db
        )
        
        logger.info(f"New client {new_client.hostname} registered")
        return ClientResponse(
            id=new_client.id,
            client_id=new_client.client_id,
            hostname=new_client.hostname,
            status=new_client.status,
            os_version=new_client.os_version,
            ip_address=new_client.ip_address,
            vpn_connected=new_client.vpn_connected,
            last_heartbeat=new_client.last_heartbeat,
            client_type=new_client.client_type,
            location=new_client.location,
            created_at=new_client.created_at
        )
        
    except Exception as e:
        logger.error(f"Error registering client: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/{client_id}/heartbeat")
async def client_heartbeat(
    client_id: str,
    heartbeat_data: ClientHeartbeat,
    request: Request,
    db: Session = Depends(get_db)
):
    """Client heartbeat endpoint"""
    try:
        client = db.query(Client).filter(Client.client_id == client_id).first()
        if not client:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Client not found"
            )
        
        # Update heartbeat information
        client.last_heartbeat = datetime.utcnow()
        client.last_seen = datetime.utcnow()
        client.status = "online"
        
        if heartbeat_data.ip_address:
            client.ip_address = heartbeat_data.ip_address
        if heartbeat_data.vpn_ip_address:
            client.vpn_ip_address = heartbeat_data.vpn_ip_address
        if heartbeat_data.uptime is not None:
            client.uptime = heartbeat_data.uptime
        
        client.vpn_connected = heartbeat_data.vpn_connected
        client.updated_at = datetime.utcnow()
        
        db.commit()
        
        return {
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
            "next_heartbeat": (datetime.utcnow() + timedelta(seconds=60)).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing heartbeat for {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/{client_id}")
async def get_client(
    client_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get client details by ID"""
    try:
        client = db.query(Client).filter(Client.id == client_id).first()
        if not client:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Client not found"
            )
        
        # Update status based on heartbeat
        if client.last_heartbeat:
            threshold = datetime.utcnow() - timedelta(minutes=5)
            client.status = "online" if client.last_heartbeat > threshold else "offline"
        else:
            client.status = "offline"
        
        return {
            "id": client.id,
            "client_id": client.client_id,
            "hostname": client.hostname,
            "status": client.status,
            "os_version": client.os_version,
            "os_build": client.os_build,
            "architecture": client.architecture,
            "domain": client.domain,
            "ip_address": client.ip_address,
            "vpn_ip_address": client.vpn_ip_address,
            "vpn_connected": client.vpn_connected,
            "client_version": client.client_version,
            "last_heartbeat": client.last_heartbeat.isoformat() if client.last_heartbeat else None,
            "last_seen": client.last_seen.isoformat() if client.last_seen else None,
            "uptime": client.uptime,
            "client_type": client.client_type,
            "location": client.location,
            "assigned_user_id": client.assigned_user_id,
            "rdp_enabled": client.rdp_enabled,
            "screen_access_enabled": client.screen_access_enabled,
            "task_execution_enabled": client.task_execution_enabled,
            "created_at": client.created_at.isoformat(),
            "updated_at": client.updated_at.isoformat() if client.updated_at else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/stats/summary")
async def get_client_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get client statistics"""
    try:
        total_clients = db.query(Client).count()
        
        # Online clients (heartbeat within last 5 minutes)
        threshold = datetime.utcnow() - timedelta(minutes=5)
        online_clients = db.query(Client).filter(
            Client.last_heartbeat > threshold
        ).count()
        
        # VPN connected clients
        vpn_connected = db.query(Client).filter(
            Client.vpn_connected == True
        ).count()
        
        # Client types
        workstations = db.query(Client).filter(
            Client.client_type == "workstation"
        ).count()
        laptops = db.query(Client).filter(
            Client.client_type == "laptop"
        ).count()
        servers = db.query(Client).filter(
            Client.client_type == "server"
        ).count()
        
        return {
            "total_clients": total_clients,
            "online_clients": online_clients,
            "offline_clients": total_clients - online_clients,
            "vpn_connected_clients": vpn_connected,
            "workstations": workstations,
            "laptops": laptops,
            "servers": servers
        }
        
    except Exception as e:
        logger.error(f"Error getting client stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
