from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import logging
import secrets

from models.client import Client, ClientStatus, ClientType
from models.user import User
from models.task import Task, TaskStatus
from schemas.client import ClientRegister, ClientUpdate, ClientHeartbeat
from config.settings import settings
from utils.exceptions import ValidationError, NotFoundError, ConflictError

logger = logging.getLogger(__name__)

class ClientService:
    """Client management service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def register_client(
        self, 
        client_data: ClientRegister, 
        ip_address: str = None
    ) -> Client:
        """Register new client"""
        
        # Check if client already exists
        existing_client = self.db.query(Client).filter(
            Client.client_id == client_data.client_id
        ).first()
        
        if existing_client:
            # Update existing client registration
            return await self._update_existing_client(existing_client, client_data, ip_address)
        
        # Create new client
        client = Client(
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
            ip_address=ip_address,
            client_version=client_data.client_version,
            status=ClientStatus.ONLINE.value,
            last_heartbeat=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            created_at=datetime.utcnow()
        )
        
        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)
        
        logger.info(f"Client {client.hostname} ({client.client_id}) registered from {ip_address}")
        return client
    
    async def _update_existing_client(
        self, 
        client: Client, 
        client_data: ClientRegister, 
        ip_address: str = None
    ) -> Client:
        """Update existing client during re-registration"""
        
        # Update system information
        client.hostname = client_data.hostname
        client.os_version = client_data.os_version
        client.os_build = client_data.os_build
        client.architecture = client_data.architecture
        client.domain = client_data.domain
        client.cpu_info = client_data.cpu_info
        client.memory_total = client_data.memory_total
        client.disk_total = client_data.disk_total
        client.mac_address = client_data.mac_address
        client.client_version = client_data.client_version
        
        # Update network information
        if ip_address:
            client.ip_address = ip_address
        
        # Update status and timestamps
        client.status = ClientStatus.ONLINE.value
        client.last_heartbeat = datetime.utcnow()
        client.last_seen = datetime.utcnow()
        client.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(client)
        
        logger.info(f"Client {client.hostname} ({client.client_id}) re-registered from {ip_address}")
        return client
    
    async def process_heartbeat(
        self, 
        client_id: str, 
        heartbeat_data: ClientHeartbeat
    ) -> bool:
        """Process client heartbeat"""
        
        client = self.db.query(Client).filter(
            Client.client_id == client_id
        ).first()
        
        if not client:
            raise NotFoundError(f"Client {client_id} not found")
        
        # Update heartbeat information
        client.last_heartbeat = datetime.utcnow()
        client.last_seen = datetime.utcnow()
        client.status = ClientStatus.ONLINE.value
        client.uptime = heartbeat_data.uptime
        
        # Update network information
        if heartbeat_data.ip_address:
            client.ip_address = heartbeat_data.ip_address
        if heartbeat_data.vpn_ip_address:
            client.vpn_ip_address = heartbeat_data.vpn_ip_address
        
        client.vpn_connected = heartbeat_data.vpn_connected
        
        # Update system status
        if heartbeat_data.antivirus_status:
            client.antivirus_status = heartbeat_data.antivirus_status
        if heartbeat_data.firewall_enabled is not None:
            client.firewall_enabled = heartbeat_data.firewall_enabled
        
        # Update task status
        if heartbeat_data.last_task_id:
            client.last_task_id = heartbeat_data.last_task_id
        if heartbeat_data.last_task_status:
            client.last_task_status = heartbeat_data.last_task_status
        
        client.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        logger.debug(f"Heartbeat processed for client {client.hostname} ({client_id})")
        return True
    
    async def get_client_by_id(self, client_id: int) -> Optional[Client]:
        """Get client by ID"""
        return self.db.query(Client).filter(Client.id == client_id).first()
    
    async def get_client_by_client_id(self, client_id: str) -> Optional[Client]:
        """Get client by client_id"""
        return self.db.query(Client).filter(Client.client_id == client_id).first()
    
    async def list_clients(
        self,
        page: int = 1,
        per_page: int = 50,
        search: Optional[str] = None,
        status: Optional[str] = None
    ) -> Dict[str, Any]:
        """List clients with pagination and filtering"""
        
        query = self.db.query(Client)
        
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
                # Clients with heartbeat within threshold
                threshold = datetime.utcnow() - timedelta(seconds=settings.CLIENT_OFFLINE_THRESHOLD)
                query = query.filter(Client.last_heartbeat > threshold)
            elif status == "offline":
                # Clients with old heartbeat or no heartbeat
                threshold = datetime.utcnow() - timedelta(seconds=settings.CLIENT_OFFLINE_THRESHOLD)
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
        
        # Update online/offline status for each client
        for client in clients:
            if client.is_online():
                client.status = ClientStatus.ONLINE.value
            else:
                client.status = ClientStatus.OFFLINE.value
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        
        return {
            "clients": clients,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages
        }
    
    async def update_client(
        self, 
        client_id: int, 
        client_data: ClientUpdate, 
        updated_by: int
    ) -> Client:
        """Update client"""
        
        client = await self.get_client_by_id(client_id)
        if not client:
            raise NotFoundError("Client not found")
        
        # Update fields
        if client_data.hostname is not None:
            client.hostname = client_data.hostname
        
        if client_data.client_type is not None:
            client.client_type = client_data.client_type.value
        
        if client_data.location is not None:
            client.location = client_data.location
        
        if client_data.asset_tag is not None:
            client.asset_tag = client_data.asset_tag
        
        if client_data.assigned_user_id is not None:
            # Validate user exists
            user = self.db.query(User).filter(User.id == client_data.assigned_user_id).first()
            if not user:
                raise ValidationError("Assigned user not found")
            client.assigned_user_id = client_data.assigned_user_id
        
        # Update RDP settings
        if client_data.rdp_enabled is not None:
            client.rdp_enabled = client_data.rdp_enabled
        
        if client_data.rdp_username is not None:
            client.rdp_username = client_data.rdp_username
        
        if client_data.rdp_password is not None:
            # Encrypt password in production
            client.rdp_password = client_data.rdp_password
        
        if client_data.rdp_domain is not None:
            client.rdp_domain = client_data.rdp_domain
        
        # Update screen settings
        if client_data.screen_access_enabled is not None:
            client.screen_access_enabled = client_data.screen_access_enabled
        
        if client_data.screen_recording_enabled is not None:
            client.screen_recording_enabled = client_data.screen_recording_enabled
        
        # Update task settings
        if client_data.task_execution_enabled is not None:
            client.task_execution_enabled = client_data.task_execution_enabled
        
        # Update configuration
        if client_data.configuration is not None:
            client.configuration = client_data.configuration
        
        client.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(client)
        
        logger.info(f"Client {client.hostname} updated by user {updated_by}")
        return client
    
    async def delete_client(self, client_id: int) -> bool:
        """Delete client (soft delete)"""
        
        client = await self.get_client_by_id(client_id)
        if not client:
            raise NotFoundError("Client not found")
        
        # Soft delete - mark as inactive
        client.status = ClientStatus.OFFLINE.value
        client.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        logger.info(f"Client {client.hostname} deleted (soft delete)")
        return True
    
    async def get_client_config(self, client_id: str) -> Dict[str, Any]:
        """Get client configuration"""
        
        client = await self.get_client_by_client_id(client_id)
        if not client:
            raise NotFoundError("Client not found")
        
        # Get VPN config if user is assigned
        vpn_config = None
        if client.assigned_user_id:
            user = self.db.query(User).filter(User.id == client.assigned_user_id).first()
            if user and user.vpn_enabled:
                vpn_config = user.get_vpn_config()
        
        config = {
            "client_id": client.client_id,
            "vpn_config": vpn_config,
            "policies": client.policies or {},
            "settings": client.configuration or {},
            "server_endpoint": f"http://localhost:{settings.PORT}",  # Should be actual server URL
            "heartbeat_interval": settings.CLIENT_HEARTBEAT_INTERVAL,
            "task_poll_interval": 30
        }
        
        return config
    
    async def get_pending_tasks(self, client_id: str) -> List[Dict[str, Any]]:
        """Get pending tasks for client"""
        
        client = await self.get_client_by_client_id(client_id)
        if not client:
            raise NotFoundError("Client not found")
        
        # Get pending tasks
        pending_tasks = self.db.query(Task).filter(
            and_(
                Task.client_id == client.id,
                Task.status == TaskStatus.PENDING.value
            )
        ).all()
        
        tasks = []
        for task in pending_tasks:
            tasks.append(task.to_execution_dict())
            
            # Mark task as running
            task.status = TaskStatus.RUNNING.value
            task.started_at = datetime.utcnow()
        
        if tasks:
            self.db.commit()
        
        return tasks
    
    async def get_rdp_credentials(self, client_id: str) -> Dict[str, Any]:
        """Get RDP credentials for client"""
        
        # Accept both string and int client_id for flexibility
        if isinstance(client_id, str) and client_id.isdigit():
            client = await self.get_client_by_id(int(client_id))
        elif isinstance(client_id, str):
            client = await self.get_client_by_client_id(client_id)
        else:
            client = await self.get_client_by_id(client_id)
        
        if not client:
            raise NotFoundError("Client not found")
        
        if not client.rdp_enabled:
            raise ValidationError("RDP is not enabled for this client")
        
        return {
            "username": client.rdp_username or "Administrator",
            "password": client.rdp_password or "",  # Decrypt in production
            "domain": client.rdp_domain or "",
            "port": client.rdp_port or 3389
        }
    
    async def get_client_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        
        total_clients = self.db.query(Client).count()
        
        # Online clients (heartbeat within threshold)
        threshold = datetime.utcnow() - timedelta(seconds=settings.CLIENT_OFFLINE_THRESHOLD)
        online_clients = self.db.query(Client).filter(
            Client.last_heartbeat > threshold
        ).count()
        
        offline_clients = total_clients - online_clients
        
        # VPN connected clients
        vpn_connected_clients = self.db.query(Client).filter(
            Client.vpn_connected == True
        ).count()
        
        # Client types
        workstations = self.db.query(Client).filter(
            Client.client_type == ClientType.WORKSTATION.value
        ).count()
        
        laptops = self.db.query(Client).filter(
            Client.client_type == ClientType.LAPTOP.value
        ).count()
        
        servers = self.db.query(Client).filter(
            Client.client_type == ClientType.SERVER.value
        ).count()
        
        virtual_machines = self.db.query(Client).filter(
            Client.client_type == ClientType.VIRTUAL.value
        ).count()
        
        # Average uptime
        avg_uptime_result = self.db.query(func.avg(Client.uptime)).filter(
            Client.uptime.isnot(None)
        ).scalar()
        avg_uptime_hours = (avg_uptime_result / 3600) if avg_uptime_result else 0
        
        # Total tasks executed
        total_tasks_executed = self.db.query(Task).filter(
            Task.status.in_([TaskStatus.COMPLETED.value, TaskStatus.FAILED.value])
        ).count()
        
        return {
            "total_clients": total_clients,
            "online_clients": online_clients,
            "offline_clients": offline_clients,
            "vpn_connected_clients": vpn_connected_clients,
            "workstations": workstations,
            "laptops": laptops,
            "servers": servers,
            "virtual_machines": virtual_machines,
            "avg_uptime_hours": round(avg_uptime_hours, 2),
            "total_tasks_executed": total_tasks_executed
        }
    
    async def update_client_status(self):
        """Update client online/offline status based on heartbeat"""
        
        threshold = datetime.utcnow() - timedelta(seconds=settings.CLIENT_OFFLINE_THRESHOLD)
        
        # Mark clients as offline if heartbeat is old
        offline_clients = self.db.query(Client).filter(
            and_(
                Client.status == ClientStatus.ONLINE.value,
                or_(
                    Client.last_heartbeat.is_(None),
                    Client.last_heartbeat <= threshold
                )
            )
        ).all()
        
        for client in offline_clients:
            client.status = ClientStatus.OFFLINE.value
            client.vpn_connected = False
            client.updated_at = datetime.utcnow()
        
        if offline_clients:
            self.db.commit()
            logger.info(f"Marked {len(offline_clients)} clients as offline")
        
        return len(offline_clients)
