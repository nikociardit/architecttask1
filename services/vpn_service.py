from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi.responses import Response
import logging
import tempfile
import os

from models.user import User
from models.client import Client
from models.audit import AuditLog, AuditAction
from config.security import security
from config.settings import settings
from utils.exceptions import ValidationError, NotFoundError

logger = logging.getLogger(__name__)

class VPNService:
    """VPN management service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def get_user_vpn_config(self, user_id: int) -> Dict[str, Any]:
        """Get VPN configuration for user"""
        
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise NotFoundError("User not found")
        
        if not user.vpn_enabled:
            raise ValidationError("VPN is not enabled for this user")
        
        if not user.vpn_private_key:
            raise ValidationError("VPN keys not generated for this user")
        
        config = {
            "config": user.get_vpn_config(),
            "private_key": user.vpn_private_key,
            "public_key": user.vpn_public_key,
            "ip_address": user.vpn_ip_address,
            "server_endpoint": f"{settings.VPN_SERVER_ENDPOINT}:{settings.VPN_PORT}",
            "server_public_key": settings.VPN_SERVER_PUBLIC_KEY,
            "network": settings.VPN_NETWORK
        }
        
        return config
    
    async def generate_config_file(self, user_id: int) -> Response:
        """Generate VPN configuration file for download"""
        
        config_data = await self.get_user_vpn_config(user_id)
        config_content = config_data["config"]
        
        user = self.db.query(User).filter(User.id == user_id).first()
        filename = f"{user.username}_vpn.conf"
        
        return Response(
            content=config_content,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    
    async def regenerate_user_config(self, user_id: int) -> Dict[str, Any]:
        """Regenerate VPN configuration for user"""
        
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise NotFoundError("User not found")
        
        # Generate new VPN keys
        private_key, public_key = security.generate_vpn_keys()
        
        user.vpn_private_key = private_key
        user.vpn_public_key = public_key
        user.vpn_enabled = True
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(user)
        
        logger.info(f"VPN config regenerated for user {user.username}")
        
        return await self.get_user_vpn_config(user_id)
    
    async def get_vpn_status(self, user_id: int) -> Dict[str, Any]:
        """Get VPN connection status for user"""
        
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise NotFoundError("User not found")
        
        # Find clients assigned to this user
        assigned_clients = self.db.query(Client).filter(
            Client.assigned_user_id == user_id
        ).all()
        
        connected_clients = []
        for client in assigned_clients:
            if client.vpn_connected:
                connected_clients.append({
                    "hostname": client.hostname,
                    "ip_address": client.vpn_ip_address,
                    "last_connected": client.vpn_last_connected.isoformat() if client.vpn_last_connected else None,
                    "bytes_sent": client.vpn_bytes_sent,
                    "bytes_received": client.vpn_bytes_received
                })
        
        status = {
            "user_id": user_id,
            "vpn_enabled": user.vpn_enabled,
            "vpn_ip": user.vpn_ip_address,
            "connected_clients": connected_clients,
            "total_clients": len(assigned_clients),
            "connected_count": len(connected_clients)
        }
        
        return status
    
    async def report_connection(self, client_id: str, vpn_ip: str) -> bool:
        """Report VPN connection from client"""
        
        client = self.db.query(Client).filter(
            Client.client_id == client_id
        ).first()
        
        if not client:
            logger.warning(f"VPN connection reported for unknown client: {client_id}")
            return False
        
        # Update client VPN status
        client.vpn_connected = True
        client.vpn_ip_address = vpn_ip
        client.vpn_last_connected = datetime.utcnow()
        client.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        # Log VPN connection
        AuditLog.log_action(
            action=AuditAction.VPN_CONNECTED.value,
            description=f"Client {client.hostname} connected to VPN with IP {vpn_ip}",
            client_id=client.id,
            ip_address=vpn_ip
        )
        
        logger.info(f"VPN connection reported for client {client.hostname} ({client_id}) with IP {vpn_ip}")
        return True
    
    async def report_disconnection(self, client_id: str) -> bool:
        """Report VPN disconnection from client"""
        
        client = self.db.query(Client).filter(
            Client.client_id == client_id
        ).first()
        
        if not client:
            logger.warning(f"VPN disconnection reported for unknown client: {client_id}")
            return False
        
        # Update VPN statistics before disconnecting
        if client.vpn_connected and client.vpn_last_connected:
            connection_duration = datetime.utcnow() - client.vpn_last_connected
            # Could store connection duration stats here
        
        # Update client VPN status
        client.vpn_connected = False
        client.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        # Log VPN disconnection
        AuditLog.log_action(
            action=AuditAction.VPN_DISCONNECTED.value,
            description=f"Client {client.hostname} disconnected from VPN",
            client_id=client.id
        )
        
        logger.info(f"VPN disconnection reported for client {client.hostname} ({client_id})")
        return True
    
    async def update_traffic_stats(
        self, 
        client_id: str, 
        bytes_sent: int, 
        bytes_received: int
    ) -> bool:
        """Update VPN traffic statistics"""
        
        client = self.db.query(Client).filter(
            Client.client_id == client_id
        ).first()
        
        if not client:
            return False
        
        client.vpn_bytes_sent = bytes_sent
        client.vpn_bytes_received = bytes_received
        client.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        return True
    
    async def get_vpn_stats(self) -> Dict[str, Any]:
        """Get VPN statistics"""
        
        # Total users with VPN enabled
        total_vpn_users = self.db.query(User).filter(User.vpn_enabled == True).count()
        
        # Total clients with VPN connected
        connected_clients = self.db.query(Client).filter(Client.vpn_connected == True).count()
        
        # Total clients with VPN capability
        total_clients = self.db.query(Client).count()
        
        # VPN traffic statistics
        total_sent_result = self.db.query(
            func.sum(Client.vpn_bytes_sent)
        ).filter(Client.vpn_bytes_sent.isnot(None)).scalar()
        
        total_received_result = self.db.query(
            func.sum(Client.vpn_bytes_received)
        ).filter(Client.vpn_bytes_received.isnot(None)).scalar()
        
        total_bytes_sent = total_sent_result or 0
        total_bytes_received = total_received_result or 0
        
        # Recent connections (last 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_connections = self.db.query(Client).filter(
            and_(
                Client.vpn_last_connected >= yesterday,
                Client.vpn_connected == True
            )
        ).count()
        
        stats = {
            "total_vpn_users": total_vpn_users,
            "connected_clients": connected_clients,
            "total_clients": total_clients,
            "connection_rate": round((connected_clients / total_clients * 100) if total_clients > 0 else 0, 2),
            "total_bytes_sent": total_bytes_sent,
            "total_bytes_received": total_bytes_received,
            "total_traffic": total_bytes_sent + total_bytes_received,
            "recent_connections_24h": recent_connections
        }
        
        return stats
    
    async def list_vpn_connections(self) -> List[Dict[str, Any]]:
        """List active VPN connections"""
        
        connected_clients = self.db.query(Client).filter(
            Client.vpn_connected == True
        ).all()
        
        connections = []
        for client in connected_clients:
            user = None
            if client.assigned_user_id:
                user = self.db.query(User).filter(User.id == client.assigned_user_id).first()
            
            connection = {
                "client_id": client.client_id,
                "hostname": client.hostname,
                "vpn_ip": client.vpn_ip_address,
                "real_ip": client.ip_address,
                "connected_since": client.vpn_last_connected.isoformat() if client.vpn_last_connected else None,
                "bytes_sent": client.vpn_bytes_sent,
                "bytes_received": client.vpn_bytes_received,
                "user": {
                    "username": user.username if user else None,
                    "full_name": user.full_name if user else None
                } if user else None
            }
            connections.append(connection)
        
        return connections
    
    async def revoke_vpn_access(self, user_id: int) -> bool:
        """Revoke VPN access for user"""
        
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise NotFoundError("User not found")
        
        # Disable VPN for user
        user.vpn_enabled = False
        user.updated_at = datetime.utcnow()
        
        # Disconnect all clients assigned to this user
        assigned_clients = self.db.query(Client).filter(
            Client.assigned_user_id == user_id
        ).all()
        
        for client in assigned_clients:
            if client.vpn_connected:
                client.vpn_connected = False
                client.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        logger.info(f"VPN access revoked for user {user.username}")
        return True
    
    async def get_server_config(self) -> Dict[str, Any]:
        """Get VPN server configuration"""
        
        # This would typically be used to configure the WireGuard server
        config = {
            "server_private_key": settings.VPN_SERVER_PRIVATE_KEY,
            "server_public_key": settings.VPN_SERVER_PUBLIC_KEY,
            "network": settings.VPN_NETWORK,
            "port": settings.VPN_PORT,
            "endpoint": settings.VPN_SERVER_ENDPOINT
        }
        
        return config
    
    async def generate_server_config_file(self) -> str:
        """Generate WireGuard server configuration file"""
        
        # Get all active VPN users
        vpn_users = self.db.query(User).filter(
            and_(
                User.vpn_enabled == True,
                User.vpn_public_key.isnot(None)
            )
        ).all()
        
        config_lines = [
            "[Interface]",
            f"PrivateKey = {settings.VPN_SERVER_PRIVATE_KEY}",
            f"Address = {settings.VPN_NETWORK.split('/')[0]}/24",
            f"ListenPort = {settings.VPN_PORT}",
            "",
            "# PostUp and PostDown rules for NAT",
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
            ""
        ]
        
        # Add peer configurations
        for user in vpn_users:
            config_lines.extend([
                "# " + user.full_name + " (" + user.username + ")",
                "[Peer]",
                f"PublicKey = {user.vpn_public_key}",
                f"AllowedIPs = {user.vpn_ip_address}/32",
                ""
            ])
        
        return "\n".join(config_lines)
    
    async def cleanup_stale_connections(self) -> int:
        """Clean up stale VPN connections"""
        
        # Mark connections as disconnected if no heartbeat for too long
        threshold = datetime.utcnow() - timedelta(seconds=settings.CLIENT_OFFLINE_THRESHOLD * 2)
        
        stale_clients = self.db.query(Client).filter(
            and_(
                Client.vpn_connected == True,
                or_(
                    Client.last_heartbeat.is_(None),
                    Client.last_heartbeat <= threshold
                )
            )
        ).all()
        
        for client in stale_clients:
            client.vpn_connected = False
            client.updated_at = datetime.utcnow()
        
        if stale_clients:
            self.db.commit()
            logger.info(f"Cleaned up {len(stale_clients)} stale VPN connections")
        
        return len(stale_clients)
