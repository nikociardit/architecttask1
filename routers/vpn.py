from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import logging

from config.database import get_db
from services.auth_service import AuthService
from services.vpn_service import VPNService
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

@router.get("/config")
async def get_vpn_config(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get VPN configuration for current user"""
    try:
        if not current_user.vpn_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="VPN access not enabled for this user"
            )
        
        vpn_service = VPNService(db)
        config = await vpn_service.get_user_vpn_config(current_user.id)
        
        return config
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting VPN config for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/config/download")
async def download_vpn_config(
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download VPN configuration file"""
    try:
        if not current_user.vpn_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="VPN access not enabled for this user"
            )
        
        vpn_service = VPNService(db)
        config_file = await vpn_service.generate_config_file(current_user.id)
        
        # Log VPN config download
        AuditLog.log_action(
            action=AuditAction.VPN_CONFIG_DOWNLOADED.value,
            description=f"VPN config downloaded by {current_user.username}",
            user_id=current_user.id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return config_file
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading VPN config for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/regenerate")
async def regenerate_vpn_config(
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Regenerate VPN configuration"""
    try:
        vpn_service = VPNService(db)
        config = await vpn_service.regenerate_user_config(current_user.id)
        
        # Log VPN config regeneration
        AuditLog.log_action(
            action=AuditAction.VPN_CONFIG_GENERATED.value,
            description=f"VPN config regenerated by {current_user.username}",
            user_id=current_user.id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return config
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error regenerating VPN config for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/status")
async def get_vpn_status(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get VPN connection status"""
    try:
        vpn_service = VPNService(db)
        status_info = await vpn_service.get_vpn_status(current_user.id)
        
        return status_info
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting VPN status for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/connect")
async def connect_vpn(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Report VPN connection (called by client)"""
    try:
        vpn_service = VPNService(db)
        await vpn_service.report_connection(client_id, request.client.host)
        
        return {"status": "connected"}
    
    except Exception as e:
        logger.error(f"Error reporting VPN connection for client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/disconnect")
async def disconnect_vpn(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Report VPN disconnection (called by client)"""
    try:
        vpn_service = VPNService(db)
        await vpn_service.report_disconnection(client_id)
        
        return {"status": "disconnected"}
    
    except Exception as e:
        logger.error(f"Error reporting VPN disconnection for client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
