from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from config.database import get_db
from schemas.client import (
    ClientRegister, ClientUpdate, ClientHeartbeat, ClientResponse,
    ClientDetailResponse, ClientListResponse, ClientStatsResponse,
    ClientConfigResponse, ClientTaskPoll, ClientRDPCredentials
)
from services.auth_service import AuthService
from services.client_service import ClientService
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

@router.get("/", response_model=ClientListResponse)
async def list_clients(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    search: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List clients with pagination and filtering"""
    try:
        if not current_user.has_permission("client.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        client_service = ClientService(db)
        result = await client_service.list_clients(
            page=page,
            per_page=per_page,
            search=search,
            status=status
        )
        
        return ClientListResponse(**result)
    
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
        client_service = ClientService(db)
        client = await client_service.register_client(
            client_data,
            ip_address=request.client.host
        )
        
        # Log client registration
        AuditLog.log_action(
            action=AuditAction.CLIENT_REGISTERED.value,
            description=f"Client {client.hostname} registered from {request.client.host}",
            client_id=client.id,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return ClientResponse.from_orm(client)
    
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
        client_service = ClientService(db)
        await client_service.process_heartbeat(client_id, heartbeat_data)
        
        return {"status": "ok", "timestamp": "2025-06-10T12:00:00Z"}
    
    except Exception as e:
        logger.error(f"Error processing heartbeat for {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/{client_id}", response_model=ClientDetailResponse)
async def get_client(
    client_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get client details by ID"""
    try:
        if not current_user.has_permission("client.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        client_service = ClientService(db)
        client = await client_service.get_client_by_id(client_id)
        
        if not client:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Client not found"
            )
        
        return ClientDetailResponse.from_orm(client)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/stats", response_model=ClientStatsResponse)
async def get_client_stats(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get client statistics"""
    try:
        if not current_user.has_permission("client.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        client_service = ClientService(db)
        stats = await client_service.get_client_stats()
        
        return ClientStatsResponse(**stats)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting client stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/{client_id}/config", response_model=ClientConfigResponse)
async def get_client_config(
    client_id: str,
    db: Session = Depends(get_db)
):
    """Get client configuration (called by client software)"""
    try:
        client_service = ClientService(db)
        config = await client_service.get_client_config(client_id)
        
        return ClientConfigResponse(**config)
    
    except Exception as e:
        logger.error(f"Error getting config for client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/{client_id}/tasks", response_model=ClientTaskPoll)
async def poll_tasks(
    client_id: str,
    db: Session = Depends(get_db)
):
    """Poll for pending tasks (called by client software)"""
    try:
        client_service = ClientService(db)
        tasks = await client_service.get_pending_tasks(client_id)
        
        return ClientTaskPoll(tasks=tasks)
    
    except Exception as e:
        logger.error(f"Error polling tasks for client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/{client_id}/rdp-credentials", response_model=ClientRDPCredentials)
async def get_rdp_credentials(
    client_id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get RDP credentials for client"""
    try:
        if not current_user.has_permission("client.manage"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        client_service = ClientService(db)
        credentials = await client_service.get_rdp_credentials(client_id)
        
        return ClientRDPCredentials(**credentials)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting RDP credentials for client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
