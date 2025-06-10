from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import logging

from config.database import get_db
from services.auth_service import AuthService
from services.audit_service import AuditService

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

@router.get("/")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    action: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    client_id: Optional[int] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List audit logs with filtering"""
    try:
        if not current_user.has_permission("audit.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        audit_service = AuditService(db)
        result = await audit_service.list_audit_logs(
            page=page,
            per_page=per_page,
            action=action,
            user_id=user_id,
            client_id=client_id,
            start_date=start_date,
            end_date=end_date
        )
        
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing audit logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/export")
async def export_audit_logs(
    format: str = Query("csv", regex="^(csv|json)$"),
    action: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    client_id: Optional[int] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export audit logs"""
    try:
        if not current_user.has_permission("audit.export"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        audit_service = AuditService(db)
        file_response = await audit_service.export_audit_logs(
            format=format,
            action=action,
            user_id=user_id,
            client_id=client_id,
            start_date=start_date,
            end_date=end_date
        )
        
        return file_response
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting audit logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/stats")
async def get_audit_stats(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get audit statistics"""
    try:
        if not current_user.has_permission("audit.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        audit_service = AuditService(db)
        stats = await audit_service.get_audit_stats()
        
        return stats
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting audit stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
