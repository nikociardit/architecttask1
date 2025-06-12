from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_
from typing import List, Optional
from datetime import datetime, timedelta
import logging
import csv
import io

from config.database import get_db
from models.audit import AuditLog, AuditAction, AuditSeverity
from routers.auth import get_current_user
from models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)

# Pydantic models
from pydantic import BaseModel

class AuditResponse(BaseModel):
    id: int
    action: str
    description: str
    severity: str
    user_id: Optional[int] = None
    client_id: Optional[int] = None
    task_id: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime

class AuditListResponse(BaseModel):
    logs: List[AuditResponse]
    total: int
    page: int
    per_page: int

def require_audit_access(current_user: User = Depends(get_current_user)):
    """Require audit access (admin or auditor)"""
    if current_user.role not in ["admin", "auditor"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit access required"
        )
    return current_user

@router.get("/", response_model=AuditListResponse)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    action: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    client_id: Optional[int] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    search: Optional[str] = Query(None),
    current_user: User = Depends(require_audit_access),
    db: Session = Depends(get_db)
):
    """List audit logs with filtering and pagination"""
    try:
        query = db.query(AuditLog)
        
        # Apply filters
        if action:
            query = query.filter(AuditLog.action == action)
        
        if severity:
            query = query.filter(AuditLog.severity == severity)
        
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        
        if client_id:
            query = query.filter(AuditLog.client_id == client_id)
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    AuditLog.action.ilike(search_term),
                    AuditLog.description.ilike(search_term),
                    AuditLog.ip_address.ilike(search_term)
                )
            )
        
        # Order by timestamp (newest first)
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        logs = query.offset(offset).limit(per_page).all()
        
        # Convert to response format
        log_responses = []
        for log in logs:
            log_responses.append(AuditResponse(
                id=log.id,
                action=log.action,
                description=log.description,
                severity=log.severity,
                user_id=log.user_id,
                client_id=log.client_id,
                task_id=log.task_id,
                ip_address=log.ip_address,
                timestamp=log.timestamp
            ))
        
        return AuditListResponse(
            logs=log_responses,
            total=total,
            page=page,
            per_page=per_page
        )
        
    except Exception as e:
        logger.error(f"Error listing audit logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/{log_id}")
async def get_audit_log(
    log_id: int,
    current_user: User = Depends(require_audit_access),
    db: Session = Depends(get_db)
):
    """Get audit log details by ID"""
    try:
        log = db.query(AuditLog).filter(AuditLog.id == log_id).first()
        if not log:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Audit log not found"
            )
        
        return {
            "id": log.id,
            "action": log.action,
            "description": log.description,
            "severity": log.severity,
            "user_id": log.user_id,
            "client_id": log.client_id,
            "task_id": log.task_id,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "request_method": log.request_method,
            "request_path": log.request_path,
            "response_status": log.response_status,
            "audit_data": log.audit_data,
            "timestamp": log.timestamp.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting audit log {log_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/actions/available")
async def get_available_actions(
    current_user: User = Depends(require_audit_access)
):
    """Get list of available audit actions for filtering"""
    return {
        "actions": [action.value for action in AuditAction],
        "severities": [severity.value for severity in AuditSeverity]
    }

@router.get("/stats/summary")
async def get_audit_stats(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(require_audit_access),
    db: Session = Depends(get_db)
):
    """Get audit statistics for the specified number of days"""
    try:
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Total logs in period
        total_logs = db.query(AuditLog).filter(
            AuditLog.timestamp >= start_date
        ).count()
        
        # Logs by severity
        severity_stats = {}
        for severity in AuditSeverity:
            count = db.query(AuditLog).filter(
                AuditLog.timestamp >= start_date,
                AuditLog.severity == severity.value
            ).count()
            severity_stats[severity.value] = count
        
        # Top actions
        top_actions = db.query(
            AuditLog.action,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.timestamp >= start_date
        ).group_by(
            AuditLog.action
        ).order_by(
            func.count(AuditLog.id).desc()
        ).limit(10).all()
        
        # Failed login attempts
        failed_logins = db.query(AuditLog).filter(
            AuditLog.timestamp >= start_date,
            AuditLog.action == "login_failed"
        ).count()
        
        # Unique users active
        active_users = db.query(func.count(func.distinct(AuditLog.user_id))).filter(
            AuditLog.timestamp >= start_date,
            AuditLog.user_id.isnot(None)
        ).scalar()
        
        # Daily activity (last 7 days)
        daily_activity = []
        for i in range(7):
            day_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
            day_end = day_start + timedelta(days=1)
            
            count = db.query(AuditLog).filter(
                AuditLog.timestamp >= day_start,
                AuditLog.timestamp < day_end
            ).count()
            
            daily_activity.append({
                "date": day_start.strftime("%Y-%m-%d"),
                "count": count
            })
        
        return {
            "period_days": days,
            "total_logs": total_logs,
            "severity_breakdown": severity_stats,
            "top_actions": [{"action": action, "count": count} for action, count in top_actions],
            "failed_logins": failed_logins,
            "active_users": active_users or 0,
            "daily_activity": list(reversed(daily_activity))
        }
        
    except Exception as e:
        logger.error(f"Error getting audit stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/export/csv")
async def export_audit_logs_csv(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    action: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    current_user: User = Depends(require_audit_access),
    db: Session = Depends(get_db)
):
    """Export audit logs to CSV"""
    try:
        query = db.query(AuditLog)
        
        # Apply filters
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        if action:
            query = query.filter(AuditLog.action == action)
        if severity:
            query = query.filter(AuditLog.severity == severity)
        
        # Order by timestamp
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Limit to prevent massive exports
        logs = query.limit(10000).all()
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'ID', 'Timestamp', 'Action', 'Description', 'Severity',
            'User ID', 'Client ID', 'Task ID', 'IP Address',
            'User Agent', 'Request Method', 'Request Path', 'Response Status'
        ])
        
        # Write data rows
        for log in logs:
            writer.writerow([
                log.id,
                log.timestamp.isoformat(),
                log.action,
                log.description,
                log.severity,
                log.user_id or '',
                log.client_id or '',
                log.task_id or '',
                log.ip_address or '',
                log.user_agent or '',
                log.request_method or '',
                log.request_path or '',
                log.response_status or ''
            ])
        
        # Get CSV content
        csv_content = output.getvalue()
        output.close()
        
        # Create filename with timestamp
        filename = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        # Return CSV response
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        logger.error(f"Error exporting audit logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/security/alerts")
async def get_security_alerts(
    hours: int = Query(24, ge=1, le=168),  # Last 1-168 hours
    current_user: User = Depends(require_audit_access),
    db: Session = Depends(get_db)
):
    """Get security-related alerts from audit logs"""
    try:
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Security-related actions to monitor
        security_actions = [
            "login_failed",
            "unauthorized_access", 
            "permission_denied",
            "security_violation"
        ]
        
        alerts = []
        
        # Failed login attempts (grouped by IP)
        failed_logins = db.query(
            AuditLog.ip_address,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.timestamp >= start_time,
            AuditLog.action == "login_failed",
            AuditLog.ip_address.isnot(None)
        ).group_by(
            AuditLog.ip_address
        ).having(
            func.count(AuditLog.id) >= 5  # 5+ failed attempts
        ).all()
        
        for ip, count in failed_logins:
            alerts.append({
                "type": "multiple_failed_logins",
                "severity": "warning" if count < 10 else "critical",
                "message": f"{count} failed login attempts from IP {ip}",
                "ip_address": ip,
                "count": count
            })
        
        # Recent security violations
        violations = db.query(AuditLog).filter(
            AuditLog.timestamp >= start_time,
            AuditLog.action.in_(["unauthorized_access", "permission_denied", "security_violation"])
        ).order_by(AuditLog.timestamp.desc()).limit(50).all()
        
        for violation in violations:
            alerts.append({
                "type": "security_violation",
                "severity": violation.severity,
                "message": violation.description,
                "timestamp": violation.timestamp.isoformat(),
                "action": violation.action,
                "ip_address": violation.ip_address
            })
        
        return {
            "period_hours": hours,
            "alert_count": len(alerts),
            "alerts": alerts
        }
        
    except Exception as e:
        logger.error(f"Error getting security alerts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
