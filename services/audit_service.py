from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from fastapi.responses import Response
import logging
import csv
import json
import io

from models.audit import AuditLog, AuditAction, AuditSeverity
from models.user import User
from models.client import Client
from utils.exceptions import ValidationError, NotFoundError

logger = logging.getLogger(__name__)

class AuditService:
    """Audit log service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def list_audit_logs(
        self,
        page: int = 1,
        per_page: int = 50,
        action: Optional[str] = None,
        user_id: Optional[int] = None,
        client_id: Optional[int] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None
    ) -> Dict[str, Any]:
        """List audit logs with filtering and pagination"""
        
        query = self.db.query(AuditLog)
        
        # Apply filters
        if action:
            query = query.filter(AuditLog.action == action)
        
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        
        if client_id:
            query = query.filter(AuditLog.client_id == client_id)
        
        if severity:
            query = query.filter(AuditLog.severity == severity)
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    AuditLog.description.ilike(search_term),
                    AuditLog.action.ilike(search_term),
                    AuditLog.ip_address.ilike(search_term)
                )
            )
        
        # Order by timestamp (newest first)
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        audit_logs = query.offset(offset).limit(per_page).all()
        
        # Enrich logs with user and client information
        enriched_logs = []
        for log in audit_logs:
            log_dict = log.to_dict()
            
            # Add user information
            if log.user_id:
                user = self.db.query(User).filter(User.id == log.user_id).first()
                if user:
                    log_dict["user"] = {
                        "username": user.username,
                        "full_name": user.full_name,
                        "email": user.email
                    }
            
            # Add client information
            if log.client_id:
                client = self.db.query(Client).filter(Client.id == log.client_id).first()
                if client:
                    log_dict["client"] = {
                        "hostname": client.hostname,
                        "client_id": client.client_id,
                        "ip_address": client.ip_address
                    }
            
            enriched_logs.append(log_dict)
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        
        return {
            "audit_logs": enriched_logs,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages
        }
    
    async def get_audit_log(self, log_id: int) -> Optional[Dict[str, Any]]:
        """Get single audit log with details"""
        
        log = self.db.query(AuditLog).filter(AuditLog.id == log_id).first()
        if not log:
            return None
        
        log_dict = log.to_dict()
        
        # Add user information
        if log.user_id:
            user = self.db.query(User).filter(User.id == log.user_id).first()
            if user:
                log_dict["user"] = {
                    "id": user.id,
                    "username": user.username,
                    "full_name": user.full_name,
                    "email": user.email,
                    "role": user.role.value
                }
        
        # Add client information
        if log.client_id:
            client = self.db.query(Client).filter(Client.id == log.client_id).first()
            if client:
                log_dict["client"] = {
                    "id": client.id,
                    "hostname": client.hostname,
                    "client_id": client.client_id,
                    "ip_address": client.ip_address,
                    "domain": client.domain
                }
        
        return log_dict
    
    async def export_audit_logs(
        self,
        format: str = "csv",
        action: Optional[str] = None,
        user_id: Optional[int] = None,
        client_id: Optional[int] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        severity: Optional[str] = None
    ) -> Response:
        """Export audit logs to CSV or JSON"""
        
        # Get all matching logs (no pagination for export)
        query = self.db.query(AuditLog)
        
        # Apply same filters as list_audit_logs
        if action:
            query = query.filter(AuditLog.action == action)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if client_id:
            query = query.filter(AuditLog.client_id == client_id)
        if severity:
            query = query.filter(AuditLog.severity == severity)
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        query = query.order_by(AuditLog.timestamp.desc())
        audit_logs = query.all()
        
        if format == "csv":
            return await self._export_csv(audit_logs)
        elif format == "json":
            return await self._export_json(audit_logs)
        else:
            raise ValidationError("Unsupported export format")
    
    async def _export_csv(self, audit_logs: List[AuditLog]) -> Response:
        """Export audit logs as CSV"""
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Timestamp", "Action", "Severity", "Description",
            "User ID", "Username", "Client ID", "Hostname",
            "IP Address", "User Agent", "Response Status"
        ])
        
        # Write data
        for log in audit_logs:
            # Get user info
            username = ""
            if log.user_id:
                user = self.db.query(User).filter(User.id == log.user_id).first()
                if user:
                    username = user.username
            
            # Get client info
            hostname = ""
            if log.client_id:
                client = self.db.query(Client).filter(Client.id == log.client_id).first()
                if client:
                    hostname = client.hostname
            
            writer.writerow([
                log.timestamp.isoformat(),
                log.action,
                log.severity,
                log.description,
                log.user_id or "",
                username,
                log.client_id or "",
                hostname,
                log.ip_address or "",
                log.user_agent or "",
                log.response_status or ""
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        filename = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    
    async def _export_json(self, audit_logs: List[AuditLog]) -> Response:
        """Export audit logs as JSON"""
        
        logs_data = []
        for log in audit_logs:
            log_dict = log.to_dict()
            
            # Add user information
            if log.user_id:
                user = self.db.query(User).filter(User.id == log.user_id).first()
                if user:
                    log_dict["user"] = {
                        "username": user.username,
                        "full_name": user.full_name
                    }
            
            # Add client information
            if log.client_id:
                client = self.db.query(Client).filter(Client.id == log.client_id).first()
                if client:
                    log_dict["client"] = {
                        "hostname": client.hostname,
                        "client_id": client.client_id
                    }
            
            logs_data.append(log_dict)
        
        export_data = {
            "exported_at": datetime.utcnow().isoformat(),
            "total_records": len(logs_data),
            "audit_logs": logs_data
        }
        
        json_content = json.dumps(export_data, indent=2, default=str)
        filename = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        return Response(
            content=json_content,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    
    async def get_audit_stats(self) -> Dict[str, Any]:
        """Get audit statistics"""
        
        # Total logs
        total_logs = self.db.query(AuditLog).count()
        
        # Logs by severity
        info_logs = self.db.query(AuditLog).filter(
            AuditLog.severity == AuditSeverity.INFO.value
        ).count()
        
        warning_logs = self.db.query(AuditLog).filter(
            AuditLog.severity == AuditSeverity.WARNING.value
        ).count()
        
        error_logs = self.db.query(AuditLog).filter(
            AuditLog.severity == AuditSeverity.ERROR.value
        ).count()
        
        critical_logs = self.db.query(AuditLog).filter(
            AuditLog.severity == AuditSeverity.CRITICAL.value
        ).count()
        
        # Recent activity (last 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_logs = self.db.query(AuditLog).filter(
            AuditLog.timestamp >= yesterday
        ).count()
        
        # Top actions (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        top_actions = self.db.query(
            AuditLog.action,
            func.count(AuditLog.action).label('count')
        ).filter(
            AuditLog.timestamp >= week_ago
        ).group_by(
            AuditLog.action
        ).order_by(
            func.count(AuditLog.action).desc()
        ).limit(10).all()
        
        # Top users (last 7 days)
        top_users = self.db.query(
            AuditLog.user_id,
            func.count(AuditLog.user_id).label('count')
        ).filter(
            and_(
                AuditLog.timestamp >= week_ago,
                AuditLog.user_id.isnot(None)
            )
        ).group_by(
            AuditLog.user_id
        ).order_by(
            func.count(AuditLog.user_id).desc()
        ).limit(10).all()
        
        # Enrich top users with usernames
        top_users_enriched = []
        for user_id, count in top_users:
            user = self.db.query(User).filter(User.id == user_id).first()
            top_users_enriched.append({
                "user_id": user_id,
                "username": user.username if user else f"Unknown ({user_id})",
                "count": count
            })
        
        # Failed login attempts (last 24 hours)
        failed_logins = self.db.query(AuditLog).filter(
            and_(
                AuditLog.action == AuditAction.LOGIN_FAILED.value,
                AuditLog.timestamp >= yesterday
            )
        ).count()
        
        # Security events (last 7 days)
        security_events = self.db.query(AuditLog).filter(
            and_(
                AuditLog.timestamp >= week_ago,
                or_(
                    AuditLog.action == AuditAction.UNAUTHORIZED_ACCESS.value,
                    AuditLog.action == AuditAction.PERMISSION_DENIED.value,
                    AuditLog.action == AuditAction.SECURITY_VIOLATION.value,
                    AuditLog.action == AuditAction.LOGIN_FAILED.value
                )
            )
        ).count()
        
        return {
            "total_logs": total_logs,
            "logs_by_severity": {
                "info": info_logs,
                "warning": warning_logs,
                "error": error_logs,
                "critical": critical_logs
            },
            "recent_activity_24h": recent_logs,
            "top_actions_7d": [{"action": action, "count": count} for action, count in top_actions],
            "top_users_7d": top_users_enriched,
            "failed_logins_24h": failed_logins,
            "security_events_7d": security_events
        }
    
    async def get_user_activity(
        self, 
        user_id: int, 
        days: int = 7
    ) -> Dict[str, Any]:
        """Get activity summary for specific user"""
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # User's audit logs
        user_logs = self.db.query(AuditLog).filter(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.timestamp >= start_date
            )
        ).order_by(AuditLog.timestamp.desc()).all()
        
        # Activity by action
        action_counts = {}
        for log in user_logs:
            action_counts[log.action] = action_counts.get(log.action, 0) + 1
        
        # Activity by day
        daily_activity = {}
        for log in user_logs:
            day = log.timestamp.date().isoformat()
            daily_activity[day] = daily_activity.get(day, 0) + 1
        
        # Get user info
        user = self.db.query(User).filter(User.id == user_id).first()
        
        return {
            "user": {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name
            } if user else None,
            "period_days": days,
            "total_actions": len(user_logs),
            "actions_by_type": action_counts,
            "daily_activity": daily_activity,
            "recent_logs": [log.to_dict() for log in user_logs[:20]]  # Last 20 actions
        }
    
    async def get_client_activity(
        self, 
        client_id: int, 
        days: int = 7
    ) -> Dict[str, Any]:
        """Get activity summary for specific client"""
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Client's audit logs
        client_logs = self.db.query(AuditLog).filter(
            and_(
                AuditLog.client_id == client_id,
                AuditLog.timestamp >= start_date
            )
        ).order_by(AuditLog.timestamp.desc()).all()
        
        # Activity by action
        action_counts = {}
        for log in client_logs:
            action_counts[log.action] = action_counts.get(log.action, 0) + 1
        
        # Activity by day
        daily_activity = {}
        for log in client_logs:
            day = log.timestamp.date().isoformat()
            daily_activity[day] = daily_activity.get(day, 0) + 1
        
        # Get client info
        client = self.db.query(Client).filter(Client.id == client_id).first()
        
        return {
            "client": {
                "id": client.id,
                "hostname": client.hostname,
                "client_id": client.client_id,
                "ip_address": client.ip_address
            } if client else None,
            "period_days": days,
            "total_actions": len(client_logs),
            "actions_by_type": action_counts,
            "daily_activity": daily_activity,
            "recent_logs": [log.to_dict() for log in client_logs[:20]]  # Last 20 actions
        }
    
    async def search_logs(
        self, 
        search_term: str, 
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search audit logs by term"""
        
        search_pattern = f"%{search_term}%"
        
        logs = self.db.query(AuditLog).filter(
            or_(
                AuditLog.description.ilike(search_pattern),
                AuditLog.action.ilike(search_pattern),
                AuditLog.ip_address.ilike(search_pattern),
                AuditLog.user_agent.ilike(search_pattern)
            )
        ).order_by(
            AuditLog.timestamp.desc()
        ).limit(limit).all()
        
        return [log.to_dict() for log in logs]
    
    async def get_security_timeline(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get security-related events timeline"""
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        security_actions = [
            AuditAction.LOGIN_FAILED.value,
            AuditAction.UNAUTHORIZED_ACCESS.value,
            AuditAction.PERMISSION_DENIED.value,
            AuditAction.SECURITY_VIOLATION.value,
            AuditAction.PASSWORD_CHANGED.value,
            AuditAction.USER_DISABLED.value,
            AuditAction.USER_ENABLED.value
        ]
        
        security_logs = self.db.query(AuditLog).filter(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.action.in_(security_actions)
            )
        ).order_by(AuditLog.timestamp.desc()).all()
        
        timeline = []
        for log in security_logs:
            event = log.to_dict()
            
            # Add user info if available
            if log.user_id:
                user = self.db.query(User).filter(User.id == log.user_id).first()
                if user:
                    event["user"] = {
                        "username": user.username,
                        "full_name": user.full_name
                    }
            
            timeline.append(event)
        
        return timeline
    
    async def cleanup_old_logs(self, retention_days: int = 365) -> int:
        """Clean up old audit logs"""
        
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        old_logs = self.db.query(AuditLog).filter(
            AuditLog.timestamp < cutoff_date
        ).all()
        
        for log in old_logs:
            self.db.delete(log)
        
        self.db.commit()
        
        logger.info(f"Cleaned up {len(old_logs)} audit logs older than {retention_days} days")
        return len(old_logs)
    
    async def create_audit_report(
        self, 
        report_type: str = "summary",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Create comprehensive audit report"""
        
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        
        if not end_date:
            end_date = datetime.utcnow()
        
        # Base query for the period
        base_query = self.db.query(AuditLog).filter(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date
            )
        )
        
        total_events = base_query.count()
        
        # Events by severity
        severity_breakdown = {}
        for severity in [AuditSeverity.INFO, AuditSeverity.WARNING, AuditSeverity.ERROR, AuditSeverity.CRITICAL]:
            count = base_query.filter(AuditLog.severity == severity.value).count()
            severity_breakdown[severity.value] = count
        
        # Events by action
        action_breakdown = self.db.query(
            AuditLog.action,
            func.count(AuditLog.action).label('count')
        ).filter(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date
            )
        ).group_by(AuditLog.action).order_by(
            func.count(AuditLog.action).desc()
        ).all()
        
        # Most active users
        active_users = self.db.query(
            AuditLog.user_id,
            func.count(AuditLog.user_id).label('count')
        ).filter(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date,
                AuditLog.user_id.isnot(None)
            )
        ).group_by(AuditLog.user_id).order_by(
            func.count(AuditLog.user_id).desc()
        ).limit(10).all()
        
        # Enrich user data
        active_users_enriched = []
        for user_id, count in active_users:
            user = self.db.query(User).filter(User.id == user_id).first()
            active_users_enriched.append({
                "user_id": user_id,
                "username": user.username if user else f"Unknown ({user_id})",
                "full_name": user.full_name if user else "Unknown",
                "action_count": count
            })
        
        # Security incidents
        security_incidents = base_query.filter(
            or_(
                AuditLog.action == AuditAction.LOGIN_FAILED.value,
                AuditLog.action == AuditAction.UNAUTHORIZED_ACCESS.value,
                AuditLog.action == AuditAction.PERMISSION_DENIED.value,
                AuditLog.action == AuditAction.SECURITY_VIOLATION.value
            )
        ).count()
        
        # Failed login attempts by IP
        failed_login_ips = self.db.query(
            AuditLog.ip_address,
            func.count(AuditLog.ip_address).label('count')
        ).filter(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date,
                AuditLog.action == AuditAction.LOGIN_FAILED.value,
                AuditLog.ip_address.isnot(None)
            )
        ).group_by(AuditLog.ip_address).order_by(
            func.count(AuditLog.ip_address).desc()
        ).limit(10).all()
        
        report = {
            "report_type": report_type,
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": (end_date - start_date).days
            },
            "summary": {
                "total_events": total_events,
                "events_per_day": round(total_events / max((end_date - start_date).days, 1), 2),
                "security_incidents": security_incidents
            },
            "breakdown": {
                "by_severity": severity_breakdown,
                "by_action": [{"action": action, "count": count} for action, count in action_breakdown],
                "active_users": active_users_enriched,
                "failed_login_ips": [{"ip_address": ip, "attempts": count} for ip, count in failed_login_ips]
            },
            "generated_at": datetime.utcnow().isoformat()
        }
        
        return report
    
    @staticmethod
    async def log_action(
        action: str,
        description: str,
        db: Session,
        user_id: Optional[int] = None,
        client_id: Optional[int] = None,
        task_id: Optional[str] = None,
        severity: str = AuditSeverity.INFO.value,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs
    ) -> AuditLog:
        """Create audit log entry (static method for easy access)"""
        
        audit_log = AuditLog(
            action=action,
            description=description,
            severity=severity,
            user_id=user_id,
            client_id=client_id,
            task_id=task_id,
            metadata=metadata,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.utcnow(),
            **kwargs
        )
        
        try:
            db.add(audit_log)
            db.commit()
            db.refresh(audit_log)
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create audit log: {e}")
            # Could implement fallback logging here
        
        return audit_log
