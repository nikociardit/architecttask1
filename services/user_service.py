from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import logging
import ipaddress

from models.user import User, UserRole, UserStatus
from schemas.user import UserCreate, UserUpdate, UserProfileUpdate
from config.security import security
from config.settings import settings
from utils.exceptions import ValidationError, NotFoundError

logger = logging.getLogger(__name__)

class UserService:
    """User management service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def create_user(self, user_data: UserCreate, created_by: int) -> User:
        """Create new user"""
        
        # Check if username already exists
        existing_user = self.db.query(User).filter(
            User.username == user_data.username.lower()
        ).first()
        if existing_user:
            raise ValidationError("Username already exists")
        
        # Check if email already exists
        existing_email = self.db.query(User).filter(
            User.email == user_data.email
        ).first()
        if existing_email:
            raise ValidationError("Email already exists")
        
        # Validate password strength
        is_strong, message = security.validate_password_strength(user_data.password)
        if not is_strong:
            raise ValidationError(message)
        
        # Generate VPN configuration if enabled
        vpn_private_key = None
        vpn_public_key = None
        vpn_ip = None
        
        if user_data.role in [UserRole.ADMIN, UserRole.TECHNICIAN]:
            vpn_private_key, vpn_public_key = security.generate_vpn_keys()
            vpn_ip = await self._allocate_vpn_ip()
        
        # Create user
        user = User(
            username=user_data.username.lower(),
            email=user_data.email,
            full_name=user_data.full_name,
            hashed_password=security.get_password_hash(user_data.password),
            role=user_data.role,
            phone=user_data.phone,
            department=user_data.department,
            job_title=user_data.job_title,
            manager_id=user_data.manager_id,
            expires_at=user_data.expires_at,
            vpn_enabled=bool(vpn_private_key),
            vpn_private_key=vpn_private_key,
            vpn_public_key=vpn_public_key,
            vpn_ip_address=vpn_ip,
            status=UserStatus.ACTIVE,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        
        logger.info(f"User {user.username} created by user {created_by}")
        return user
    
    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        return self.db.query(User).filter(User.id == user_id).first()
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        return self.db.query(User).filter(
            User.username == username.lower()
        ).first()
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        return self.db.query(User).filter(User.email == email).first()
    
    async def list_users(
        self,
        page: int = 1,
        per_page: int = 50,
        search: Optional[str] = None,
        role: Optional[UserRole] = None,
        status: Optional[str] = None
    ) -> Dict[str, Any]:
        """List users with pagination and filtering"""
        
        query = self.db.query(User)
        
        # Apply search filter
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                and_(
                    User.username.ilike(search_term) |
                    User.email.ilike(search_term) |
                    User.full_name.ilike(search_term)
                )
            )
        
        # Apply role filter
        if role:
            query = query.filter(User.role == role)
        
        # Apply status filter
        if status:
            if status == "active":
                query = query.filter(User.status == UserStatus.ACTIVE)
            elif status == "inactive":
                query = query.filter(User.status == UserStatus.INACTIVE)
            elif status == "disabled":
                query = query.filter(User.status == UserStatus.DISABLED)
            elif status == "expired":
                query = query.filter(User.status == UserStatus.EXPIRED)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * per_page
        users = query.offset(offset).limit(per_page).all()
        
        # Calculate pagination info
        pages = (total + per_page - 1) // per_page
        
        return {
            "users": users,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages
        }
    
    async def update_user(
        self, 
        user_id: int, 
        user_data: UserUpdate, 
        updated_by: int
    ) -> User:
        """Update user"""
        
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Update fields
        if user_data.email is not None:
            # Check if email already exists
            existing_email = self.db.query(User).filter(
                and_(User.email == user_data.email, User.id != user_id)
            ).first()
            if existing_email:
                raise ValidationError("Email already exists")
            user.email = user_data.email
        
        if user_data.full_name is not None:
            user.full_name = user_data.full_name
        
        if user_data.role is not None:
            user.role = user_data.role
            # Update VPN access based on role
            if user_data.role in [UserRole.ADMIN, UserRole.TECHNICIAN]:
                if not user.vpn_enabled:
                    await self._enable_vpn_for_user(user)
            else:
                user.vpn_enabled = False
        
        if user_data.status is not None:
            user.status = user_data.status
        
        if user_data.phone is not None:
            user.phone = user_data.phone
        
        if user_data.department is not None:
            user.department = user_data.department
        
        if user_data.job_title is not None:
            user.job_title = user_data.job_title
        
        if user_data.manager_id is not None:
            user.manager_id = user_data.manager_id
        
        if user_data.expires_at is not None:
            user.expires_at = user_data.expires_at
        
        if user_data.vpn_enabled is not None:
            if user_data.vpn_enabled and not user.vpn_enabled:
                await self._enable_vpn_for_user(user)
            elif not user_data.vpn_enabled:
                user.vpn_enabled = False
        
        if user_data.permissions is not None:
            import json
            user.permissions = json.dumps(user_data.permissions)
        
        user.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(user)
        
        logger.info(f"User {user.username} updated by user {updated_by}")
        return user
    
    async def delete_user(self, user_id: int) -> bool:
        """Delete user"""
        
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Soft delete - disable instead of actual deletion
        user.status = UserStatus.DISABLED
        user.is_active = False
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        logger.info(f"User {user.username} deleted (disabled)")
        return True
    
    async def disable_user(self, user_id: int) -> User:
        """Disable user account"""
        
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        user.status = UserStatus.DISABLED
        user.is_active = False
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(user)
        
        return user
    
    async def enable_user(self, user_id: int) -> User:
        """Enable user account"""
        
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        user.status = UserStatus.ACTIVE
        user.is_active = True
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(user)
        
        return user
    
    async def get_user_vpn_config(self, user_id: int) -> Dict[str, Any]:
        """Get user VPN configuration"""
        
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        if not user.vpn_enabled or not user.vpn_private_key:
            raise ValidationError("VPN not enabled for this user")
        
        return {
            "config": user.get_vpn_config(),
            "private_key": user.vpn_private_key,
            "public_key": user.vpn_public_key,
            "ip_address": user.vpn_ip_address,
            "server_endpoint": f"{settings.VPN_SERVER_ENDPOINT}:{settings.VPN_PORT}"
        }
    
    async def regenerate_vpn_config(self, user_id: int) -> Dict[str, Any]:
        """Regenerate VPN configuration for user"""
        
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Generate new keys
        private_key, public_key = security.generate_vpn_keys()
        
        user.vpn_private_key = private_key
        user.vpn_public_key = public_key
        user.vpn_enabled = True
        user.updated_at = datetime.utcnow()
        
        # Allocate new IP if needed
        if not user.vpn_ip_address:
            user.vpn_ip_address = await self._allocate_vpn_ip()
        
        self.db.commit()
        self.db.refresh(user)
        
        return await self.get_user_vpn_config(user_id)
    
    async def update_user_profile(
        self, 
        user_id: int, 
        profile_data: UserProfileUpdate
    ) -> User:
        """Update user profile (self-service)"""
        
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        if profile_data.full_name is not None:
            user.full_name = profile_data.full_name
        
        if profile_data.phone is not None:
            user.phone = profile_data.phone
        
        user.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(user)
        
        return user
    
    async def get_user_stats(self) -> Dict[str, Any]:
        """Get user statistics"""
        
        total_users = self.db.query(User).count()
        active_users = self.db.query(User).filter(User.status == UserStatus.ACTIVE).count()
        inactive_users = self.db.query(User).filter(User.status == UserStatus.INACTIVE).count()
        
        admin_users = self.db.query(User).filter(User.role == UserRole.ADMIN).count()
        technician_users = self.db.query(User).filter(User.role == UserRole.TECHNICIAN).count()
        auditor_users = self.db.query(User).filter(User.role == UserRole.AUDITOR).count()
        
        vpn_enabled_users = self.db.query(User).filter(User.vpn_enabled == True).count()
        mfa_enabled_users = self.db.query(User).filter(User.mfa_enabled == True).count()
        ad_synced_users = self.db.query(User).filter(User.ad_sync_enabled == True).count()
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "admin_users": admin_users,
            "technician_users": technician_users,
            "auditor_users": auditor_users,
            "vpn_enabled_users": vpn_enabled_users,
            "mfa_enabled_users": mfa_enabled_users,
            "ad_synced_users": ad_synced_users
        }
    
    async def _enable_vpn_for_user(self, user: User):
        """Enable VPN for user"""
        if not user.vpn_private_key:
            private_key, public_key = security.generate_vpn_keys()
            user.vpn_private_key = private_key
            user.vpn_public_key = public_key
        
        if not user.vpn_ip_address:
            user.vpn_ip_address = await self._allocate_vpn_ip()
        
        user.vpn_enabled = True
    
    async def _allocate_vpn_ip(self) -> str:
        """Allocate next available VPN IP address"""
        
        # Get network from settings
        network = ipaddress.IPv4Network(settings.VPN_NETWORK)
        
        # Get all allocated IPs
        allocated_ips = set()
        users_with_ips = self.db.query(User.vpn_ip_address).filter(
            User.vpn_ip_address.isnot(None)
        ).all()
        
        for (ip,) in users_with_ips:
            if ip:
                allocated_ips.add(ip)
        
        # Find next available IP
        for ip in network.hosts():
            if str(ip) not in allocated_ips:
                return str(ip)
        
        raise ValidationError("No available VPN IP addresses")

async def create_default_admin():
    """Create default admin user if none exists"""
    from config.database import get_db_session
    
    db = get_db_session()
    try:
        # Check if any admin user exists
        admin_exists = db.query(User).filter(User.role == UserRole.ADMIN).first()
        
        if not admin_exists:
            # Create default admin
            private_key, public_key = security.generate_vpn_keys()
            
            admin_user = User(
                username="admin",
                email="admin@company.com",
                full_name="System Administrator",
                hashed_password=security.get_password_hash("ChangeMe123!"),
                role=UserRole.ADMIN,
                status=UserStatus.ACTIVE,
                is_active=True,
                vpn_enabled=True,
                vpn_private_key=private_key,
                vpn_public_key=public_key,
                vpn_ip_address="10.0.0.2",  # First available IP
                created_at=datetime.utcnow()
            )
            
            db.add(admin_user)
            db.commit()
            
            logger.info("Default admin user created - username: admin, password: ChangeMe123!")
    
    except Exception as e:
        logger.error(f"Failed to create default admin user: {e}")
        db.rollback()
    finally:
        db.close()
