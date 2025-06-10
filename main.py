from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import logging
from pathlib import Path
import sys
import os

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config.database import engine, Base, get_db
from config.settings import settings

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("Starting Windows Endpoint Management System Backend")
    
    # Create database tables
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
    
    # Create default admin user if not exists
    try:
        # Simple admin creation function
        def create_default_admin():
            from models.user import User
            from config.security import security
            
            db = next(get_db())
            try:
                # Check if admin exists
                existing_admin = db.query(User).filter(User.username == "admin").first()
                if existing_admin:
                    logger.info("Default admin user already exists")
                    return
                
                # Create admin user
                admin_user = User(
                    username="admin",
                    email="admin@localhost", 
                    full_name="System Administrator",
                    role="admin",  # Direct string value
                    status="active",  # Direct string value
                    is_active=True,
                    vpn_enabled=True,
                    vpn_ip_address="10.0.0.1"
                )
                
                # Set password
                admin_user.password_hash = security.get_password_hash("ChangeMe123!")
                
                # Add to database
                db.add(admin_user)
                db.commit()
                
                logger.info("[OK] Default admin user created: admin / ChangeMe123!")
                
            except Exception as e:
                db.rollback()
                logger.error(f"[ERROR] Failed to create admin user: {e}")
            finally:
                db.close()
        
        create_default_admin()
        
    except Exception as e:
        logger.error(f"Failed to create default admin: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Windows Endpoint Management System Backend")

# Create FastAPI application
app = FastAPI(
    title="Windows Endpoint Management System",
    description="Backend API for managing Windows endpoints with VPN, RDP, and screen management",
    version="1.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup exception handlers
from utils.exceptions import setup_exception_handlers
setup_exception_handlers(app)

# Import and include routers after app creation
try:
    from routers import auth, users, clients, tasks, vpn, screen, audit
    
    app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
    app.include_router(users.router, prefix="/api/users", tags=["User Management"])
    app.include_router(clients.router, prefix="/api/clients", tags=["Client Management"])
    app.include_router(tasks.router, prefix="/api/tasks", tags=["Task Execution"])
    app.include_router(vpn.router, prefix="/api/vpn", tags=["VPN Management"])
    app.include_router(screen.router, prefix="/api/screen", tags=["Screen Management"])
    app.include_router(audit.router, prefix="/api/audit", tags=["Audit Logs"])
    
except Exception as e:
    logger.error(f"Failed to import routers: {e}")
    # Create minimal app without routers for debugging
    pass

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Windows Endpoint Management System Backend",
        "version": "1.1.0",
        "status": "running"
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.1.0",
        "timestamp": "2025-06-10"
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )
