from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
import logging
import sys
import os

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config.database import engine, Base, get_db
from config.settings import settings

# Setup logging (no unicode)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log", encoding='utf-8'),
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
        # Import all models first to register them with SQLAlchemy
        from models.user import User
        from models.client import Client
        from models.task import Task, TaskTemplate
        from models.audit import AuditLog
        from models.screen import ScreenRecording, ScreenSession, RecordingPolicy
        
        # Now create tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
    
    # Create default admin user (simplified)
    try:
        from models.user import User
        from config.security import security
        
        db = next(get_db())
        try:
            existing_admin = db.query(User).filter(User.username == "admin").first()
            if not existing_admin:
                admin_user = User(
                    username="admin",
                    email="admin@localhost", 
                    full_name="System Administrator",
                    role="admin",
                    status="active",
                    is_active=True
                )
                admin_user.password_hash = security.get_password_hash("ChangeMe123!")
                db.add(admin_user)
                db.commit()
                logger.info("Default admin user created: admin / ChangeMe123!")
            else:
                logger.info("Default admin user already exists")
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create admin user: {e}")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Admin creation error: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Windows Endpoint Management System Backend")

# Create FastAPI application
app = FastAPI(
    title="Windows Endpoint Management System",
    description="Backend API for managing Windows endpoints",
    version="1.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers with all complete APIs
try:
    from routers import auth, users, clients, tasks, audit
    
    app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
    app.include_router(users.router, prefix="/api/users", tags=["User Management"])
    app.include_router(clients.router, prefix="/api/clients", tags=["Client Management"])
    app.include_router(tasks.router, prefix="/api/tasks", tags=["Task Management"])
    app.include_router(audit.router, prefix="/api/audit", tags=["Audit Logs"])
    
    logger.info("All API routers loaded successfully")
    
except Exception as e:
    logger.error(f"Failed to import routers: {e}")
    # Continue without routers for debugging

# Basic routes
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Windows Endpoint Management System Backend",
        "version": "1.1.0",
        "status": "running",
        "endpoints": {
            "health": "/api/health",
            "docs": "/api/docs",
            "auth": "/api/auth",
            "users": "/api/users",
            "clients": "/api/clients"
        }
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.1.0",
        "timestamp": "2025-06-10",
        "database": "connected",
        "apis": ["auth", "users", "clients"]
    }

# Simple endpoint to test database connectivity
@app.get("/api/test-db")
async def test_database():
    """Test database connectivity"""
    try:
        from models.user import User
        db = next(get_db())
        user_count = db.query(User).count()
        db.close()
        return {
            "status": "success",
            "message": "Database connection successful",
            "user_count": user_count
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Database connection failed: {str(e)}"
        }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
