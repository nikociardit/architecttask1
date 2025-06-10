from pydantic_settings import BaseSettings
from typing import List
import os
from pathlib import Path

class Settings(BaseSettings):
    # Application settings
    APP_NAME: str = "Windows Endpoint Management System"
    VERSION: str = "1.1.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Security settings
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Database settings
    DATABASE_URL: str = "sqlite:///./endpoint_management.db"
    
    # CORS settings
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://localhost:3000"
    ]
    
    # Active Directory settings
    AD_SERVER: str = ""
    AD_PORT: int = 636
    AD_USE_SSL: bool = True
    AD_BASE_DN: str = ""
    AD_BIND_USER: str = ""
    AD_BIND_PASSWORD: str = ""
    AD_USER_SEARCH_BASE: str = ""
    AD_GROUP_SEARCH_BASE: str = ""
    
    # VPN settings (WireGuard)
    VPN_SERVER_ENDPOINT: str = ""
    VPN_SERVER_PUBLIC_KEY: str = ""
    VPN_SERVER_PRIVATE_KEY: str = ""
    VPN_NETWORK: str = "10.0.0.0/24"
    VPN_PORT: int = 51820
    
    # Redis settings
    REDIS_URL: str = "redis://localhost:6379"
    
    # File storage settings
    UPLOAD_DIR: str = "uploads"
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    ALLOWED_EXTENSIONS: List[str] = [".exe", ".msi", ".zip", ".ps1", ".bat"]
    
    # Screen recording settings
    SCREEN_RECORDING_DIR: str = "recordings"
    MAX_RECORDING_SIZE: int = 1024 * 1024 * 1024  # 1GB
    RECORDING_RETENTION_DAYS: int = 30
    DEFAULT_RECORDING_QUALITY: str = "medium"  # low, medium, high
    
    # Audit settings
    AUDIT_LOG_RETENTION_DAYS: int = 365
    
    # Client settings
    CLIENT_HEARTBEAT_INTERVAL: int = 60  # seconds
    CLIENT_OFFLINE_THRESHOLD: int = 300  # seconds
    
    # Logging settings
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "app.log"
    LOG_MAX_SIZE: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5
    
    # Email settings (for notifications)
    SMTP_SERVER: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    
    # Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    LOGS_DIR: Path = BASE_DIR / "logs"
    
    class Config:
        env_file = ".env"
        case_sensitive = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Create directories if they don't exist
        self.DATA_DIR.mkdir(exist_ok=True)
        self.LOGS_DIR.mkdir(exist_ok=True)
        (self.BASE_DIR / self.UPLOAD_DIR).mkdir(exist_ok=True)
        (self.BASE_DIR / self.SCREEN_RECORDING_DIR).mkdir(exist_ok=True)

# Create global settings instance
settings = Settings()
