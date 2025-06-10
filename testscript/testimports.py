#!/usr/bin/env python3
"""Test script to verify all imports work correctly"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test all module imports"""
    
    try:
        print("Testing config imports...")
        from config.database import Base, engine, get_db
        from config.settings import settings
        from config.security import security
        print("✅ Config imports successful")
    except Exception as e:
        print(f"❌ Config imports failed: {e}")
        return False
    
    try:
        print("Testing model imports...")
        from models.user import User, UserRole, UserStatus
        from models.client import Client, ClientStatus, ClientType
        from models.task import Task, TaskTemplate, TaskType, TaskStatus, TaskPriority
        from models.audit import AuditLog, AuditAction, AuditSeverity
        from models.screen import ScreenRecording, ScreenSession, RecordingPolicy
        print("✅ Model imports successful")
    except Exception as e:
        print(f"❌ Model imports failed: {e}")
        return False
    
    try:
        print("Testing schema imports...")
        from schemas.auth import LoginRequest, LoginResponse
        from schemas.user import UserCreate, UserResponse
        from schemas.client import ClientRegister, ClientResponse
        from schemas.task import TaskCreate, TaskResponse
        from schemas.screen import ScreenSessionCreate, ScreenRecordingCreate
        print("✅ Schema imports successful")
    except Exception as e:
        print(f"❌ Schema imports failed: {e}")
        return False
    
    try:
        print("Testing service imports...")
        from services.auth_service import AuthService
        from services.user_service import UserService
        from services.client_service import ClientService
        from services.task_service import TaskService
        from services.vpn_service import VPNService
        from services.screen_service import ScreenService
        from services.audit_service import AuditService
        print("✅ Service imports successful")
    except Exception as e:
        print(f"❌ Service imports failed: {e}")
        return False
    
    try:
        print("Testing database creation...")
        Base.metadata.create_all(bind=engine)
        print("✅ Database creation successful")
    except Exception as e:
        print(f"❌ Database creation failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🔍 Testing backend imports and setup...")
    success = test_imports()
    
    if success:
        print("\n🎉 All tests passed! Backend is ready to run.")
        print("\nTo start the server, run:")
        print("uvicorn main:app --reload --host 0.0.0.0 --port 8000")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
    
    sys.exit(0 if success else 1)
