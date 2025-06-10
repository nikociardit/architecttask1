#!/usr/bin/env python3
"""Minimal test to verify basic FastAPI setup works"""

def test_minimal():
    try:
        print("Testing FastAPI...")
        from fastapi import FastAPI
        print("✅ FastAPI imported")
        
        print("Testing Uvicorn...")
        import uvicorn
        print("✅ Uvicorn imported")
        
        print("Testing SQLAlchemy...")
        from sqlalchemy import create_engine
        print("✅ SQLAlchemy imported")
        
        print("Testing basic config...")
        from config.settings import settings
        print("✅ Settings imported")
        
        print("Creating minimal app...")
        app = FastAPI()
        
        @app.get("/")
        def root():
            return {"message": "Backend working!"}
        
        print("✅ Minimal app created successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("🔍 Testing minimal backend setup...")
    success = test_minimal()
    
    if success:
        print("\n🎉 Minimal setup works! You can now run:")
        print("uvicorn main:app --reload --host 0.0.0.0 --port 8000")
    else:
        print("\n❌ Setup failed. Check the errors above.")
