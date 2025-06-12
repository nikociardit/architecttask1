# routers/__init__.py
"""API routers module - all complete backend endpoints"""

# Import all routers to make them available
from . import auth
from . import users  
from . import clients
from . import tasks
from . import audit

__all__ = [
    "auth",
    "users", 
    "clients",
    "tasks",
    "audit"
]
