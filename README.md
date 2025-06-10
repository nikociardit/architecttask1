# Windows Endpoint Management System - Backend

FastAPI-based backend for managing Windows endpoints with VPN, RDP, task execution, and screen management capabilities.

## Features

- **Authentication & Authorization**: JWT-based auth with RBAC (Admin, Technician, Auditor)
- **User Management**: Complete user lifecycle with Active Directory integration
- **Client Management**: Windows endpoint registration and monitoring
- **Task Execution**: Remote PowerShell, CMD, and executable execution
- **VPN Management**: WireGuard configuration and monitoring
- **Screen Management**: Live screen viewing, control, and recording
- **Audit Logging**: Comprehensive activity tracking
- **Real-time Monitoring**: WebSocket-based client heartbeat and status

## Architecture

### Database Models
- **User**: Authentication, roles, VPN config
- **Client**: Endpoint information and status
- **Task**: Remote command execution
- **AuditLog**: System activity tracking
- **ScreenRecording**: Screen capture management
- **ScreenSession**: Live screen sessions

### API Endpoints
- `/api/auth/*` - Authentication and authorization
- `/api/users/*` - User management
- `/api/clients/*` - Client management and heartbeat
- `/api/tasks/*` - Task creation and execution
- `/api/vpn/*` - VPN configuration management
- `/api/screen/*` - Screen management and recording
- `/api/audit/*` - Audit log access

## Setup

### Prerequisites
- Python 3.11+
- Redis (for background tasks)
- SQLite (default) or PostgreSQL

### Installation

1. **Clone and setup**:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Configure environment**:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Initialize database**:
```bash
python -c "from config.database import init_db; init_db()"
```

4. **Run the application**:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Docker Setup

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t endpoint-backend .
docker run -p 8000:8000 endpoint-backend
```

## Configuration

### Required Environment Variables

```bash
# Security (REQUIRED)
SECRET_KEY=your-secret-key-change-in-production

# VPN Configuration (if using VPN features)
VPN_SERVER_ENDPOINT=your-server-ip
VPN_SERVER_PUBLIC_KEY=your-wireguard-public-key
VPN_SERVER_PRIVATE_KEY=your-wireguard-private-key
```

### Optional Configuration

- **Active Directory**: Configure AD_* variables for user sync
- **Email**: Configure SMTP_* variables for notifications
- **Redis**: For background task processing
- **Database**: Switch from SQLite to PostgreSQL for production

## Default Credentials

On first startup, a default admin user is created:
- **Username**: `admin`
- **Password**: `ChangeMe123!`
- **Role**: Admin

**⚠️ Change this password immediately after first login!**

## API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc

## Security Features

- **JWT Authentication**: Secure token-based authentication
- **Role-Based Access Control**: Granular permission system
- **Password Policies**: Enforced password complexity
- **MFA Support**: Time-based one-time passwords
- **Audit Logging**: All actions tracked and logged
- **Input Validation**: Comprehensive request validation
- **Rate Limiting**: Protection against abuse

## VPN Integration

The system generates WireGuard configurations for users:
- Automatic key generation
- Static IP assignment
- Per-user configuration
- Connection monitoring

## Screen Management

- **Live Sessions**: Real-time screen viewing and control
- **Recording**: Scheduled and on-demand screen recording
- **Encryption**: All recordings encrypted at rest
- **Access Control**: Role-based access to recordings

## Monitoring & Health

- **Health Check**: `/api/health`
- **Metrics**: Basic system statistics
- **Client Status**: Real-time endpoint monitoring
- **Audit Trail**: Complete activity logging

## Development

### Code Structure
```
backend/
├── main.py                 # FastAPI application
├── config/                 # Configuration management
├── models/                 # SQLAlchemy database models
├── schemas/                # Pydantic request/response schemas
├── routers/                # FastAPI route handlers
├── services/               # Business logic
└── utils/                  # Utility functions
```

### Adding New Features

1. **Database**: Add models in `models/`
2. **Schemas**: Define request/response in `schemas/`
3. **Service**: Implement business logic in `services/`
4. **Router**: Add API endpoints in `routers/`
5. **Tests**: Add tests (when test framework is added)

## Production Deployment

### Security Checklist
- [ ] Change default admin password
- [ ] Generate secure SECRET_KEY
- [ ] Configure HTTPS/TLS
- [ ] Set up proper database (PostgreSQL)
- [ ] Configure Redis for production
- [ ] Set up monitoring and logging
- [ ] Configure firewall rules
- [ ] Set up backup procedures

### Performance Optimization
- Use PostgreSQL instead of SQLite
- Configure Redis for caching
- Set up reverse proxy (nginx)
- Enable gzip compression
- Configure proper logging levels

## License

Enterprise software - see company licensing terms.
