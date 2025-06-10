from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging

logger = logging.getLogger(__name__)

class BaseCustomException(Exception):
    """Base custom exception"""
    def __init__(self, message: str, code: str = None):
        self.message = message
        self.code = code
        super().__init__(self.message)

class AuthenticationError(BaseCustomException):
    """Authentication related errors"""
    pass

class AuthorizationError(BaseCustomException):
    """Authorization related errors"""
    pass

class ValidationError(BaseCustomException):
    """Validation related errors"""
    pass

class NotFoundError(BaseCustomException):
    """Resource not found errors"""
    pass

class ConflictError(BaseCustomException):
    """Resource conflict errors"""
    pass

class PermissionError(BaseCustomException):
    """Permission related errors"""
    pass

class ClientError(BaseCustomException):
    """Client related errors"""
    pass

class TaskError(BaseCustomException):
    """Task execution related errors"""
    pass

class VPNError(BaseCustomException):
    """VPN related errors"""
    pass

class ScreenError(BaseCustomException):
    """Screen management related errors"""
    pass

def setup_exception_handlers(app: FastAPI):
    """Setup custom exception handlers"""
    
    @app.exception_handler(AuthenticationError)
    async def authentication_exception_handler(request: Request, exc: AuthenticationError):
        logger.warning(f"Authentication error: {exc.message} - {request.url}")
        return JSONResponse(
            status_code=401,
            content={
                "error": "authentication_error",
                "message": exc.message,
                "code": exc.code
            }
        )
    
    @app.exception_handler(AuthorizationError)
    async def authorization_exception_handler(request: Request, exc: AuthorizationError):
        logger.warning(f"Authorization error: {exc.message} - {request.url}")
        return JSONResponse(
            status_code=403,
            content={
                "error": "authorization_error",
                "message": exc.message,
                "code": exc.code
            }
        )
    
    @app.exception_handler(ValidationError)
    async def validation_exception_handler(request: Request, exc: ValidationError):
        logger.info(f"Validation error: {exc.message} - {request.url}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "validation_error",
                "message": exc.message,
                "code": exc.code
            }
        )
    
    @app.exception_handler(NotFoundError)
    async def not_found_exception_handler(request: Request, exc: NotFoundError):
        logger.info(f"Not found error: {exc.message} - {request.url}")
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found",
                "message": exc.message,
                "code": exc.code
            }
        )
    
    @app.exception_handler(ConflictError)
    async def conflict_exception_handler(request: Request, exc: ConflictError):
        logger.info(f"Conflict error: {exc.message} - {request.url}")
        return JSONResponse(
            status_code=409,
            content={
                "error": "conflict",
                "message": exc.message,
                "code": exc.code
            }
        )
    
    @app.exception_handler(PermissionError)
    async def permission_exception_handler(request: Request, exc: PermissionError):
        logger.warning(f"Permission error: {exc.message} - {request.url}")
        return JSONResponse(
            status_code=403,
            content={
                "error": "permission_denied",
                "message": exc.message,
                "code": exc.code
            }
        )
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger.info(f"Request validation error: {exc.errors()} - {request.url}")
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "message": "Request validation failed",
                "details": exc.errors()
            }
        )
    
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        logger.info(f"HTTP exception: {exc.status_code} {exc.detail} - {request.url}")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "http_error",
                "message": exc.detail
            }
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {str(exc)} - {request.url}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "message": "An internal server error occurred"
            }
        )
