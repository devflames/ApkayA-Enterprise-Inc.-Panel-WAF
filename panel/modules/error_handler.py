"""
ApkayA Enterprise Control Panel - Error Handling Module
Comprehensive error handling and recovery

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import traceback
from typing import Dict, Any, Optional, Tuple
from datetime import datetime


class ErrorHandler:
    """Centralized error handling"""
    
    # Error Categories
    ERROR_TYPES = {
        'VALIDATION_ERROR': 400,
        'AUTHENTICATION_ERROR': 401,
        'AUTHORIZATION_ERROR': 403,
        'NOT_FOUND_ERROR': 404,
        'CONFLICT_ERROR': 409,
        'RATE_LIMIT_ERROR': 429,
        'SERVER_ERROR': 500,
        'SERVICE_UNAVAILABLE': 503,
        'DATABASE_ERROR': 500,
        'FILE_SYSTEM_ERROR': 500,
        'NETWORK_ERROR': 502,
        'TIMEOUT_ERROR': 504,
    }
    
    def __init__(self):
        """Initialize error handler"""
        self.error_log = []
        self.max_log_size = 1000
    
    @staticmethod
    def format_error(
        error_type: str,
        message: str,
        details: Optional[str] = None,
        status_code: Optional[int] = None
    ) -> Dict[str, Any]:
        """Format error response"""
        
        http_code = status_code or ErrorHandler.ERROR_TYPES.get(error_type, 500)
        
        return {
            'success': False,
            'error': {
                'type': error_type,
                'message': message,
                'details': details,
                'timestamp': datetime.now().isoformat(),
                'code': http_code
            }
        }
    
    def handle_validation_error(
        self,
        field: str,
        message: str
    ) -> Dict[str, Any]:
        """Handle validation errors"""
        return self.format_error(
            'VALIDATION_ERROR',
            f'Validation failed for field: {field}',
            message
        )
    
    def handle_not_found(
        self,
        resource_type: str,
        resource_id: str
    ) -> Dict[str, Any]:
        """Handle not found errors"""
        return self.format_error(
            'NOT_FOUND_ERROR',
            f'{resource_type} not found',
            f'Could not find {resource_type} with ID: {resource_id}'
        )
    
    def handle_database_error(
        self,
        operation: str,
        exception: Exception,
        query: Optional[str] = None
    ) -> Dict[str, Any]:
        """Handle database errors"""
        error_msg = str(exception)
        details = f"Operation: {operation}\nException: {error_msg}"
        
        if query:
            details += f"\nQuery: {query}"
        
        return self.format_error(
            'DATABASE_ERROR',
            'Database operation failed',
            details
        )
    
    def handle_file_error(
        self,
        operation: str,
        file_path: str,
        exception: Exception
    ) -> Dict[str, Any]:
        """Handle file system errors"""
        error_msg = str(exception)
        details = f"Operation: {operation}\nFile: {file_path}\nException: {error_msg}"
        
        return self.format_error(
            'FILE_SYSTEM_ERROR',
            'File operation failed',
            details
        )
    
    def handle_network_error(
        self,
        service: str,
        exception: Exception
    ) -> Dict[str, Any]:
        """Handle network errors"""
        error_msg = str(exception)
        details = f"Service: {service}\nException: {error_msg}"
        
        return self.format_error(
            'NETWORK_ERROR',
            f'Failed to connect to {service}',
            details
        )
    
    def handle_waf_error(
        self,
        operation: str,
        exception: Exception
    ) -> Dict[str, Any]:
        """Handle WAF errors"""
        error_msg = str(exception)
        details = f"WAF Operation: {operation}\nException: {error_msg}"
        
        return self.format_error(
            'SERVICE_UNAVAILABLE',
            'WAF service error',
            details
        )
    
    def handle_generic_error(
        self,
        exception: Exception,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """Handle generic errors"""
        error_msg = str(exception)
        error_type = type(exception).__name__
        
        details = f"Exception Type: {error_type}\nMessage: {error_msg}"
        if context:
            details += f"\nContext: {context}"
        
        # Log stack trace
        details += f"\nStack Trace:\n{traceback.format_exc()}"
        
        return self.format_error(
            'SERVER_ERROR',
            'An unexpected error occurred',
            details
        )
    
    def log_error(
        self,
        error_type: str,
        message: str,
        exception: Optional[Exception] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log error for monitoring"""
        error_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': error_type,
            'message': message,
            'exception': str(exception) if exception else None,
            'context': context or {}
        }
        
        self.error_log.append(error_entry)
        
        # Keep log size manageable
        if len(self.error_log) > self.max_log_size:
            self.error_log.pop(0)
    
    def get_error_log(self, limit: int = 100) -> list:
        """Get error log entries"""
        return self.error_log[-limit:]
    
    def get_errors_by_type(self, error_type: str, limit: int = 100) -> list:
        """Get errors filtered by type"""
        return [e for e in self.error_log[-limit:] if e['type'] == error_type]
    
    def clear_error_log(self) -> None:
        """Clear error log"""
        self.error_log = []
    
    @staticmethod
    def safe_operation(
        func,
        *args,
        fallback_value=None,
        **kwargs
    ) -> Tuple[bool, Any]:
        """Execute operation safely with error handling"""
        try:
            result = func(*args, **kwargs)
            return True, result
        except Exception as e:
            return False, fallback_value


# Global error handler instance
error_handler = ErrorHandler()
