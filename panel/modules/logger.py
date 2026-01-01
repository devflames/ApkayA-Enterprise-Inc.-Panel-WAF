"""
Apkaya Panel WAF - Logging & Audit Trail Module
Comprehensive logging for all operations and security events

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import json
import os
from datetime import datetime
from pathlib import Path


class Logger:
    """Centralized logging system for audit trail"""
    
    LOG_LEVELS = {
        'DEBUG': 0,
        'INFO': 1,
        'WARNING': 2,
        'ERROR': 3,
        'CRITICAL': 4
    }
    
    def __init__(self, log_dir='logs'):
        """Initialize logger"""
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Log files
        self.access_log = self.log_dir / 'access.log'
        self.error_log = self.log_dir / 'error.log'
        self.audit_log = self.log_dir / 'audit.log'
        self.system_log = self.log_dir / 'system.log'
    
    def _write_log(self, file_path, message, level='INFO', metadata=None):
        """Write log entry"""
        try:
            timestamp = datetime.now().isoformat()
            
            log_entry = {
                'timestamp': timestamp,
                'level': level,
                'message': message,
                'metadata': metadata or {}
            }
            
            # Append to log file
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            return True
        except Exception as e:
            print(f"Failed to write log: {e}")
            return False
    
    # Access Logging
    def log_access(self, method, path, status_code, response_time, user_ip=None):
        """Log API access"""
        metadata = {
            'method': method,
            'path': path,
            'status_code': status_code,
            'response_time_ms': response_time,
            'user_ip': user_ip
        }
        return self._write_log(
            self.access_log,
            f"{method} {path} - Status: {status_code}",
            'INFO',
            metadata
        )
    
    # System Events
    def log_system_event(self, event, details=None, level='INFO'):
        """Log system event"""
        return self._write_log(
            self.system_log,
            f"System Event: {event}",
            level,
            {'details': details}
        )
    
    # Database Operations
    def log_database_operation(self, operation, database, details=None):
        """Log database operation"""
        metadata = {
            'operation': operation,
            'database': database,
            'details': details
        }
        return self._write_log(
            self.audit_log,
            f"Database: {operation} on {database}",
            'INFO',
            metadata
        )
    
    # File Operations
    def log_file_operation(self, operation, file_path, details=None):
        """Log file operation"""
        metadata = {
            'operation': operation,
            'file_path': file_path,
            'details': details
        }
        return self._write_log(
            self.audit_log,
            f"File: {operation} on {file_path}",
            'INFO',
            metadata
        )
    
    # Website Operations
    def log_website_operation(self, operation, domain, details=None):
        """Log website operation"""
        metadata = {
            'operation': operation,
            'domain': domain,
            'details': details
        }
        return self._write_log(
            self.audit_log,
            f"Website: {operation} on {domain}",
            'INFO',
            metadata
        )
    
    # WAF Operations
    def log_waf_event(self, event_type, details, severity='INFO'):
        """Log WAF security event"""
        metadata = {
            'event_type': event_type,
            'details': details
        }
        return self._write_log(
            self.audit_log,
            f"WAF: {event_type}",
            severity,
            metadata
        )
    
    # Security Events
    def log_security_event(self, event, details, level='WARNING'):
        """Log security event"""
        metadata = {
            'event': event,
            'details': details
        }
        return self._write_log(
            self.audit_log,
            f"Security: {event}",
            level,
            metadata
        )
    
    # Error Logging
    def log_error(self, error_msg, exception=None, context=None):
        """Log error"""
        metadata = {
            'exception': str(exception) if exception else None,
            'context': context
        }
        return self._write_log(
            self.error_log,
            error_msg,
            'ERROR',
            metadata
        )
    
    # Get Logs
    def get_audit_logs(self, limit=100, filter_type=None):
        """Retrieve audit logs"""
        logs = []
        try:
            if not self.audit_log.exists():
                return logs
            
            with open(self.audit_log, 'r', encoding='utf-8') as f:
                for line in f.readlines()[-limit:]:
                    try:
                        log = json.loads(line)
                        if filter_type is None or log.get('message', '').startswith(filter_type):
                            logs.append(log)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        
        return logs
    
    def get_access_logs(self, limit=100, status_code=None):
        """Retrieve access logs"""
        logs = []
        try:
            if not self.access_log.exists():
                return logs
            
            with open(self.access_log, 'r', encoding='utf-8') as f:
                for line in f.readlines()[-limit:]:
                    try:
                        log = json.loads(line)
                        if status_code is None or log['metadata']['status_code'] == status_code:
                            logs.append(log)
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception:
            pass
        
        return logs
    
    def get_error_logs(self, limit=100):
        """Retrieve error logs"""
        logs = []
        try:
            if not self.error_log.exists():
                return logs
            
            with open(self.error_log, 'r', encoding='utf-8') as f:
                for line in f.readlines()[-limit:]:
                    try:
                        log = json.loads(line)
                        logs.append(log)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        
        return logs
    
    def clear_old_logs(self, days=30):
        """Clear logs older than specified days"""
        try:
            from datetime import timedelta
            cutoff = datetime.now() - timedelta(days=days)
            
            for log_file in [self.access_log, self.error_log, self.audit_log, self.system_log]:
                if not log_file.exists():
                    continue
                
                valid_logs = []
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            log = json.loads(line)
                            log_time = datetime.fromisoformat(log['timestamp'])
                            if log_time > cutoff:
                                valid_logs.append(line)
                        except (json.JSONDecodeError, ValueError):
                            valid_logs.append(line)
                
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.writelines(valid_logs)
            
            return True
        except Exception as e:
            print(f"Failed to clear old logs: {e}")
            return False


# Global logger instance
logger = Logger()
