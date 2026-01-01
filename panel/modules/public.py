"""
ApkayA Enterprise Control Panel - Core Public Module

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import sys
import json
import time
import hashlib
import random
import string
import socket
import platform
import subprocess
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union


class Public:
    """Core public utilities class - NO LICENSE CHECKS"""
    
    # All features enabled by default - No restrictions
    _features_enabled = True
    _version = "1.0.0"
    
    @staticmethod
    def get_panel_path() -> str:
        """Get the panel installation path"""
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    @staticmethod
    def get_data_path() -> str:
        """Get the data directory path"""
        return os.path.join(Public.get_panel_path(), 'data')
    
    @staticmethod
    def get_config_path() -> str:
        """Get the config directory path"""
        return os.path.join(Public.get_panel_path(), 'config')
    
    @staticmethod
    def get_logs_path() -> str:
        """Get the logs directory path"""
        return os.path.join(Public.get_panel_path(), 'logs')
    
    @staticmethod
    def read_file(filename: str, mode: str = 'r') -> Optional[str]:
        """Read file contents"""
        try:
            if not os.path.exists(filename):
                return None
            with open(filename, mode, encoding='utf-8') as f:
                return f.read()
        except Exception:
            return None
    
    @staticmethod
    def write_file(filename: str, content: str, mode: str = 'w') -> bool:
        """Write content to file"""
        try:
            dir_path = os.path.dirname(filename)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            with open(filename, mode, encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception:
            return False
    
    @staticmethod
    def read_json(filename: str) -> Optional[Dict]:
        """Read JSON file"""
        try:
            content = Public.read_file(filename)
            if content:
                return json.loads(content)
            return None
        except Exception:
            return None
    
    @staticmethod
    def write_json(filename: str, data: Any, indent: int = 2) -> bool:
        """Write data to JSON file"""
        try:
            content = json.dumps(data, indent=indent, ensure_ascii=False)
            return Public.write_file(filename, content)
        except Exception:
            return False
    
    @staticmethod
    def md5(text: str) -> str:
        """Calculate MD5 hash"""
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    
    @staticmethod
    def sha256(text: str) -> str:
        """Calculate SHA256 hash"""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    @staticmethod
    def generate_random_string(length: int = 32) -> str:
        """Generate random string"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def generate_password(length: int = 16) -> str:
        """Generate secure random password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
            random.choice("!@#$%^&*")
        ]
        password.extend(random.choice(chars) for _ in range(length - 4))
        random.shuffle(password)
        return ''.join(password)
    
    @staticmethod
    def get_timestamp() -> int:
        """Get current timestamp"""
        return int(time.time())
    
    @staticmethod
    def format_datetime(timestamp: Optional[int] = None, fmt: str = '%Y-%m-%d %H:%M:%S') -> str:
        """Format timestamp to datetime string"""
        if timestamp is None:
            timestamp = Public.get_timestamp()
        return datetime.fromtimestamp(timestamp).strftime(fmt)
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'
    
    @staticmethod
    def get_public_ip() -> str:
        """Get public IP address"""
        try:
            import requests
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            return response.json().get('ip', '')
        except Exception:
            return ''
    
    @staticmethod
    def get_hostname() -> str:
        """Get system hostname"""
        return socket.gethostname()
    
    @staticmethod
    def get_os_info() -> Dict[str, str]:
        """Get operating system information"""
        return {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        }
    
    @staticmethod
    def exec_shell(cmd: str, timeout: int = 60) -> tuple:
        """Execute shell command"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return (result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return ('', 'Command execution timeout')
        except Exception as e:
            return ('', str(e))
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate domain format"""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def is_valid_port(port: Union[int, str]) -> bool:
        """Validate port number"""
        try:
            port = int(port)
            return 1 <= port <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def sanitize_path(path: str) -> str:
        """Sanitize file path to prevent directory traversal"""
        # Remove dangerous patterns
        path = path.replace('..', '').replace('//', '/')
        path = re.sub(r'[<>:"|?*]', '', path)
        return path.strip()
    
    @staticmethod
    def get_size_format(size: int) -> str:
        """Format byte size to human readable"""
        units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
        index = 0
        while size >= 1024 and index < len(units) - 1:
            size /= 1024
            index += 1
        return f"{size:.2f} {units[index]}"
    
    @staticmethod
    def return_msg(status: bool, msg: str, data: Any = None) -> Dict:
        """Return standard message format"""
        result = {
            'status': status,
            'msg': msg
        }
        if data is not None:
            result['data'] = data
        return result
    
    @staticmethod
    def return_data(status: bool, data: Any = None, msg: str = '') -> Dict:
        """Return standard data format"""
        return {
            'status': status,
            'data': data,
            'msg': msg
        }
    
    # ========== FEATURE ACCESS - ALL ENABLED ==========
    # No license checks. All features are free.
    
    @staticmethod
    def is_pro() -> bool:
        """Check if pro features are enabled - ALWAYS TRUE (NO LICENSE)"""
        return True
    
    @staticmethod
    def is_enterprise() -> bool:
        """Check if enterprise features are enabled - ALWAYS TRUE (NO LICENSE)"""
        return True
    
    @staticmethod
    def check_feature(feature: str) -> bool:
        """Check if a feature is enabled - ALWAYS TRUE (NO LICENSE)"""
        return True
    
    @staticmethod
    def get_license_info() -> Dict:
        """Get license info - Returns open source status"""
        return {
            'status': True,
            'type': 'open_source',
            'name': 'MIT License',
            'features': 'all',
            'expiry': 'never',
            'msg': 'All features enabled - Open Source Edition'
        }
    
    @staticmethod
    def verify_license() -> bool:
        """Verify license - ALWAYS TRUE (NO LICENSE REQUIRED)"""
        return True


# Singleton instance
public = Public()


def get_panel_path() -> str:
    return Public.get_panel_path()

def get_data_path() -> str:
    return Public.get_data_path()

def read_file(filename: str, mode: str = 'r') -> Optional[str]:
    return Public.read_file(filename, mode)

def write_file(filename: str, content: str, mode: str = 'w') -> bool:
    return Public.write_file(filename, content, mode)

def read_json(filename: str) -> Optional[Dict]:
    return Public.read_json(filename)

def write_json(filename: str, data: Any, indent: int = 2) -> bool:
    return Public.write_json(filename, data, indent)

def md5(text: str) -> str:
    return Public.md5(text)

def exec_shell(cmd: str, timeout: int = 60) -> tuple:
    return Public.exec_shell(cmd, timeout)

def return_msg(status: bool, msg: str, data: Any = None) -> Dict:
    return Public.return_msg(status, msg, data)

def return_data(status: bool, data: Any = None, msg: str = '') -> Dict:
    return Public.return_data(status, data, msg)

def sanitize_path(path: str) -> str:
    """Sanitize file path to prevent directory traversal"""
    return Public.sanitize_path(path)

def is_pro() -> bool:
    """All Pro features enabled - No license required"""
    return True

def is_enterprise() -> bool:
    """All Enterprise features enabled - No license required"""
    return True

def check_feature(feature: str) -> bool:
    """All features enabled - No license required"""
    return True
