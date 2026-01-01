"""
Apkaya Panel WAF - Input Validation & Security Module
Handles all input validation and sanitization

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import re
import html
from urllib.parse import urlparse


class Validator:
    """Input validation and sanitization"""
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, str(email)))
    
    @staticmethod
    def validate_domain(domain):
        """Validate domain name format"""
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, str(domain)))
    
    @staticmethod
    def validate_ip(ip):
        """Validate IP address (IPv4)"""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, str(ip)))
    
    @staticmethod
    def validate_port(port):
        """Validate port number"""
        try:
            port_int = int(port)
            return 1 <= port_int <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_url(url):
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def sanitize_string(text, max_length=1000):
        """Sanitize string input"""
        if not isinstance(text, str):
            return ""
        # Remove null bytes
        text = text.replace('\x00', '')
        # HTML encode for safety
        text = html.escape(text)
        # Limit length
        return text[:max_length]
    
    @staticmethod
    def validate_filename(filename):
        """Validate filename (no path traversal)"""
        dangerous_chars = ['..', '/', '\\', '\x00', '\n', '\r']
        for char in dangerous_chars:
            if char in filename:
                return False
        return len(filename) > 0 and len(filename) <= 255
    
    @staticmethod
    def validate_path(path):
        """Validate file path (prevent traversal)"""
        # Normalize path
        path = str(path).replace('\\', '/')
        
        # Check for path traversal
        if '..' in path:
            return False
        
        # Check for null bytes
        if '\x00' in path:
            return False
        
        return True
    
    @staticmethod
    def validate_json_key(key):
        """Validate JSON object key"""
        return isinstance(key, str) and len(key) > 0 and len(key) <= 100
    
    @staticmethod
    def validate_password_strength(password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        score = sum([has_upper, has_lower, has_digit, has_special])
        
        if score < 3:
            return False, "Password must contain uppercase, lowercase, numbers, and special characters"
        
        return True, "Password is strong"
    
    @staticmethod
    def validate_database_name(name):
        """Validate database name"""
        pattern = r'^[a-zA-Z0-9_\-]+$'
        if not re.match(pattern, name):
            return False
        return 1 <= len(name) <= 64
    
    @staticmethod
    def validate_username(username):
        """Validate username"""
        pattern = r'^[a-zA-Z0-9_\-]{3,32}$'
        return bool(re.match(pattern, username))
