"""
ApkayA Enterprise Control Panel - API Security Module
Rate limiting, API key management, and request signing

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import json
import hashlib
import hmac
import secrets
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple, Optional
from functools import wraps
from flask import request, jsonify
from collections import defaultdict


class RateLimitStore:
    """Thread-safe in-memory rate limit tracking"""
    
    def __init__(self):
        self._store = defaultdict(lambda: {'count': 0, 'window_start': 0})
        self._lock = threading.Lock()
    
    def check_and_increment(self, key: str, limit: int, window_seconds: int = 60) -> Tuple[bool, int]:
        """
        Check if request is within rate limit and increment counter.
        Returns (is_allowed, remaining_requests)
        """
        current_time = int(time.time())
        
        with self._lock:
            entry = self._store[key]
            
            # Check if we need to reset the window
            if current_time - entry['window_start'] >= window_seconds:
                entry['count'] = 0
                entry['window_start'] = current_time
            
            # Check limit
            if entry['count'] >= limit:
                remaining = 0
                allowed = False
            else:
                entry['count'] += 1
                remaining = max(0, limit - entry['count'])
                allowed = True
            
            return allowed, remaining
    
    def get_reset_time(self, key: str, window_seconds: int = 60) -> int:
        """Get the time when the rate limit window resets"""
        with self._lock:
            entry = self._store[key]
            return entry['window_start'] + window_seconds
    
    def cleanup_old_entries(self, max_age_seconds: int = 3600):
        """Remove entries older than max_age_seconds"""
        current_time = int(time.time())
        with self._lock:
            keys_to_remove = [
                key for key, entry in self._store.items()
                if current_time - entry['window_start'] > max_age_seconds
            ]
            for key in keys_to_remove:
                del self._store[key]


# Global rate limit store
_rate_limit_store = RateLimitStore()


class APISecurityManager:
    """Manage API keys, rate limiting, and request signing"""
    
    def __init__(self, db_file='data/api_keys.json', config_file='data/api_config.json'):
        """Initialize API security manager"""
        self.db_file = Path(db_file)
        self.config_file = Path(config_file)
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize databases
        if not self.db_file.exists():
            self._write_keys({})
        if not self.config_file.exists():
            self._write_config(self._default_config())
        
        # Load config
        self.config = self._read_config()
    
    # ===== Configuration =====
    
    @staticmethod
    def _default_config() -> dict:
        """Default API security configuration"""
        return {
            'rate_limits': {
                'admin': {'requests_per_minute': 1000, 'requests_per_hour': 100000},
                'operator': {'requests_per_minute': 500, 'requests_per_hour': 50000},
                'user': {'requests_per_minute': 100, 'requests_per_hour': 10000},
                'guest': {'requests_per_minute': 10, 'requests_per_hour': 1000}
            },
            'api_key_expiry_days': 90,
            'require_api_signing': True,
            'require_https': False,  # Set to true in production
            'allowed_ips': [],  # Empty = allow all
            'blocked_ips': [],
            'rate_limit_reset_window': 60,  # seconds
            'api_version': '1.0'
        }
    
    # ===== API Key Management =====
    
    def create_api_key(self, user_id: str, name: str, permissions: list = None, 
                      expires_in_days: int = None) -> dict:
        """Create new API key for user"""
        
        if expires_in_days is None:
            expires_in_days = self.config['api_key_expiry_days']
        
        # Generate key and secret
        api_key = f"apk_{secrets.token_urlsafe(32)}"
        api_secret = secrets.token_urlsafe(64)
        
        # Hash secret for storage
        secret_hash = hashlib.sha256(api_secret.encode()).hexdigest()
        
        keys = self._read_keys()
        
        key_data = {
            'api_key': api_key,
            'secret_hash': secret_hash,
            'user_id': user_id,
            'name': name,
            'permissions': permissions or [],
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=expires_in_days)).isoformat(),
            'last_used': None,
            'request_count': 0,
            'enabled': True
        }
        
        keys[api_key] = key_data
        self._write_keys(keys)
        
        return {
            'success': True,
            'api_key': api_key,
            'api_secret': api_secret,
            'message': 'API key created. Save secret in secure location!',
            'expires_at': key_data['expires_at']
        }
    
    def revoke_api_key(self, api_key: str) -> dict:
        """Revoke API key"""
        keys = self._read_keys()
        
        if api_key not in keys:
            return {'success': False, 'message': 'API key not found'}
        
        keys[api_key]['enabled'] = False
        keys[api_key]['revoked_at'] = datetime.now().isoformat()
        self._write_keys(keys)
        
        return {'success': True, 'message': 'API key revoked'}
    
    def regenerate_api_key(self, api_key: str) -> dict:
        """Regenerate API secret for key"""
        keys = self._read_keys()
        
        if api_key not in keys:
            return {'success': False, 'message': 'API key not found'}
        
        # Generate new secret
        api_secret = secrets.token_urlsafe(64)
        secret_hash = hashlib.sha256(api_secret.encode()).hexdigest()
        
        keys[api_key]['secret_hash'] = secret_hash
        keys[api_key]['updated_at'] = datetime.now().isoformat()
        self._write_keys(keys)
        
        return {
            'success': True,
            'api_secret': api_secret,
            'message': 'API secret regenerated'
        }
    
    def list_api_keys(self, user_id: str) -> dict:
        """List all API keys for user (without secrets)"""
        keys = self._read_keys()
        user_keys = []
        
        for api_key, key_data in keys.items():
            if key_data['user_id'] == user_id:
                # Don't return secret hash
                key_info = key_data.copy()
                del key_info['secret_hash']
                key_info['api_key'] = api_key
                user_keys.append(key_info)
        
        return {'success': True, 'keys': user_keys}
    
    def get_api_key_info(self, api_key: str) -> dict:
        """Get API key info (without secret)"""
        keys = self._read_keys()
        
        if api_key not in keys:
            return {'success': False, 'message': 'API key not found'}
        
        key_data = keys[api_key].copy()
        del key_data['secret_hash']
        
        return {'success': True, 'key': key_data}
    
    # ===== Request Validation =====
    
    def validate_api_key(self, api_key: str, api_secret: str = None) -> Tuple[bool, str]:
        """Validate API key"""
        keys = self._read_keys()
        
        if api_key not in keys:
            return False, 'Invalid API key'
        
        key_data = keys[api_key]
        
        # Check if enabled
        if not key_data['enabled']:
            return False, 'API key is disabled'
        
        # Check expiration
        expires_at = datetime.fromisoformat(key_data['expires_at'])
        if datetime.now() > expires_at:
            return False, 'API key expired'
        
        # Verify secret if provided
        if api_secret:
            secret_hash = hashlib.sha256(api_secret.encode()).hexdigest()
            if secret_hash != key_data['secret_hash']:
                return False, 'Invalid API secret'
        
        # Update last used
        key_data['last_used'] = datetime.now().isoformat()
        key_data['request_count'] = key_data.get('request_count', 0) + 1
        keys[api_key] = key_data
        self._write_keys(keys)
        
        return True, 'Valid'
    
    def verify_request_signature(self, api_key: str, api_secret: str, 
                                 signature: str, data: bytes) -> Tuple[bool, str]:
        """Verify request signature (HMAC-SHA256)"""
        
        # Validate key first
        valid, msg = self.validate_api_key(api_key, api_secret)
        if not valid:
            return False, msg
        
        # Compute expected signature
        expected_sig = hmac.new(
            api_secret.encode(),
            data,
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures (constant-time)
        if not hmac.compare_digest(signature, expected_sig):
            return False, 'Invalid signature'
        
        return True, 'Signature valid'
    
    # ===== Rate Limiting =====
    
    def check_rate_limit(self, user_id: str, user_role: str = 'user') -> Tuple[bool, Dict]:
        """Check if request is within rate limit using in-memory tracking"""
        
        limits = self.config['rate_limits'].get(user_role, 
                                                self.config['rate_limits']['guest'])
        
        rate_limit_key = f"{user_id}_{user_role}"
        window_seconds = self.config.get('rate_limit_reset_window', 60)
        limit_per_minute = limits['requests_per_minute']
        
        # Check and increment the rate limit counter
        allowed, remaining = _rate_limit_store.check_and_increment(
            rate_limit_key, 
            limit_per_minute, 
            window_seconds
        )
        
        reset_time = _rate_limit_store.get_reset_time(rate_limit_key, window_seconds)
        
        return allowed, {
            'allowed': allowed,
            'remaining': remaining,
            'limit': limit_per_minute,
            'reset_at': reset_time
        }
    
    def apply_rate_limit_headers(self, response, user_role: str = 'user', rate_info: Dict = None):
        """Add rate limit headers to response"""
        limits = self.config['rate_limits'].get(user_role, 
                                                self.config['rate_limits']['guest'])
        
        if rate_info:
            response.headers['X-RateLimit-Limit'] = str(rate_info.get('limit', limits['requests_per_minute']))
            response.headers['X-RateLimit-Remaining'] = str(rate_info.get('remaining', 0))
            response.headers['X-RateLimit-Reset'] = str(rate_info.get('reset_at', int(time.time()) + 60))
        else:
            response.headers['X-RateLimit-Limit'] = str(limits['requests_per_minute'])
            response.headers['X-RateLimit-Remaining'] = str(limits['requests_per_minute'])
            response.headers['X-RateLimit-Reset'] = str(int(time.time()) + 60)
        
        return response
    
    # ===== IP Whitelisting/Blacklisting =====
    
    def add_allowed_ip(self, ip_address: str) -> dict:
        """Add IP to whitelist"""
        if ip_address not in self.config['allowed_ips']:
            self.config['allowed_ips'].append(ip_address)
            self._write_config(self.config)
        
        return {'success': True, 'message': f'IP {ip_address} added to whitelist'}
    
    def remove_allowed_ip(self, ip_address: str) -> dict:
        """Remove IP from whitelist"""
        if ip_address in self.config['allowed_ips']:
            self.config['allowed_ips'].remove(ip_address)
            self._write_config(self.config)
        
        return {'success': True, 'message': f'IP {ip_address} removed from whitelist'}
    
    def add_blocked_ip(self, ip_address: str) -> dict:
        """Add IP to blacklist"""
        if ip_address not in self.config['blocked_ips']:
            self.config['blocked_ips'].append(ip_address)
            self._write_config(self.config)
        
        return {'success': True, 'message': f'IP {ip_address} added to blacklist'}
    
    def remove_blocked_ip(self, ip_address: str) -> dict:
        """Remove IP from blacklist"""
        if ip_address in self.config['blocked_ips']:
            self.config['blocked_ips'].remove(ip_address)
            self._write_config(self.config)
        
        return {'success': True, 'message': f'IP {ip_address} removed from blacklist'}
    
    def is_ip_allowed(self, ip_address: str) -> Tuple[bool, str]:
        """Check if IP is allowed"""
        # Check blacklist first
        if ip_address in self.config['blocked_ips']:
            return False, 'IP is blocked'
        
        # Check whitelist (if list exists and is not empty)
        if self.config['allowed_ips'] and ip_address not in self.config['allowed_ips']:
            return False, 'IP is not whitelisted'
        
        return True, 'IP is allowed'
    
    # ===== Usage Statistics =====
    
    def get_api_key_stats(self, api_key: str) -> dict:
        """Get API key usage statistics"""
        keys = self._read_keys()
        
        if api_key not in keys:
            return {'success': False, 'message': 'API key not found'}
        
        key_data = keys[api_key]
        
        return {
            'success': True,
            'api_key': api_key,
            'created_at': key_data['created_at'],
            'expires_at': key_data['expires_at'],
            'last_used': key_data['last_used'],
            'request_count': key_data.get('request_count', 0),
            'enabled': key_data['enabled']
        }
    
    def get_user_api_stats(self, user_id: str) -> dict:
        """Get aggregate API stats for user"""
        keys = self._read_keys()
        
        total_keys = 0
        active_keys = 0
        total_requests = 0
        
        for api_key, key_data in keys.items():
            if key_data['user_id'] == user_id:
                total_keys += 1
                if key_data['enabled']:
                    active_keys += 1
                total_requests += key_data.get('request_count', 0)
        
        return {
            'success': True,
            'total_keys': total_keys,
            'active_keys': active_keys,
            'disabled_keys': total_keys - active_keys,
            'total_requests': total_requests
        }
    
    # ===== File Operations =====
    
    def _read_keys(self) -> dict:
        """Read API keys database"""
        try:
            if self.db_file.exists():
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _write_keys(self, data: dict) -> None:
        """Write API keys database"""
        try:
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to write API keys: {e}")
    
    def _read_config(self) -> dict:
        """Read API config"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return self._default_config()
    
    def _write_config(self, data: dict) -> None:
        """Write API config"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to write API config: {e}")


# ===== Flask Decorators =====

def require_api_key(f):
    """Decorator: Require API key for endpoint"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'success': False, 'message': 'Missing API key'}), 401
        
        api_security = api_security_manager
        valid, msg = api_security.validate_api_key(api_key)
        
        if not valid:
            return jsonify({'success': False, 'message': msg}), 401
        
        # Store key in request context for use in handler
        request.api_key = api_key
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_api_signature(f):
    """Decorator: Require API request signature"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        signature = request.headers.get('X-API-Signature')
        api_secret = request.headers.get('X-API-Secret')  # Should be from secure storage
        
        if not all([api_key, signature, api_secret]):
            return jsonify({'success': False, 'message': 'Missing signature headers'}), 401
        
        api_security = api_security_manager
        data = request.get_data()
        
        valid, msg = api_security.verify_request_signature(api_key, api_secret, signature, data)
        
        if not valid:
            return jsonify({'success': False, 'message': msg}), 401
        
        request.api_key = api_key
        return f(*args, **kwargs)
    
    return decorated_function


def check_rate_limit(user_role='user'):
    """Decorator: Check rate limit with actual enforcement"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get user identifier from request
            user_id = getattr(request, 'user_id', None)
            if not user_id:
                # Fall back to IP address for anonymous users
                user_id = request.remote_addr or 'anonymous'
            
            api_security = api_security_manager
            allowed, rate_info = api_security.check_rate_limit(user_id, user_role)
            
            if not allowed:
                response = jsonify({
                    'success': False, 
                    'message': 'Rate limit exceeded',
                    'retry_after': rate_info.get('reset_at', 60) - int(time.time())
                })
                response = api_security.apply_rate_limit_headers(response, user_role, rate_info)
                return response, 429
            
            # Execute the endpoint
            result = f(*args, **kwargs)
            
            # Add rate limit headers to response
            if isinstance(result, tuple):
                response, code = result
                if hasattr(response, 'headers'):
                    response = api_security.apply_rate_limit_headers(response, user_role, rate_info)
                return response, code
            else:
                if hasattr(result, 'headers'):
                    result = api_security.apply_rate_limit_headers(result, user_role, rate_info)
                return result
        
        return decorated_function
    return decorator


# Global API security manager instance
api_security_manager = APISecurityManager()
