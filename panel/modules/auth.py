"""
ApkayA Enterprise Control Panel - Authentication Module
User login, registration, session management, and password handling

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
"""

import bcrypt
import secrets
import json
from datetime import datetime, timedelta
from pathlib import Path


class AuthManager:
    """Complete authentication system for user management"""
    
    def __init__(self, db_file='data/users.json', sessions_file='data/sessions.json'):
        """Initialize authentication manager"""
        self.db_file = Path(db_file)
        self.sessions_file = Path(sessions_file)
        
        # Create data directory
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize data files
        if not self.db_file.exists():
            self._write_users({})
        if not self.sessions_file.exists():
            self._write_sessions({})
        
        # Configuration
        self.session_timeout = 24 * 60 * 60  # 24 hours
        self.max_login_attempts = 5
        self.lockout_duration = 15 * 60  # 15 minutes
    
    # ===== User Management =====
    
    def register(self, username: str, email: str, password: str) -> dict:
        """Register new user"""
        users = self._read_users()
        
        # Validation
        if not self._validate_username(username):
            return {'success': False, 'message': 'Invalid username'}
        
        if not self._validate_email(email):
            return {'success': False, 'message': 'Invalid email'}
        
        if not self._validate_password(password):
            return {'success': False, 'message': 'Password too weak'}
        
        # Check if user exists
        if any(u['username'] == username for u in users.values()):
            return {'success': False, 'message': 'Username already exists'}
        
        if any(u['email'] == email for u in users.values()):
            return {'success': False, 'message': 'Email already exists'}
        
        # Create user
        user_id = str(len(users) + 1)
        user_data = {
            'id': user_id,
            'username': username,
            'email': email,
            'password_hash': self._hash_password(password),
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'status': 'active',
            'roles': ['user'],  # Default role
            'login_attempts': 0,
            'last_login_attempt': None,
            'locked_until': None,
            'two_fa_enabled': False,
            'two_fa_secret': None
        }
        
        users[user_id] = user_data
        self._write_users(users)
        
        return {
            'success': True,
            'message': 'User registered successfully',
            'user_id': user_id,
            'username': username
        }
    
    def login(self, username: str, password: str) -> dict:
        """User login"""
        users = self._read_users()
        
        # Find user
        user = None
        user_id = None
        for uid, u in users.items():
            if u['username'] == username:
                user = u
                user_id = uid
                break
        
        if not user:
            return {'success': False, 'message': 'Invalid credentials'}
        
        # Check account status
        if user['status'] != 'active':
            return {'success': False, 'message': 'Account is not active'}
        
        # Check lockout
        if user['locked_until']:
            locked_until = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < locked_until:
                return {'success': False, 'message': 'Account is locked. Try again later.'}
            else:
                # Unlock account
                user['locked_until'] = None
                user['login_attempts'] = 0
        
        # Verify password
        if not self._verify_password(password, user['password_hash']):
            # Increment failed attempts
            user['login_attempts'] = user.get('login_attempts', 0) + 1
            user['last_login_attempt'] = datetime.now().isoformat()
            
            if user['login_attempts'] >= self.max_login_attempts:
                user['locked_until'] = (datetime.now() + timedelta(seconds=self.lockout_duration)).isoformat()
                users[user_id] = user
                self._write_users(users)
                return {'success': False, 'message': 'Account locked due to failed login attempts'}
            
            users[user_id] = user
            self._write_users(users)
            return {'success': False, 'message': 'Invalid credentials'}
        
        # Reset login attempts
        user['login_attempts'] = 0
        user['last_login_attempt'] = datetime.now().isoformat()
        user['updated_at'] = datetime.now().isoformat()
        
        # Check if 2FA is enabled
        if user.get('two_fa_enabled'):
            # Generate temporary token
            temp_token = secrets.token_urlsafe(32)
            user['temp_token'] = temp_token
            user['temp_token_expires'] = (datetime.now() + timedelta(minutes=5)).isoformat()
            users[user_id] = user
            self._write_users(users)
            
            return {
                'success': True,
                'message': 'Enter 2FA code',
                'requires_2fa': True,
                'temp_token': temp_token
            }
        
        # Create session
        session = self._create_session(user_id, user)
        users[user_id] = user
        self._write_users(users)
        
        return {
            'success': True,
            'message': 'Login successful',
            'user_id': user_id,
            'username': user['username'],
            'email': user['email'],
            'roles': user['roles'],
            'session_token': session['token'],
            'expires_at': session['expires_at']
        }
    
    def logout(self, session_token: str) -> dict:
        """User logout"""
        sessions = self._read_sessions()
        
        if session_token not in sessions:
            return {'success': False, 'message': 'Invalid session'}
        
        del sessions[session_token]
        self._write_sessions(sessions)
        
        return {'success': True, 'message': 'Logged out successfully'}
    
    # ===== Session Management =====
    
    def _create_session(self, user_id: str, user_data: dict) -> dict:
        """Create user session"""
        sessions = self._read_sessions()
        
        # Generate token
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(seconds=self.session_timeout)).isoformat()
        
        session = {
            'user_id': user_id,
            'username': user_data['username'],
            'email': user_data['email'],
            'roles': user_data['roles'],
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at,
            'last_activity': datetime.now().isoformat()
        }
        
        sessions[token] = session
        self._write_sessions(sessions)
        
        return {
            'token': token,
            'expires_at': expires_at,
            'user_id': user_id
        }
    
    def validate_session(self, session_token: str) -> dict:
        """Validate session token"""
        sessions = self._read_sessions()
        
        if session_token not in sessions:
            return {'valid': False, 'message': 'Invalid session'}
        
        session = sessions[session_token]
        
        # Check expiration
        expires_at = datetime.fromisoformat(session['expires_at'])
        if datetime.now() > expires_at:
            del sessions[session_token]
            self._write_sessions(sessions)
            return {'valid': False, 'message': 'Session expired'}
        
        # Update last activity
        session['last_activity'] = datetime.now().isoformat()
        sessions[session_token] = session
        self._write_sessions(sessions)
        
        return {
            'valid': True,
            'user_id': session['user_id'],
            'username': session['username'],
            'roles': session['roles']
        }
    
    def get_session(self, session_token: str) -> dict:
        """Get session information"""
        sessions = self._read_sessions()
        
        if session_token not in sessions:
            return None
        
        return sessions[session_token]
    
    # ===== Password Management =====
    
    def change_password(self, user_id: str, old_password: str, new_password: str) -> dict:
        """Change user password"""
        users = self._read_users()
        
        if user_id not in users:
            return {'success': False, 'message': 'User not found'}
        
        user = users[user_id]
        
        # Verify old password
        if not self._verify_password(old_password, user['password_hash']):
            return {'success': False, 'message': 'Old password is incorrect'}
        
        # Validate new password
        if not self._validate_password(new_password):
            return {'success': False, 'message': 'New password is too weak'}
        
        # Hash and save new password
        user['password_hash'] = self._hash_password(new_password)
        user['updated_at'] = datetime.now().isoformat()
        users[user_id] = user
        self._write_users(users)
        
        return {'success': True, 'message': 'Password changed successfully'}
    
    def reset_password(self, username: str) -> dict:
        """Initiate password reset"""
        users = self._read_users()
        
        # Find user
        user = None
        user_id = None
        for uid, u in users.items():
            if u['username'] == username:
                user = u
                user_id = uid
                break
        
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        user['reset_token'] = reset_token
        user['reset_token_expires'] = (datetime.now() + timedelta(hours=1)).isoformat()
        users[user_id] = user
        self._write_users(users)
        
        return {
            'success': True,
            'message': 'Password reset initiated',
            'reset_token': reset_token,
            'username': username
        }
    
    def confirm_password_reset(self, reset_token: str, new_password: str) -> dict:
        """Confirm password reset with token"""
        users = self._read_users()
        
        # Find user with token
        user = None
        user_id = None
        for uid, u in users.items():
            if u.get('reset_token') == reset_token:
                user = u
                user_id = uid
                break
        
        if not user:
            return {'success': False, 'message': 'Invalid reset token'}
        
        # Check token expiration
        if not user.get('reset_token_expires'):
            return {'success': False, 'message': 'Reset token expired'}
        
        expires = datetime.fromisoformat(user['reset_token_expires'])
        if datetime.now() > expires:
            user['reset_token'] = None
            user['reset_token_expires'] = None
            users[user_id] = user
            self._write_users(users)
            return {'success': False, 'message': 'Reset token expired'}
        
        # Validate new password
        if not self._validate_password(new_password):
            return {'success': False, 'message': 'New password is too weak'}
        
        # Update password
        user['password_hash'] = self._hash_password(new_password)
        user['reset_token'] = None
        user['reset_token_expires'] = None
        user['updated_at'] = datetime.now().isoformat()
        users[user_id] = user
        self._write_users(users)
        
        return {'success': True, 'message': 'Password reset successful'}
    
    # ===== Password Hashing =====
    
    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password with bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def _verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False
    
    # ===== Validation =====
    
    @staticmethod
    def _validate_username(username: str) -> bool:
        """Validate username format"""
        import re
        pattern = r'^[a-zA-Z0-9_\-]{3,32}$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def _validate_email(email: str) -> bool:
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def _validate_password(password: str) -> bool:
        """Validate password strength"""
        if len(password) < 8:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*(),.?":{}|<>' for c in password)
        
        return has_upper and has_lower and has_digit and has_special
    
    # ===== File Operations =====
    
    def _read_users(self) -> dict:
        """Read users database"""
        try:
            if self.db_file.exists():
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _write_users(self, users: dict) -> None:
        """Write users database"""
        try:
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(users, f, indent=2)
        except Exception as e:
            print(f"Failed to write users: {e}")
    
    def _read_sessions(self) -> dict:
        """Read sessions database"""
        try:
            if self.sessions_file.exists():
                with open(self.sessions_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _write_sessions(self, sessions: dict) -> None:
        """Write sessions database"""
        try:
            with open(self.sessions_file, 'w', encoding='utf-8') as f:
                json.dump(sessions, f, indent=2)
        except Exception as e:
            print(f"Failed to write sessions: {e}")
    
    # ===== User Retrieval =====
    
    def get_user(self, user_id: str) -> dict:
        """Get user information"""
        users = self._read_users()
        
        if user_id not in users:
            return None
        
        user = users[user_id].copy()
        user.pop('password_hash', None)  # Don't return password hash
        return user
    
    def list_users(self, limit: int = 100, offset: int = 0) -> list:
        """List all users"""
        users = self._read_users()
        
        user_list = list(users.values())
        # Remove password hashes
        for user in user_list:
            user.pop('password_hash', None)
        
        return user_list[offset:offset + limit]
    
    def update_user(self, user_id: str, updates: dict) -> dict:
        """Update user information"""
        users = self._read_users()
        
        if user_id not in users:
            return {'success': False, 'message': 'User not found'}
        
        user = users[user_id]
        
        # Only allow certain fields to be updated
        allowed_fields = ['email', 'status', 'roles']
        for field, value in updates.items():
            if field in allowed_fields:
                user[field] = value
        
        user['updated_at'] = datetime.now().isoformat()
        users[user_id] = user
        self._write_users(users)
        
        return {'success': True, 'message': 'User updated successfully'}
    
    def delete_user(self, user_id: str) -> dict:
        """Delete user"""
        users = self._read_users()
        
        if user_id not in users:
            return {'success': False, 'message': 'User not found'}
        
        del users[user_id]
        self._write_users(users)
        
        # Clean up sessions
        sessions = self._read_sessions()
        sessions_to_delete = [token for token, session in sessions.items() if session['user_id'] == user_id]
        for token in sessions_to_delete:
            del sessions[token]
        self._write_sessions(sessions)
        
        return {'success': True, 'message': 'User deleted successfully'}


# Global authentication manager instance
auth_manager = AuthManager()
