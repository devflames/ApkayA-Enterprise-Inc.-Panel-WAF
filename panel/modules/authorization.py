"""
Phase 2: Authorization & RBAC Module
Role-Based Access Control system with permission management
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class AuthorizationManager:
    """Complete RBAC system for role and permission management"""
    
    def __init__(self, db_file='data/rbac.json'):
        """Initialize authorization manager"""
        self.db_file = Path(db_file)
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Default role definitions
        self.default_roles = {
            'admin': {
                'name': 'Administrator',
                'description': 'Full system access',
                'permissions': [
                    'users.create', 'users.read', 'users.update', 'users.delete',
                    'roles.create', 'roles.read', 'roles.update', 'roles.delete',
                    'permissions.create', 'permissions.read', 'permissions.update', 'permissions.delete',
                    'sites.create', 'sites.read', 'sites.update', 'sites.delete',
                    'database.create', 'database.read', 'database.update', 'database.delete',
                    'files.create', 'files.read', 'files.update', 'files.delete',
                    'waf.read', 'waf.update',
                    'system.read', 'logs.read', 'audit.read', 'settings.read', 'settings.update'
                ],
                'level': 10  # Highest level
            },
            'operator': {
                'name': 'Operator',
                'description': 'System management and monitoring',
                'permissions': [
                    'sites.read', 'sites.update',
                    'database.read', 'database.update',
                    'files.read', 'files.update',
                    'waf.read',
                    'system.read', 'logs.read', 'audit.read'
                ],
                'level': 5
            },
            'user': {
                'name': 'User',
                'description': 'Limited system access',
                'permissions': [
                    'sites.read',
                    'database.read',
                    'files.read',
                    'system.read'
                ],
                'level': 1
            },
            'guest': {
                'name': 'Guest',
                'description': 'View-only access',
                'permissions': [
                    'system.read'
                ],
                'level': 0
            }
        }

        # Initialize default roles if not exists
        if not self.db_file.exists():
            self._init_default_rbac()
    
    # ===== Role Management =====
    
    def create_role(self, role_name: str, description: str, permissions: List[str] = None, level: int = 1) -> dict:
        """Create new role"""
        rbac = self._read_rbac()
        
        if 'roles' not in rbac:
            rbac['roles'] = {}
        
        if role_name in rbac['roles']:
            return {'success': False, 'message': f'Role {role_name} already exists'}
        
        if not self._validate_role_name(role_name):
            return {'success': False, 'message': 'Invalid role name'}
        
        role = {
            'name': role_name,
            'display_name': description.split('|')[0] if '|' in description else role_name.title(),
            'description': description,
            'permissions': permissions or [],
            'level': level,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        rbac['roles'][role_name] = role
        self._write_rbac(rbac)
        
        return {
            'success': True,
            'message': f'Role {role_name} created',
            'role': role
        }
    
    def get_role(self, role_name: str) -> Optional[dict]:
        """Get role information"""
        rbac = self._read_rbac()
        
        if 'roles' not in rbac or role_name not in rbac['roles']:
            return None
        
        return rbac['roles'][role_name]
    
    def list_roles(self, include_permissions: bool = True) -> list:
        """List all roles"""
        rbac = self._read_rbac()
        
        if 'roles' not in rbac:
            return []
        
        roles = list(rbac['roles'].values())
        
        if not include_permissions:
            for role in roles:
                role.pop('permissions', None)
        
        return roles
    
    def update_role(self, role_name: str, updates: dict) -> dict:
        """Update role"""
        rbac = self._read_rbac()
        
        if 'roles' not in rbac or role_name not in rbac['roles']:
            return {'success': False, 'message': 'Role not found'}
        
        # Prevent modification of default roles
        if role_name in ['admin', 'user', 'operator', 'guest']:
            return {'success': False, 'message': 'Cannot modify default roles'}
        
        role = rbac['roles'][role_name]
        
        # Update allowed fields
        allowed_fields = ['description', 'display_name', 'permissions', 'level']
        for field, value in updates.items():
            if field in allowed_fields:
                role[field] = value
        
        role['updated_at'] = datetime.now().isoformat()
        rbac['roles'][role_name] = role
        self._write_rbac(rbac)
        
        return {'success': True, 'message': f'Role {role_name} updated', 'role': role}
    
    def delete_role(self, role_name: str) -> dict:
        """Delete role"""
        rbac = self._read_rbac()
        
        if 'roles' not in rbac or role_name not in rbac['roles']:
            return {'success': False, 'message': 'Role not found'}
        
        # Prevent deletion of default roles
        if role_name in ['admin', 'user', 'operator', 'guest']:
            return {'success': False, 'message': 'Cannot delete default roles'}
        
        del rbac['roles'][role_name]
        self._write_rbac(rbac)
        
        return {'success': True, 'message': f'Role {role_name} deleted'}
    
    # ===== Permission Management =====
    
    def add_permission_to_role(self, role_name: str, permission: str) -> dict:
        """Add permission to role"""
        rbac = self._read_rbac()
        
        if 'roles' not in rbac or role_name not in rbac['roles']:
            return {'success': False, 'message': 'Role not found'}
        
        role = rbac['roles'][role_name]
        
        if permission in role.get('permissions', []):
            return {'success': False, 'message': f'Permission {permission} already exists'}
        
        if 'permissions' not in role:
            role['permissions'] = []
        
        role['permissions'].append(permission)
        role['updated_at'] = datetime.now().isoformat()
        rbac['roles'][role_name] = role
        self._write_rbac(rbac)
        
        return {'success': True, 'message': f'Permission {permission} added to role {role_name}'}
    
    def remove_permission_from_role(self, role_name: str, permission: str) -> dict:
        """Remove permission from role"""
        rbac = self._read_rbac()
        
        if 'roles' not in rbac or role_name not in rbac['roles']:
            return {'success': False, 'message': 'Role not found'}
        
        role = rbac['roles'][role_name]
        
        if permission not in role.get('permissions', []):
            return {'success': False, 'message': f'Permission {permission} not found'}
        
        role['permissions'].remove(permission)
        role['updated_at'] = datetime.now().isoformat()
        rbac['roles'][role_name] = role
        self._write_rbac(rbac)
        
        return {'success': True, 'message': f'Permission {permission} removed from role {role_name}'}
    
    def get_all_permissions(self) -> list:
        """Get all available permissions"""
        all_permissions = []
        
        for role in self.default_roles.values():
            all_permissions.extend(role['permissions'])
        
        # Return unique permissions
        return sorted(list(set(all_permissions)))
    
    # ===== User-Role Assignment =====
    
    def assign_role_to_user(self, user_id: str, role_name: str) -> dict:
        """Assign role to user"""
        rbac = self._read_rbac()
        
        if 'roles' not in rbac or role_name not in rbac['roles']:
            return {'success': False, 'message': 'Role not found'}
        
        if 'user_roles' not in rbac:
            rbac['user_roles'] = {}
        
        if user_id not in rbac['user_roles']:
            rbac['user_roles'][user_id] = []
        
        if role_name in rbac['user_roles'][user_id]:
            return {'success': False, 'message': f'User already has role {role_name}'}
        
        rbac['user_roles'][user_id].append(role_name)
        self._write_rbac(rbac)
        
        return {'success': True, 'message': f'Role {role_name} assigned to user {user_id}'}
    
    def remove_role_from_user(self, user_id: str, role_name: str) -> dict:
        """Remove role from user"""
        rbac = self._read_rbac()
        
        if 'user_roles' not in rbac or user_id not in rbac['user_roles']:
            return {'success': False, 'message': 'User has no roles'}
        
        if role_name not in rbac['user_roles'][user_id]:
            return {'success': False, 'message': f'User does not have role {role_name}'}
        
        rbac['user_roles'][user_id].remove(role_name)
        self._write_rbac(rbac)
        
        return {'success': True, 'message': f'Role {role_name} removed from user {user_id}'}
    
    def get_user_roles(self, user_id: str) -> list:
        """Get user's roles"""
        rbac = self._read_rbac()
        
        if 'user_roles' not in rbac or user_id not in rbac['user_roles']:
            # Return default user role
            return ['user']
        
        return rbac['user_roles'][user_id]
    
    def set_user_roles(self, user_id: str, roles: List[str]) -> dict:
        """Set user's roles (replaces existing)"""
        rbac = self._read_rbac()
        
        # Validate all roles exist
        if 'roles' in rbac:
            for role in roles:
                if role not in rbac['roles'] and role not in self.default_roles:
                    return {'success': False, 'message': f'Role {role} not found'}
        
        if 'user_roles' not in rbac:
            rbac['user_roles'] = {}
        
        rbac['user_roles'][user_id] = roles
        self._write_rbac(rbac)
        
        return {'success': True, 'message': f'User roles updated', 'roles': roles}
    
    # ===== Permission Checking =====
    
    def has_permission(self, user_id: str, permission: str) -> bool:
        """Check if user has permission"""
        roles = self.get_user_roles(user_id)
        rbac = self._read_rbac()
        
        for role_name in roles:
            role_data = None
            
            # Check custom roles
            if 'roles' in rbac and role_name in rbac['roles']:
                role_data = rbac['roles'][role_name]
            # Check default roles
            elif role_name in self.default_roles:
                role_data = self.default_roles[role_name]
            
            if role_data and permission in role_data.get('permissions', []):
                return True
        
        return False
    
    def can_user_action(self, user_id: str, action: str, resource: str = None) -> bool:
        """Check if user can perform action on resource"""
        # Format: resource.action (e.g., 'sites.delete', 'users.create')
        permission = f"{resource}.{action}" if resource else action
        return self.has_permission(user_id, permission)
    
    def get_user_permissions(self, user_id: str) -> list:
        """Get all permissions for user"""
        roles = self.get_user_roles(user_id)
        rbac = self._read_rbac()
        permissions = set()
        
        for role_name in roles:
            role_data = None
            
            if 'roles' in rbac and role_name in rbac['roles']:
                role_data = rbac['roles'][role_name]
            elif role_name in self.default_roles:
                role_data = self.default_roles[role_name]
            
            if role_data:
                permissions.update(role_data.get('permissions', []))
        
        return sorted(list(permissions))
    
    def get_user_level(self, user_id: str) -> int:
        """Get user's privilege level (max of all roles)"""
        roles = self.get_user_roles(user_id)
        rbac = self._read_rbac()
        max_level = 0
        
        for role_name in roles:
            level = 0
            
            if 'roles' in rbac and role_name in rbac['roles']:
                level = rbac['roles'][role_name].get('level', 0)
            elif role_name in self.default_roles:
                level = self.default_roles[role_name].get('level', 0)
            
            max_level = max(max_level, level)
        
        return max_level
    
    # ===== Validation =====
    
    @staticmethod
    def _validate_role_name(role_name: str) -> bool:
        """Validate role name"""
        import re
        pattern = r'^[a-z_][a-z0-9_]*$'
        return bool(re.match(pattern, role_name))
    
    # ===== File Operations =====
    
    def _init_default_rbac(self) -> None:
        """Initialize default RBAC"""
        rbac_data = {
            'version': '1.0',
            'roles': self.default_roles,
            'user_roles': {
                # Default admin user
                '1': ['admin']
            },
            'created_at': datetime.now().isoformat()
        }
        self._write_rbac(rbac_data)
    
    def _read_rbac(self) -> dict:
        """Read RBAC database"""
        try:
            if self.db_file.exists():
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {'roles': self.default_roles, 'user_roles': {}}
    
    def _write_rbac(self, data: dict) -> None:
        """Write RBAC database"""
        try:
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to write RBAC: {e}")


# Authorization decorators for Flask
def login_required(f):
    """Decorator to require login"""
    from functools import wraps
    from flask import request, jsonify
    from .auth import auth_manager
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        token = parts[1]

        session_result = auth_manager.validate_session(token)
        if not session_result.get('valid'):
            message = session_result.get('message', 'Invalid session')
            return jsonify({'success': False, 'message': message}), 401

        # Attach session info to request for downstream use
        request.auth_token = token
        request.session_user = {
            'user_id': session_result.get('user_id'),
            'username': session_result.get('username'),
            'roles': session_result.get('roles', [])
        }
        request.user_id = session_result.get('user_id')
        return f(*args, **kwargs)
    
    return decorated_function


def role_required(required_role: str):
    """Decorator to require specific role"""
    def decorator(f):
        from functools import wraps
        from flask import request, jsonify
        from .auth import auth_manager
        from .authorization import authz_manager
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return jsonify({'success': False, 'message': 'Authentication required'}), 401
            token = parts[1]

            session_result = auth_manager.validate_session(token)
            if not session_result.get('valid'):
                message = session_result.get('message', 'Invalid session')
                return jsonify({'success': False, 'message': message}), 401

            user_id = session_result.get('user_id')
            roles = authz_manager.get_user_roles(user_id)
            if required_role not in roles:
                return jsonify({'success': False, 'message': 'Insufficient role'}), 403

            request.auth_token = token
            request.session_user = {
                'user_id': user_id,
                'username': session_result.get('username'),
                'roles': roles
            }
            request.user_id = user_id
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def permission_required(permission: str):
    """Decorator to require specific permission"""
    def decorator(f):
        from functools import wraps
        from flask import request, jsonify
        from .auth import auth_manager
        from .authorization import authz_manager
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return jsonify({'success': False, 'message': 'Authentication required'}), 401
            token = parts[1]

            session_result = auth_manager.validate_session(token)
            if not session_result.get('valid'):
                message = session_result.get('message', 'Invalid session')
                return jsonify({'success': False, 'message': message}), 401

            user_id = session_result.get('user_id')
            if not authz_manager.has_permission(user_id, permission):
                return jsonify({'success': False, 'message': 'Insufficient permissions'}), 403

            request.auth_token = token
            request.session_user = {
                'user_id': user_id,
                'username': session_result.get('username'),
                'roles': authz_manager.get_user_roles(user_id)
            }
            request.user_id = user_id
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# Global authorization manager instance
authz_manager = AuthorizationManager()
