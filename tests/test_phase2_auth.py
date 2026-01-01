"""
ApkayA Enterprise Control Panel - Authentication Tests
Tests for auth endpoints, session management, and RBAC

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import unittest
import json
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'panel'))

# Import using importlib to handle 'class' directory name
import importlib.util

def load_module_from_path(module_name, file_path):
    """Load a module from file path"""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Load modules
auth_module = load_module_from_path('auth', os.path.join(project_root, 'panel', 'class', 'auth.py'))
authz_module = load_module_from_path('authorization', os.path.join(project_root, 'panel', 'class', 'authorization.py'))
api_sec_module = load_module_from_path('api_security', os.path.join(project_root, 'panel', 'class', 'api_security.py'))

AuthManager = auth_module.AuthManager
AuthorizationManager = authz_module.AuthorizationManager
APISecurityManager = api_sec_module.APISecurityManager


class TestAuthEndpoints(unittest.TestCase):
    """Test authentication endpoints"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        cls.auth = AuthManager(
            db_file='data/test_users.json',
            sessions_file='data/test_sessions.json'
        )
        # Clean up any existing test data
        if os.path.exists('data/test_users.json'):
            os.remove('data/test_users.json')
        if os.path.exists('data/test_sessions.json'):
            os.remove('data/test_sessions.json')
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test data"""
        if os.path.exists('data/test_users.json'):
            os.remove('data/test_users.json')
        if os.path.exists('data/test_sessions.json'):
            os.remove('data/test_sessions.json')
    
    def test_01_register_valid_user(self):
        """Test successful user registration"""
        result = self.auth.register(
            username='testuser',
            email='test@example.com',
            password='Test@123!'
        )
        self.assertTrue(result['success'])
        self.assertIn('user_id', result)
        self.assertEqual(result['username'], 'testuser')
    
    def test_02_register_duplicate_username(self):
        """Test registration with duplicate username"""
        result = self.auth.register(
            username='testuser',
            email='test2@example.com',
            password='Test@123!'
        )
        self.assertFalse(result['success'])
        self.assertIn('already exists', result['message'])
    
    def test_03_register_duplicate_email(self):
        """Test registration with duplicate email"""
        result = self.auth.register(
            username='testuser2',
            email='test@example.com',
            password='Test@123!'
        )
        self.assertFalse(result['success'])
        self.assertIn('already exists', result['message'])
    
    def test_04_register_weak_password(self):
        """Test registration with weak password"""
        result = self.auth.register(
            username='testuser3',
            email='test3@example.com',
            password='weak'
        )
        self.assertFalse(result['success'])
        self.assertIn('weak', result['message'].lower())
    
    def test_05_register_invalid_username(self):
        """Test registration with invalid username"""
        result = self.auth.register(
            username='ab',  # Too short
            email='test4@example.com',
            password='Test@123!'
        )
        self.assertFalse(result['success'])
    
    def test_06_register_invalid_email(self):
        """Test registration with invalid email"""
        result = self.auth.register(
            username='testuser5',
            email='invalid-email',
            password='Test@123!'
        )
        self.assertFalse(result['success'])
    
    def test_07_login_valid_credentials(self):
        """Test successful login"""
        result = self.auth.login('testuser', 'Test@123!')
        self.assertTrue(result['success'])
        self.assertIn('session_token', result)
        self.assertEqual(result['username'], 'testuser')
        self.__class__.session_token = result['session_token']
    
    def test_08_login_invalid_username(self):
        """Test login with invalid username"""
        result = self.auth.login('nonexistent', 'Test@123!')
        self.assertFalse(result['success'])
        self.assertIn('Invalid', result['message'])
    
    def test_09_login_invalid_password(self):
        """Test login with invalid password"""
        result = self.auth.login('testuser', 'WrongPassword!')
        self.assertFalse(result['success'])
        self.assertIn('Invalid', result['message'])
    
    def test_10_validate_session_valid(self):
        """Test session validation with valid token"""
        result = self.auth.validate_session(self.session_token)
        self.assertTrue(result['valid'])
        self.assertEqual(result['username'], 'testuser')
    
    def test_11_validate_session_invalid(self):
        """Test session validation with invalid token"""
        result = self.auth.validate_session('invalid_token_here')
        self.assertFalse(result['valid'])
    
    def test_12_get_user(self):
        """Test get user info"""
        # Get user by ID (first registered user)
        user = self.auth.get_user('1')
        self.assertIsNotNone(user)
        self.assertEqual(user['username'], 'testuser')
        self.assertNotIn('password_hash', user)
    
    def test_13_list_users(self):
        """Test list users"""
        users = self.auth.list_users()
        self.assertIsInstance(users, list)
        self.assertGreater(len(users), 0)
        # Ensure password hashes are not exposed
        for user in users:
            self.assertNotIn('password_hash', user)
    
    def test_14_change_password(self):
        """Test password change"""
        result = self.auth.change_password('1', 'Test@123!', 'NewTest@456!')
        self.assertTrue(result['success'])
        
        # Verify old password no longer works
        result = self.auth.login('testuser', 'Test@123!')
        self.assertFalse(result['success'])
        
        # Verify new password works
        result = self.auth.login('testuser', 'NewTest@456!')
        self.assertTrue(result['success'])
    
    def test_15_change_password_wrong_old(self):
        """Test password change with wrong old password"""
        result = self.auth.change_password('1', 'WrongOldPassword!', 'NewTest@789!')
        self.assertFalse(result['success'])
        self.assertIn('incorrect', result['message'].lower())
    
    def test_16_reset_password(self):
        """Test password reset initiation"""
        result = self.auth.reset_password('testuser')
        self.assertTrue(result['success'])
        self.assertIn('reset_token', result)
        self.__class__.reset_token = result['reset_token']
    
    def test_17_confirm_password_reset(self):
        """Test password reset confirmation"""
        result = self.auth.confirm_password_reset(self.reset_token, 'Reset@123!')
        self.assertTrue(result['success'])
        
        # Verify new password works
        result = self.auth.login('testuser', 'Reset@123!')
        self.assertTrue(result['success'])
    
    def test_18_confirm_password_reset_invalid_token(self):
        """Test password reset with invalid token"""
        result = self.auth.confirm_password_reset('invalid_token', 'Reset@456!')
        self.assertFalse(result['success'])
    
    def test_19_logout(self):
        """Test logout"""
        # Login first
        login_result = self.auth.login('testuser', 'Reset@123!')
        token = login_result['session_token']
        
        # Logout
        result = self.auth.logout(token)
        self.assertTrue(result['success'])
        
        # Verify session is invalid
        result = self.auth.validate_session(token)
        self.assertFalse(result['valid'])
    
    def test_20_update_user(self):
        """Test user update"""
        result = self.auth.update_user('1', {'email': 'updated@example.com'})
        self.assertTrue(result['success'])
        
        # Verify update
        user = self.auth.get_user('1')
        self.assertEqual(user['email'], 'updated@example.com')
    
    def test_21_delete_user(self):
        """Test user deletion"""
        # Create a new user to delete
        self.auth.register(
            username='deleteuser',
            email='delete@example.com',
            password='Delete@123!'
        )
        
        # Get the user ID
        users = self.auth.list_users()
        delete_user = next((u for u in users if u['username'] == 'deleteuser'), None)
        self.assertIsNotNone(delete_user)
        
        # Delete
        result = self.auth.delete_user(delete_user['id'])
        self.assertTrue(result['success'])
        
        # Verify user is gone
        user = self.auth.get_user(delete_user['id'])
        self.assertIsNone(user)


class TestAuthorizationRBAC(unittest.TestCase):
    """Test RBAC authorization"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        cls.authz = AuthorizationManager(db_file='data/test_rbac.json')
        if os.path.exists('data/test_rbac.json'):
            os.remove('data/test_rbac.json')
        cls.authz = AuthorizationManager(db_file='data/test_rbac.json')
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test data"""
        if os.path.exists('data/test_rbac.json'):
            os.remove('data/test_rbac.json')
    
    def test_01_list_default_roles(self):
        """Test listing default roles"""
        roles = self.authz.list_roles()
        self.assertIsInstance(roles, list)
        # Roles use display names in 'name' field
        role_names = [r['name'] for r in roles]
        self.assertIn('Administrator', role_names)
        self.assertIn('Operator', role_names)
        self.assertIn('User', role_names)
        self.assertIn('Guest', role_names)
    
    def test_02_create_custom_role(self):
        """Test creating custom role"""
        result = self.authz.create_role(
            'custom_role',
            'Custom Role Description',
            permissions=['sites.read', 'files.read'],
            level=3
        )
        self.assertTrue(result['success'])
        self.assertEqual(result['role']['name'], 'custom_role')
    
    def test_03_create_duplicate_role(self):
        """Test creating duplicate role"""
        result = self.authz.create_role('custom_role', 'Duplicate')
        self.assertFalse(result['success'])
        self.assertIn('already exists', result['message'])
    
    def test_04_get_role(self):
        """Test getting role info"""
        role = self.authz.get_role('custom_role')
        self.assertIsNotNone(role)
        self.assertEqual(role['name'], 'custom_role')
        self.assertIn('sites.read', role['permissions'])
    
    def test_05_update_custom_role(self):
        """Test updating custom role"""
        result = self.authz.update_role('custom_role', {
            'description': 'Updated Description',
            'level': 4
        })
        self.assertTrue(result['success'])
        
        role = self.authz.get_role('custom_role')
        self.assertEqual(role['description'], 'Updated Description')
        self.assertEqual(role['level'], 4)
    
    def test_06_cannot_update_default_role(self):
        """Test that default roles cannot be modified"""
        result = self.authz.update_role('admin', {'level': 100})
        self.assertFalse(result['success'])
        self.assertIn('default', result['message'].lower())
    
    def test_07_add_permission_to_role(self):
        """Test adding permission to role"""
        result = self.authz.add_permission_to_role('custom_role', 'database.read')
        self.assertTrue(result['success'])
        
        role = self.authz.get_role('custom_role')
        self.assertIn('database.read', role['permissions'])
    
    def test_08_remove_permission_from_role(self):
        """Test removing permission from role"""
        result = self.authz.remove_permission_from_role('custom_role', 'database.read')
        self.assertTrue(result['success'])
        
        role = self.authz.get_role('custom_role')
        self.assertNotIn('database.read', role['permissions'])
    
    def test_09_assign_role_to_user(self):
        """Test assigning role to user"""
        result = self.authz.assign_role_to_user('test_user_1', 'custom_role')
        self.assertTrue(result['success'])
        
        roles = self.authz.get_user_roles('test_user_1')
        self.assertIn('custom_role', roles)
    
    def test_10_remove_role_from_user(self):
        """Test removing role from user"""
        result = self.authz.remove_role_from_user('test_user_1', 'custom_role')
        self.assertTrue(result['success'])
        
        roles = self.authz.get_user_roles('test_user_1')
        self.assertNotIn('custom_role', roles)
    
    def test_11_has_permission_admin(self):
        """Test admin has all permissions"""
        self.authz.assign_role_to_user('admin_user', 'admin')
        
        self.assertTrue(self.authz.has_permission('admin_user', 'users.create'))
        self.assertTrue(self.authz.has_permission('admin_user', 'sites.delete'))
        self.assertTrue(self.authz.has_permission('admin_user', 'waf.update'))
    
    def test_12_has_permission_user(self):
        """Test user has limited permissions"""
        self.authz.assign_role_to_user('regular_user', 'user')
        
        self.assertTrue(self.authz.has_permission('regular_user', 'sites.read'))
        self.assertFalse(self.authz.has_permission('regular_user', 'sites.delete'))
        self.assertFalse(self.authz.has_permission('regular_user', 'users.create'))
    
    def test_13_has_permission_guest(self):
        """Test guest has minimal permissions"""
        self.authz.assign_role_to_user('guest_user', 'guest')
        
        self.assertTrue(self.authz.has_permission('guest_user', 'system.read'))
        self.assertFalse(self.authz.has_permission('guest_user', 'sites.read'))
        self.assertFalse(self.authz.has_permission('guest_user', 'files.read'))
    
    def test_14_get_user_permissions(self):
        """Test getting all user permissions"""
        self.authz.set_user_roles('multi_role_user', ['operator', 'user'])
        
        permissions = self.authz.get_user_permissions('multi_role_user')
        self.assertIn('sites.read', permissions)
        self.assertIn('sites.update', permissions)  # from operator
        self.assertIn('audit.read', permissions)  # from operator
    
    def test_15_get_user_level(self):
        """Test user privilege level"""
        self.authz.set_user_roles('level_user', ['admin'])
        level = self.authz.get_user_level('level_user')
        self.assertEqual(level, 10)
        
        self.authz.set_user_roles('level_user', ['user'])
        level = self.authz.get_user_level('level_user')
        self.assertEqual(level, 1)
    
    def test_16_delete_custom_role(self):
        """Test deleting custom role"""
        result = self.authz.delete_role('custom_role')
        self.assertTrue(result['success'])
        
        role = self.authz.get_role('custom_role')
        self.assertIsNone(role)
    
    def test_17_cannot_delete_default_role(self):
        """Test that default roles cannot be deleted"""
        result = self.authz.delete_role('admin')
        self.assertFalse(result['success'])
        self.assertIn('default', result['message'].lower())
    
    def test_18_get_all_permissions(self):
        """Test getting all available permissions"""
        permissions = self.authz.get_all_permissions()
        self.assertIsInstance(permissions, list)
        self.assertIn('users.create', permissions)
        self.assertIn('sites.read', permissions)
        self.assertIn('waf.update', permissions)


class TestAPISecurityRateLimiting(unittest.TestCase):
    """Test API security and rate limiting"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        cls.api_sec = APISecurityManager(
            db_file='data/test_api_keys.json',
            config_file='data/test_api_config.json'
        )
        if os.path.exists('data/test_api_keys.json'):
            os.remove('data/test_api_keys.json')
        if os.path.exists('data/test_api_config.json'):
            os.remove('data/test_api_config.json')
        cls.api_sec = APISecurityManager(
            db_file='data/test_api_keys.json',
            config_file='data/test_api_config.json'
        )
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test data"""
        for f in ['data/test_api_keys.json', 'data/test_api_config.json']:
            if os.path.exists(f):
                os.remove(f)
    
    def test_01_create_api_key(self):
        """Test API key creation"""
        result = self.api_sec.create_api_key(
            user_id='1',
            name='Test API Key',
            permissions=['sites.read', 'files.read']
        )
        self.assertTrue(result['success'])
        self.assertIn('api_key', result)
        self.assertIn('api_secret', result)
        self.assertTrue(result['api_key'].startswith('apk_'))
        self.__class__.api_key = result['api_key']
        self.__class__.api_secret = result['api_secret']
    
    def test_02_validate_api_key(self):
        """Test API key validation"""
        valid, msg = self.api_sec.validate_api_key(self.api_key)
        self.assertTrue(valid)
    
    def test_03_validate_api_key_with_secret(self):
        """Test API key validation with secret"""
        valid, msg = self.api_sec.validate_api_key(self.api_key, self.api_secret)
        self.assertTrue(valid)
    
    def test_04_validate_invalid_key(self):
        """Test validation of invalid API key"""
        valid, msg = self.api_sec.validate_api_key('invalid_key')
        self.assertFalse(valid)
    
    def test_05_validate_wrong_secret(self):
        """Test validation with wrong secret"""
        valid, msg = self.api_sec.validate_api_key(self.api_key, 'wrong_secret')
        self.assertFalse(valid)
    
    def test_06_list_api_keys(self):
        """Test listing user's API keys"""
        result = self.api_sec.list_api_keys('1')
        self.assertTrue(result['success'])
        self.assertIsInstance(result['keys'], list)
        self.assertGreater(len(result['keys']), 0)
        # Ensure secret hash is not exposed
        for key in result['keys']:
            self.assertNotIn('secret_hash', key)
    
    def test_07_get_api_key_info(self):
        """Test getting API key info"""
        result = self.api_sec.get_api_key_info(self.api_key)
        self.assertTrue(result['success'])
        self.assertEqual(result['key']['name'], 'Test API Key')
        self.assertNotIn('secret_hash', result['key'])
    
    def test_08_regenerate_api_key(self):
        """Test regenerating API secret"""
        result = self.api_sec.regenerate_api_key(self.api_key)
        self.assertTrue(result['success'])
        self.assertIn('api_secret', result)
        
        # Old secret should no longer work
        valid, _ = self.api_sec.validate_api_key(self.api_key, self.api_secret)
        self.assertFalse(valid)
        
        # New secret should work
        valid, _ = self.api_sec.validate_api_key(self.api_key, result['api_secret'])
        self.assertTrue(valid)
        self.__class__.api_secret = result['api_secret']
    
    def test_09_get_api_key_stats(self):
        """Test getting API key statistics"""
        result = self.api_sec.get_api_key_stats(self.api_key)
        self.assertTrue(result['success'])
        self.assertIn('request_count', result)
        self.assertIn('last_used', result)
    
    def test_10_get_user_api_stats(self):
        """Test getting user API statistics"""
        result = self.api_sec.get_user_api_stats('1')
        self.assertTrue(result['success'])
        self.assertIn('total_keys', result)
        self.assertIn('active_keys', result)
    
    def test_11_check_rate_limit(self):
        """Test rate limit checking"""
        allowed, info = self.api_sec.check_rate_limit('1', 'user')
        self.assertTrue(allowed)
        self.assertIn('remaining', info)
        self.assertIn('reset_at', info)
    
    def test_12_ip_whitelist(self):
        """Test IP whitelist management"""
        result = self.api_sec.add_allowed_ip('192.168.1.100')
        self.assertTrue(result['success'])
        
        # Check if IP is allowed
        allowed, _ = self.api_sec.is_ip_allowed('192.168.1.100')
        self.assertTrue(allowed)
        
        # Remove and verify
        result = self.api_sec.remove_allowed_ip('192.168.1.100')
        self.assertTrue(result['success'])
    
    def test_13_ip_blacklist(self):
        """Test IP blacklist management"""
        result = self.api_sec.add_blocked_ip('10.0.0.1')
        self.assertTrue(result['success'])
        
        # Check if IP is blocked
        allowed, _ = self.api_sec.is_ip_allowed('10.0.0.1')
        self.assertFalse(allowed)
        
        # Remove and verify
        result = self.api_sec.remove_blocked_ip('10.0.0.1')
        self.assertTrue(result['success'])
    
    def test_14_revoke_api_key(self):
        """Test revoking API key"""
        result = self.api_sec.revoke_api_key(self.api_key)
        self.assertTrue(result['success'])
        
        # Verify key is disabled
        valid, msg = self.api_sec.validate_api_key(self.api_key)
        self.assertFalse(valid)
        self.assertIn('disabled', msg.lower())


if __name__ == '__main__':
    # Create data directory if needed
    os.makedirs('data', exist_ok=True)
    
    # Run tests
    unittest.main(verbosity=2)
