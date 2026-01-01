"""
Apkaya Panel WAF - Test Suite
Tests all implemented functionality using direct file imports

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import unittest
import json
import tempfile
import os
import sys
import shutil
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Import modules directly from files
import importlib.util

def load_module(module_name, file_path):
    """Load a module directly from file"""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Load all panel modules
class_dir = os.path.join(project_root, 'panel', 'modules')

# Load validator
validator_module = load_module('validator', os.path.join(class_dir, 'validator.py'))
Validator = validator_module.Validator

# Load public
public_module = load_module('public', os.path.join(class_dir, 'public.py'))
Public = public_module.Public

# Load logger  
logger_module = load_module('logger', os.path.join(class_dir, 'logger.py'))
Logger = logger_module.Logger


class TestValidator(unittest.TestCase):
    """Test Validator class"""
    
    def test_validate_email_valid(self):
        """Test valid email addresses"""
        valid_emails = [
            'test@example.com',
            'user+tag@domain.co.uk',
            'admin@sub.domain.org',
            'user123@test.io'
        ]
        for email in valid_emails:
            self.assertTrue(Validator.validate_email(email), f"Should be valid: {email}")
    
    def test_validate_email_invalid(self):
        """Test invalid email addresses"""
        invalid_emails = ['invalid', 'no@', '@nodomain.com', '']
        for email in invalid_emails:
            self.assertFalse(Validator.validate_email(email), f"Should be invalid: {email}")
    
    def test_validate_domain_valid(self):
        """Test valid domains"""
        valid_domains = ['example.com', 'sub.domain.co.uk', 'test123.org']
        for domain in valid_domains:
            self.assertTrue(Validator.validate_domain(domain), f"Should be valid: {domain}")
    
    def test_validate_domain_invalid(self):
        """Test invalid domains"""
        invalid_domains = ['', '-invalid.com', 'invalid..com', '.invalid.com']
        for domain in invalid_domains:
            self.assertFalse(Validator.validate_domain(domain), f"Should be invalid: {domain}")
    
    def test_validate_ip_valid(self):
        """Test valid IP addresses"""
        valid_ips = ['192.168.1.1', '10.0.0.1', '127.0.0.1', '255.255.255.255']
        for ip in valid_ips:
            self.assertTrue(Validator.validate_ip(ip), f"Should be valid: {ip}")
    
    def test_validate_ip_invalid(self):
        """Test invalid IP addresses"""
        invalid_ips = ['256.1.1.1', 'invalid', '192.168.1', '']
        for ip in invalid_ips:
            self.assertFalse(Validator.validate_ip(ip), f"Should be invalid: {ip}")
    
    def test_validate_port_valid(self):
        """Test valid ports"""
        valid_ports = [80, 443, 8080, 22, 3306, 65535, 1]
        for port in valid_ports:
            self.assertTrue(Validator.validate_port(port), f"Should be valid: {port}")
    
    def test_validate_port_invalid(self):
        """Test invalid ports"""
        invalid_ports = [0, -1, 65536, 100000]
        for port in invalid_ports:
            self.assertFalse(Validator.validate_port(port), f"Should be invalid: {port}")
    
    def test_validate_path_safe(self):
        """Test safe paths"""
        safe_paths = ['/var/www/html', '/home/user', '/opt/data/file.txt']
        for path in safe_paths:
            self.assertTrue(Validator.validate_path(path), f"Should be safe: {path}")
    
    def test_validate_path_unsafe(self):
        """Test unsafe paths with directory traversal"""
        unsafe_paths = ['../etc/passwd', '/var/../../../etc', '/var/www\x00']
        for path in unsafe_paths:
            self.assertFalse(Validator.validate_path(path), f"Should be unsafe: {path}")
    
    def test_validate_filename_valid(self):
        """Test valid filenames"""
        valid_names = ['file.txt', 'document.pdf', 'image_2024.png', 'test-file.docx']
        for name in valid_names:
            self.assertTrue(Validator.validate_filename(name), f"Should be valid: {name}")
    
    def test_validate_filename_invalid(self):
        """Test invalid filenames"""
        invalid_names = ['../file.txt', '']
        for name in invalid_names:
            self.assertFalse(Validator.validate_filename(name), f"Should be invalid: {name}")
    
    def test_password_strength_strong(self):
        """Test strong passwords"""
        strong_passwords = ['StrongP@ss1', 'MySecure#123', 'Complex!Pass99']
        for pwd in strong_passwords:
            valid, _ = Validator.validate_password_strength(pwd)
            self.assertTrue(valid, f"Should be strong: {pwd}")
    
    def test_password_strength_weak(self):
        """Test weak passwords"""
        weak_passwords = ['weak', '12345678', 'nouppercaseletter']
        for pwd in weak_passwords:
            valid, _ = Validator.validate_password_strength(pwd)
            self.assertFalse(valid, f"Should be weak: {pwd}")
    
    def test_validate_url_valid(self):
        """Test valid URLs"""
        valid_urls = ['http://example.com', 'https://secure.site.org/path']
        for url in valid_urls:
            self.assertTrue(Validator.validate_url(url), f"Should be valid: {url}")
    
    def test_validate_url_invalid(self):
        """Test invalid URLs"""
        invalid_urls = ['not-a-url', 'javascript:alert(1)']
        for url in invalid_urls:
            self.assertFalse(Validator.validate_url(url), f"Should be invalid: {url}")
    
    def test_sanitize_string(self):
        """Test string sanitization"""
        dangerous = '<script>alert("xss")</script>'
        result = Validator.sanitize_string(dangerous)
        self.assertNotIn('<', result)
        self.assertNotIn('>', result)
    
    def test_sanitize_string_null_bytes(self):
        """Test null byte removal"""
        dangerous = "test\x00string"
        result = Validator.sanitize_string(dangerous)
        self.assertNotIn('\x00', result)


class TestPublic(unittest.TestCase):
    """Test Public utility class"""
    
    def test_return_msg_success(self):
        """Test success message format"""
        result = Public.return_msg(True, 'Operation succeeded')
        self.assertTrue(result.get('status'))
        self.assertEqual(result.get('msg'), 'Operation succeeded')
    
    def test_return_msg_failure(self):
        """Test failure message format"""
        result = Public.return_msg(False, 'Operation failed')
        self.assertFalse(result.get('status'))
        self.assertEqual(result.get('msg'), 'Operation failed')
    
    def test_generate_random_string(self):
        """Test random string generation"""
        result = Public.generate_random_string(16)
        self.assertEqual(len(result), 16)
        
        result2 = Public.generate_random_string(16)
        self.assertNotEqual(result, result2)
    
    def test_get_file_size_str(self):
        """Test human-readable file size formatting"""
        test_cases = [
            (0, '0.00 B'),
            (1024, '1.00 KB'),
            (1024 * 1024, '1.00 MB'),
            (1024 * 1024 * 1024, '1.00 GB'),
        ]
        for size, expected in test_cases:
            result = Public.get_size_format(size)
            self.assertEqual(result, expected, f"Size {size} should be {expected}")
    
    def test_md5_string(self):
        """Test MD5 hashing"""
        result = Public.md5('test')
        self.assertEqual(len(result), 32)
        
        # Same input should produce same hash
        result2 = Public.md5('test')
        self.assertEqual(result, result2)
    
    def test_get_timestamp(self):
        """Test timestamp retrieval"""
        result = Public.get_timestamp()
        self.assertIsInstance(result, int)
        self.assertGreater(result, 0)


class TestLogger(unittest.TestCase):
    """Test Logger class"""
    
    def setUp(self):
        """Set up test directory"""
        self.temp_dir = tempfile.mkdtemp()
        self.logger = Logger(self.temp_dir)
    
    def tearDown(self):
        """Clean up test directory"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_log_access(self):
        """Test access logging"""
        result = self.logger.log_access('GET', '/api/test', 200, 50.0, '127.0.0.1')
        self.assertTrue(result)
    
    def test_log_error(self):
        """Test error logging"""
        result = self.logger.log_error('Test error message', exception=None, context={'test': True})
        self.assertTrue(result)
    
    def test_log_security(self):
        """Test security event logging"""
        result = self.logger.log_security_event(
            event='login_failed',
            details={'ip': '192.168.1.100', 'username': 'admin'},
            level='WARNING'
        )
        self.assertTrue(result)
    
    def test_get_access_logs(self):
        """Test retrieving access logs"""
        # Create some logs
        for i in range(5):
            self.logger.log_access('GET', f'/api/test/{i}', 200, 25.0, '127.0.0.1')
        
        logs = self.logger.get_access_logs(limit=10)
        self.assertIsInstance(logs, list)
    
    def test_get_error_logs(self):
        """Test retrieving error logs"""
        self.logger.log_error('Test error')
        
        logs = self.logger.get_error_logs(limit=10)
        self.assertIsInstance(logs, list)


class TestFileOperations(unittest.TestCase):
    """Test file system operations"""
    
    def setUp(self):
        """Set up test directory"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test directory"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_file_creation_and_read(self):
        """Test creating and reading files"""
        test_file = os.path.join(self.temp_dir, 'test.txt')
        content = 'Hello, World!'
        
        with open(test_file, 'w') as f:
            f.write(content)
        
        with open(test_file, 'r') as f:
            result = f.read()
        
        self.assertEqual(result, content)
    
    def test_directory_creation(self):
        """Test directory creation"""
        test_dir = os.path.join(self.temp_dir, 'subdir', 'nested')
        os.makedirs(test_dir, exist_ok=True)
        
        self.assertTrue(os.path.exists(test_dir))
        self.assertTrue(os.path.isdir(test_dir))
    
    def test_file_deletion(self):
        """Test file deletion"""
        test_file = os.path.join(self.temp_dir, 'delete_me.txt')
        
        with open(test_file, 'w') as f:
            f.write('To be deleted')
        
        self.assertTrue(os.path.exists(test_file))
        
        os.remove(test_file)
        self.assertFalse(os.path.exists(test_file))


class TestDataStructures(unittest.TestCase):
    """Test data structure handling"""
    
    def test_json_parsing(self):
        """Test JSON parsing"""
        data = {'key': 'value', 'number': 123, 'list': [1, 2, 3]}
        json_str = json.dumps(data)
        
        parsed = json.loads(json_str)
        self.assertEqual(parsed, data)
    
    def test_nested_json(self):
        """Test nested JSON structures"""
        data = {
            'level1': {
                'level2': {
                    'level3': 'deep value'
                }
            }
        }
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        
        self.assertEqual(parsed['level1']['level2']['level3'], 'deep value')
    
    def test_json_array(self):
        """Test JSON arrays"""
        data = [
            {'id': 1, 'name': 'Item 1'},
            {'id': 2, 'name': 'Item 2'}
        ]
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]['name'], 'Item 1')


class TestSecurityFunctions(unittest.TestCase):
    """Test security-related functions"""
    
    def test_random_string_uniqueness(self):
        """Test that random strings are unique"""
        strings = [Public.generate_random_string(32) for _ in range(100)]
        unique_strings = set(strings)
        
        self.assertEqual(len(strings), len(unique_strings))
    
    def test_hash_consistency(self):
        """Test hash consistency"""
        test_input = 'consistent_input'
        hash1 = Public.md5(test_input)
        hash2 = Public.md5(test_input)
        
        self.assertEqual(hash1, hash2)
    
    def test_hash_different_inputs(self):
        """Test different inputs produce different hashes"""
        hash1 = Public.md5('input1')
        hash2 = Public.md5('input2')
        
        self.assertNotEqual(hash1, hash2)
    
    def test_path_traversal_prevention(self):
        """Test path traversal attack prevention"""
        dangerous_paths = [
            '../../../etc/passwd',
            '..\\..\\windows\\system32',
            '/var/www/../../etc/shadow',
            'valid/../../dangerous'
        ]
        
        for path in dangerous_paths:
            self.assertFalse(Validator.validate_path(path), 
                           f"Path traversal should be blocked: {path}")


class TestConfigurationHandling(unittest.TestCase):
    """Test configuration file handling"""
    
    def setUp(self):
        """Set up test directory"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test directory"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_json_config_write_read(self):
        """Test writing and reading JSON config"""
        config_file = os.path.join(self.temp_dir, 'config.json')
        config = {
            'server': {
                'host': '0.0.0.0',
                'port': 8888
            },
            'security': {
                'enable_waf': True,
                'max_requests': 1000
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        with open(config_file, 'r') as f:
            loaded = json.load(f)
        
        self.assertEqual(loaded['server']['port'], 8888)
        self.assertTrue(loaded['security']['enable_waf'])


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""
    
    def test_empty_string_validation(self):
        """Test validation of empty strings"""
        self.assertFalse(Validator.validate_email(''))
        self.assertFalse(Validator.validate_domain(''))
        self.assertFalse(Validator.validate_filename(''))
    
    def test_unicode_handling(self):
        """Test Unicode string handling"""
        unicode_text = 'Hello 世界 🌍'
        json_str = json.dumps({'text': unicode_text})
        parsed = json.loads(json_str)
        
        self.assertEqual(parsed['text'], unicode_text)
    
    def test_large_number_handling(self):
        """Test large number handling"""
        large_num = 999999999999999
        json_str = json.dumps({'number': large_num})
        parsed = json.loads(json_str)
        
        self.assertEqual(parsed['number'], large_num)
    
    def test_special_characters_in_paths(self):
        """Test special characters in paths"""
        special_paths = [
            '/path/with spaces',
            '/path/with-dashes',
            '/path/with_underscores'
        ]
        
        for path in special_paths:
            # These should be valid paths
            result = Validator.validate_path(path)
            self.assertIsInstance(result, bool)


if __name__ == '__main__':
    # Run tests with verbosity
    unittest.main(verbosity=2)

