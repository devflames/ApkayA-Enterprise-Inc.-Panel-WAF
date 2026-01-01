"""
ApkayA Enterprise Control Panel - Test Suite
Comprehensive testing for all implemented features

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import unittest
import json
import tempfile
import os
from pathlib import Path


class Phase1TestSuite(unittest.TestCase):
    """Complete test suite for Phase 1 features"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    # ========== VALIDATOR TESTS ==========
    
    def test_email_validation(self):
        """Test email validation"""
        from panel.class.validator import Validator
        
        self.assertTrue(Validator.validate_email('test@example.com'))
        self.assertTrue(Validator.validate_email('user+tag@domain.co.uk'))
        self.assertFalse(Validator.validate_email('invalid.email'))
        self.assertFalse(Validator.validate_email(''))
    
    def test_domain_validation(self):
        """Test domain validation"""
        from panel.class.validator import Validator
        
        self.assertTrue(Validator.validate_domain('example.com'))
        self.assertTrue(Validator.validate_domain('subdomain.example.co.uk'))
        self.assertFalse(Validator.validate_domain('invalid..domain'))
        self.assertFalse(Validator.validate_domain('-invalid.com'))
    
    def test_ip_validation(self):
        """Test IP validation"""
        from panel.class.validator import Validator
        
        self.assertTrue(Validator.validate_ip('192.168.1.1'))
        self.assertTrue(Validator.validate_ip('127.0.0.1'))
        self.assertFalse(Validator.validate_ip('256.1.1.1'))
        self.assertFalse(Validator.validate_ip('invalid.ip'))
    
    def test_port_validation(self):
        """Test port validation"""
        from panel.class.validator import Validator
        
        self.assertTrue(Validator.validate_port(8080))
        self.assertTrue(Validator.validate_port(443))
        self.assertFalse(Validator.validate_port(70000))
        self.assertFalse(Validator.validate_port(0))
    
    def test_path_validation(self):
        """Test path validation"""
        from panel.class.validator import Validator
        
        self.assertTrue(Validator.validate_path('/var/www/html'))
        self.assertFalse(Validator.validate_path('/var/www/../../../etc'))
        self.assertFalse(Validator.validate_path('/var/www\x00'))
    
    def test_filename_validation(self):
        """Test filename validation"""
        from panel.class.validator import Validator
        
        self.assertTrue(Validator.validate_filename('document.txt'))
        self.assertTrue(Validator.validate_filename('file-name_2024.pdf'))
        self.assertFalse(Validator.validate_filename('../etc/passwd'))
        self.assertFalse(Validator.validate_filename(''))
    
    def test_password_strength(self):
        """Test password strength validation"""
        from panel.class.validator import Validator
        
        valid, msg = Validator.validate_password_strength('StrongPass123!')
        self.assertTrue(valid)
        
        valid, msg = Validator.validate_password_strength('weak')
        self.assertFalse(valid)
    
    # ========== LOGGER TESTS ==========
    
    def test_logger_access_logging(self):
        """Test access logging"""
        from panel.class.logger import Logger
        
        logger = Logger(self.temp_dir)
        result = logger.log_access('GET', '/api/test', 200, 125.5, '127.0.0.1')
        self.assertTrue(result)
        
        logs = logger.get_access_logs(limit=10)
        self.assertGreater(len(logs), 0)
    
    def test_logger_audit_logging(self):
        """Test audit logging"""
        from panel.class.logger import Logger
        
        logger = Logger(self.temp_dir)
        result = logger.log_database_operation('add', 'test_db', {'user': 'admin'})
        self.assertTrue(result)
        
        logs = logger.get_audit_logs(limit=10)
        self.assertGreater(len(logs), 0)
    
    def test_logger_error_logging(self):
        """Test error logging"""
        from panel.class.logger import Logger
        
        logger = Logger(self.temp_dir)
        exc = ValueError("Test error")
        result = logger.log_error('Test error', exc)
        self.assertTrue(result)
        
        logs = logger.get_error_logs(limit=10)
        self.assertGreater(len(logs), 0)
    
    # ========== ERROR HANDLER TESTS ==========
    
    def test_error_formatting(self):
        """Test error formatting"""
        from panel.class.error_handler import ErrorHandler
        
        handler = ErrorHandler()
        error = handler.format_error(
            'VALIDATION_ERROR',
            'Field required',
            'username is required'
        )
        
        self.assertFalse(error['success'])
        self.assertEqual(error['error']['type'], 'VALIDATION_ERROR')
        self.assertIn('timestamp', error['error'])
    
    def test_validation_error_handling(self):
        """Test validation error handling"""
        from panel.class.error_handler import ErrorHandler
        
        handler = ErrorHandler()
        error = handler.handle_validation_error('email', 'Invalid email format')
        
        self.assertFalse(error['success'])
        self.assertIn('email', error['error']['message'])
    
    def test_not_found_error_handling(self):
        """Test not found error handling"""
        from panel.class.error_handler import ErrorHandler
        
        handler = ErrorHandler()
        error = handler.handle_not_found('User', '123')
        
        self.assertFalse(error['success'])
        self.assertIn('not found', error['error']['message'])
    
    def test_error_logging(self):
        """Test error logging in handler"""
        from panel.class.error_handler import ErrorHandler
        
        handler = ErrorHandler()
        exc = ValueError("Test exception")
        handler.log_error('TEST_ERROR', 'Test error', exc)
        
        logs = handler.get_error_log(limit=10)
        self.assertGreater(len(logs), 0)
    
    # ========== MONITORING TESTS ==========
    
    def test_monitoring_process_listing(self):
        """Test process monitoring"""
        from panel.class.monitoring import AdvancedMonitoring
        
        monitor = AdvancedMonitoring(self.temp_dir)
        cpu_procs = monitor.get_top_processes_by_cpu(top_n=3)
        memory_procs = monitor.get_top_processes_by_memory(top_n=3)
        
        self.assertIsInstance(cpu_procs, list)
        self.assertIsInstance(memory_procs, list)
    
    def test_monitoring_port_detection(self):
        """Test port monitoring"""
        from panel.class.monitoring import AdvancedMonitoring
        
        monitor = AdvancedMonitoring(self.temp_dir)
        ports = monitor.get_listening_ports()
        
        self.assertIsInstance(ports, list)
        # Should have at least some listening ports
        self.assertGreater(len(ports), 0)
    
    def test_monitoring_metrics_collection(self):
        """Test metrics collection"""
        from panel.class.monitoring import AdvancedMonitoring
        
        monitor = AdvancedMonitoring(self.temp_dir)
        metrics = monitor.collect_system_metrics()
        
        self.assertIn('timestamp', metrics)
        self.assertIn('cpu', metrics)
        self.assertIn('memory', metrics)
        self.assertIn('disk', metrics)
    
    def test_monitoring_network_info(self):
        """Test network monitoring"""
        from panel.class.monitoring import AdvancedMonitoring
        
        monitor = AdvancedMonitoring(self.temp_dir)
        interfaces = monitor.get_network_interfaces_detailed()
        
        self.assertIsInstance(interfaces, dict)
    
    # ========== INTEGRATION TESTS ==========
    
    def test_validator_integration(self):
        """Test validator with multiple inputs"""
        from panel.class.validator import Validator
        
        test_data = {
            'email': 'admin@example.com',
            'domain': 'example.com',
            'port': 8080,
            'path': '/var/www/html',
            'filename': 'index.php'
        }
        
        self.assertTrue(Validator.validate_email(test_data['email']))
        self.assertTrue(Validator.validate_domain(test_data['domain']))
        self.assertTrue(Validator.validate_port(test_data['port']))
        self.assertTrue(Validator.validate_path(test_data['path']))
        self.assertTrue(Validator.validate_filename(test_data['filename']))
    
    def test_logging_and_error_handling_integration(self):
        """Test logging with error handling"""
        from panel.class.logger import Logger
        from panel.class.error_handler import ErrorHandler
        
        logger = Logger(self.temp_dir)
        handler = ErrorHandler()
        
        # Log an error
        exc = Exception("Test exception")
        handler.log_error('TEST', 'Test error', exc)
        logger.log_error('Test error', exc)
        
        # Verify logging
        error_logs = logger.get_error_logs(limit=10)
        self.assertGreater(len(error_logs), 0)


class Phase1FeatureCompleteness(unittest.TestCase):
    """Verify all Phase 1 features are implemented"""
    
    def test_system_features_exist(self):
        """Verify system monitoring features"""
        from panel.class.system import system
        from panel.class.monitoring import monitoring
        
        self.assertIsNotNone(system.get_cpu_info())
        self.assertIsNotNone(system.get_memory_info())
        self.assertIsNotNone(system.get_disk_info())
        self.assertTrue(len(monitoring.get_listening_ports()) >= 0)
    
    def test_database_features_exist(self):
        """Verify database management features"""
        from panel.class.database import database
        
        self.assertIsNotNone(database.list_mysql())
        self.assertIsNotNone(database.list_redis())
    
    def test_file_manager_features_exist(self):
        """Verify file manager features"""
        from panel.class.files import file_manager
        
        # Verify methods exist
        self.assertTrue(hasattr(file_manager, 'list_files'))
        self.assertTrue(hasattr(file_manager, 'read_file'))
        self.assertTrue(hasattr(file_manager, 'write_file'))
        self.assertTrue(hasattr(file_manager, 'delete_file'))
    
    def test_waf_features_exist(self):
        """Verify WAF features"""
        from panel.class.waf import waf_client, waf_config
        
        self.assertIsNotNone(waf_client)
        self.assertIsNotNone(waf_config)
    
    def test_logging_system_exists(self):
        """Verify logging system"""
        from panel.class.logger import logger
        
        self.assertIsNotNone(logger)
        self.assertTrue(hasattr(logger, 'log_access'))
        self.assertTrue(hasattr(logger, 'log_audit'))
        self.assertTrue(hasattr(logger, 'get_audit_logs'))
    
    def test_validation_system_exists(self):
        """Verify validation system"""
        from panel.class.validator import Validator
        
        self.assertTrue(hasattr(Validator, 'validate_email'))
        self.assertTrue(hasattr(Validator, 'validate_domain'))
        self.assertTrue(hasattr(Validator, 'validate_ip'))
        self.assertTrue(hasattr(Validator, 'validate_path'))
    
    def test_error_handling_system_exists(self):
        """Verify error handling system"""
        from panel.class.error_handler import error_handler
        
        self.assertIsNotNone(error_handler)
        self.assertTrue(hasattr(error_handler, 'format_error'))
        self.assertTrue(hasattr(error_handler, 'log_error'))
    
    def test_monitoring_system_exists(self):
        """Verify monitoring system"""
        from panel.class.monitoring import monitoring
        
        self.assertIsNotNone(monitoring)
        self.assertTrue(hasattr(monitoring, 'collect_system_metrics'))
        self.assertTrue(hasattr(monitoring, 'get_top_processes_by_cpu'))
        self.assertTrue(hasattr(monitoring, 'get_listening_ports'))


if __name__ == '__main__':
    # Run tests
    unittest.main()
