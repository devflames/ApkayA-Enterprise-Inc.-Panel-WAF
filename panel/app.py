"""
Apkaya Panel WAF - Main Flask Application

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source

A modern server control panel with integrated WAF protection.
"""

from flask import Flask, render_template, jsonify, request, session
from flask_socketio import SocketIO
import os
import json
import time
from functools import wraps
from .modules.public import Public, public
from .modules.database import database
from .modules.sites import sites
from .modules.files import file_manager
from .modules.system import system
from .modules.waf import waf_client, waf_config
from .modules.validator import Validator
from .modules.logger import logger
from .modules.error_handler import error_handler
from .modules.monitoring import monitoring
from .modules.auth import auth_manager
from .modules.authorization import login_required, permission_required
from .modules.api_security import check_rate_limit
from .modules.ssl_manager import ssl_manager
from .modules.firewall import firewall_manager
from .modules.backup import backup_manager
from .modules.cron import cron_manager
from .modules.webserver import webserver_manager
from .modules.php_manager import php_manager
from .modules.ftp_manager import ftp_manager
from .modules.docker_manager import docker_manager


def create_app():
    """Create and configure Flask application"""
    from pathlib import Path
    
    app = Flask(__name__)
    
    # Load or generate secret key from config
    secret_key_file = Path('config/app.secret')
    if secret_key_file.exists():
        app.secret_key = secret_key_file.read_text().strip()
    else:
        app.secret_key = Public.generate_random_string(32)
        secret_key_file.parent.mkdir(parents=True, exist_ok=True)
        secret_key_file.write_text(app.secret_key)
        try:
            secret_key_file.chmod(0o600)
        except:
            pass
    
    # Security Configuration
    app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JS access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF protection
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours
    
    # Configuration
    app.config['JSON_SORT_KEYS'] = False
    app.config['JSON_AS_ASCII'] = False
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload
    
    # Initialize SocketIO for real-time updates
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode='threading',
        logger=False,
        engineio_logger=False,
        ping_timeout=60,
        ping_interval=25,
        transports=['websocket', 'http_long_polling']  # Prioritize websocket
    )
    
    # Request/Response logging middleware
    @app.before_request
    def log_request():
        request.start_time = time.time()
    
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' fonts.googleapis.com cdnjs.cloudflare.com; font-src 'self' fonts.gstatic.com cdnjs.cloudflare.com"
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        if hasattr(request, 'start_time'):
            elapsed = (time.time() - request.start_time) * 1000
            logger.log_access(
                request.method,
                request.path,
                response.status_code,
                elapsed,
                request.remote_addr
            )
        return response

    # Helper: extract bearer token
    def _get_auth_token():
        auth_header = request.headers.get('Authorization', '')
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            return parts[1]
        return None

    # Helper: require a valid session and return session data
    def _require_session():
        token = _get_auth_token()
        if not token:
            return None, ('Authentication required', 401)
        session_result = auth_manager.validate_session(token)
        if not session_result.get('valid'):
            message = session_result.get('message', 'Invalid session')
            return None, (message, 401)
        session_result['token'] = token
        return session_result, None

    # ========== SYSTEM ROUTES ==========
    
    @app.route('/api', methods=['GET'])
    def api_root():
        """API root endpoint - returns documentation"""
        return jsonify({
            'success': True,
            'message': 'Apkaya Panel WAF API',
            'version': '1.0.0',
            'documentation': '/api/docs',
            'modules': {
                'auth': '/api/auth',
                'sites': '/api/sites',
                'database': '/api/database',
                'files': '/api/files',
                'system': '/api/system',
                'firewall': '/api/firewall',
                'waf': '/api/waf',
                'backup': '/api/backup',
                'cron': '/api/cron',
                'php': '/api/php',
                'ftp': '/api/ftp'
            },
            'status': 'running',
            'api_endpoints': 174
        })

    # ========== AUTH ROUTES ==========

    @app.route('/api/auth/register', methods=['POST'])
    @check_rate_limit('guest')
    def auth_register():
        """Register a new user"""
        data = request.get_json() or {}
        username = (data.get('username') or '').strip()
        email = (data.get('email') or '').strip()
        password = data.get('password') or ''

        if not username or not email or not password:
            return jsonify(Public.return_msg(False, 'Username, email, and password are required')), 400

        result = auth_manager.register(username, email, password)
        status = 200 if result.get('success') else 400
        return jsonify(result), status

    @app.route('/api/auth/login', methods=['POST'])
    @check_rate_limit('guest')
    def auth_login():
        """Authenticate user and return session or 2FA challenge"""
        data = request.get_json() or {}
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''

        if not username or not password:
            return jsonify(Public.return_msg(False, 'Username and password are required')), 400

        result = auth_manager.login(username, password)
        status = 200 if result.get('success') else 401
        return jsonify(result), status

    @app.route('/api/auth/logout', methods=['POST'])
    @check_rate_limit('user')
    def auth_logout():
        """Terminate current session"""
        token = _get_auth_token()
        if not token:
            return jsonify(Public.return_msg(False, 'Authentication required')), 401

        result = auth_manager.logout(token)
        status = 200 if result.get('success') else 401
        return jsonify(result), status

    @app.route('/api/auth/verify', methods=['GET'])
    @check_rate_limit('user')
    def auth_verify():
        """Validate session token and return user info"""
        session_data, error = _require_session()
        if error:
            message, code = error
            return jsonify(Public.return_msg(False, message)), code

        user = auth_manager.get_user(session_data['user_id'])
        return jsonify(Public.return_data(True, {
            'user': user,
            'session': {
                'user_id': session_data['user_id'],
                'username': session_data['username'],
                'roles': session_data.get('roles', []),
                'token': session_data.get('token')
            }
        }))

    @app.route('/api/users/profile', methods=['GET'])
    @check_rate_limit('user')
    def get_profile():
        """Get current user's profile"""
        session_data, error = _require_session()
        if error:
            message, code = error
            return jsonify(Public.return_msg(False, message)), code

        user = auth_manager.get_user(session_data['user_id'])
        if not user:
            return jsonify(Public.return_msg(False, 'User not found')), 404

        user['roles'] = session_data.get('roles', [])
        return jsonify(Public.return_data(True, user))

    @app.route('/api/users/profile', methods=['PUT'])
    @check_rate_limit('user')
    def update_profile():
        """Update current user's profile (email only)"""
        session_data, error = _require_session()
        if error:
            message, code = error
            return jsonify(Public.return_msg(False, message)), code

        data = request.get_json() or {}
        updates = {}

        if 'email' in data:
            email = (data.get('email') or '').strip()
            if not email:
                return jsonify(Public.return_msg(False, 'Email is required')), 400
            updates['email'] = email

        if not updates:
            return jsonify(Public.return_msg(False, 'No valid fields to update')), 400

        result = auth_manager.update_user(session_data['user_id'], updates)
        status = 200 if result.get('success') else 400
        return jsonify(result), status
    
    # ========== SYSTEM ROUTES ==========
    
    @app.route('/api/system/info', methods=['GET'])
    @permission_required('system.read')
    @check_rate_limit('user')
    def get_system_info():
        """Get system information"""
        return jsonify(system.get_full_system_info())
    
    @app.route('/api/system/status', methods=['GET'])
    @permission_required('system.read')
    def get_system_status():
        """Get system status"""
        cpu = system.get_cpu_info()
        memory = system.get_memory_info()
        return jsonify(Public.return_data(True, {
            'cpu_usage': cpu['usage'],
            'memory_usage': memory['percent'],
            'disk': system.get_disk_info(),
            'uptime': system.get_system_uptime()
        }))
    
    @app.route('/api/system/processes/top-cpu', methods=['GET'])
    @permission_required('system.read')
    def get_top_cpu_processes():
        """Get top processes by CPU"""
        top_n = request.args.get('limit', 5, type=int)
        processes = monitoring.get_top_processes_by_cpu(top_n)
        return jsonify(Public.return_data(True, processes))
    
    @app.route('/api/system/processes/top-memory', methods=['GET'])
    @permission_required('system.read')
    def get_top_memory_processes():
        """Get top processes by memory"""
        top_n = request.args.get('limit', 5, type=int)
        processes = monitoring.get_top_processes_by_memory(top_n)
        return jsonify(Public.return_data(True, processes))
    
    @app.route('/api/system/processes/<int:pid>', methods=['GET'])
    @permission_required('system.read')
    def get_process_info(pid):
        """Get process information"""
        info = monitoring.get_process_details(pid)
        if info:
            return jsonify(Public.return_data(True, info))
        return jsonify(Public.return_msg(False, f'Process {pid} not found'))
    
    @app.route('/api/system/ports/listening', methods=['GET'])
    @permission_required('system.read')
    def get_listening_ports():
        """Get listening ports"""
        ports = monitoring.get_listening_ports()
        return jsonify(Public.return_data(True, ports))
    
    @app.route('/api/system/ports/<int:port>', methods=['GET'])
    @permission_required('system.read')
    def get_port_details(port):
        """Get port information"""
        info = monitoring.get_port_info(port)
        if info:
            return jsonify(Public.return_data(True, info))
        return jsonify(Public.return_msg(False, f'Port {port} not found'))
    
    @app.route('/api/system/network', methods=['GET'])
    @permission_required('system.read')
    def get_network_details():
        """Get network interface details"""
        interfaces = monitoring.get_network_interfaces_detailed()
        return jsonify(Public.return_data(True, interfaces))
    
    @app.route('/api/system/disk/io', methods=['GET'])
    @permission_required('system.read')
    def get_disk_io():
        """Get disk I/O statistics"""
        stats = monitoring.get_disk_io_stats()
        return jsonify(Public.return_data(True, stats))
    
    @app.route('/api/system/disk/partitions', methods=['GET'])
    @permission_required('system.read')
    def get_disk_partitions():
        """Get partition details"""
        partitions = monitoring.get_partition_usage_detailed()
        return jsonify(Public.return_data(True, partitions))
    
    @app.route('/api/system/metrics', methods=['GET'])
    @permission_required('system.read')
    def get_system_metrics():
        """Get comprehensive system metrics"""
        metrics = monitoring.collect_system_metrics()
        return jsonify(Public.return_data(True, metrics))
    
    @app.route('/api/system/metrics/history', methods=['GET'])
    @permission_required('system.read')
    def get_metrics_history():
        """Get metrics history"""
        limit = request.args.get('limit', 100, type=int)
        history = monitoring.get_metrics_history(limit)
        return jsonify(Public.return_data(True, history))
    
    # ========== DATABASE ROUTES ==========
    
    @app.route('/api/database/list', methods=['GET'])
    @permission_required('database.read')
    @check_rate_limit('user')
    def list_databases():
        """List all databases"""
        db_type = request.args.get('type', 'all')
        
        if db_type == 'mysql':
            return jsonify(database.list_mysql())
        elif db_type == 'redis':
            return jsonify(database.list_redis())
        else:
            return jsonify(database.get_database_stats())
    
    @app.route('/api/database/add', methods=['POST'])
    @permission_required('database.create')
    def add_database():
        """Add database"""
        data = request.get_json()
        db_type = data.get('type', 'mysql')
        
        if db_type == 'mysql':
            return jsonify(database.add_mysql(
                data.get('name'),
                data.get('host'),
                data.get('user'),
                data.get('password'),
                data.get('port', 3306)
            ))
        elif db_type == 'redis':
            return jsonify(database.add_redis(
                data.get('name'),
                data.get('host'),
                data.get('port', 6379),
                data.get('password', '')
            ))
        
        return jsonify(Public.return_msg(False, 'Unknown database type'))
    
    @app.route('/api/database/delete', methods=['POST'])
    @permission_required('database.delete')
    def delete_database():
        """Delete database"""
        data = request.get_json()
        db_type = data.get('type', 'mysql')
        db_id = data.get('id')
        
        if db_type == 'mysql':
            return jsonify(database.delete_mysql(db_id))
        elif db_type == 'redis':
            return jsonify(database.delete_redis(db_id))
        
        return jsonify(Public.return_msg(False, 'Unknown database type'))
    
    @app.route('/api/database/info', methods=['GET'])
    @permission_required('database.read')
    def get_database_info():
        """Get database information"""
        db_type = request.args.get('type', 'mysql')
        db_id = int(request.args.get('id', 0))
        
        if db_type == 'mysql':
            return jsonify(database.get_mysql_info(db_id))
        elif db_type == 'redis':
            return jsonify(database.get_redis_info(db_id))
        
        return jsonify(Public.return_msg(False, 'Unknown database type'))
    
    # ========== SITE ROUTES ==========
    
    @app.route('/api/sites/list', methods=['GET'])
    @permission_required('sites.read')
    @check_rate_limit('user')
    def list_sites():
        """List all websites"""
        return jsonify(sites.list_sites())
    
    @app.route('/api/sites/add', methods=['POST'])
    @permission_required('sites.create')
    def add_site():
        """Add website"""
        data = request.get_json()
        return jsonify(sites.add_site(
            data.get('domain'),
            data.get('root_path'),
            data.get('php_version', '8.0'),
            data.get('server_type', 'nginx'),
            data.get('ssl', False)
        ))
    
    @app.route('/api/sites/delete', methods=['POST'])
    @permission_required('sites.delete')
    def delete_site():
        """Delete website"""
        data = request.get_json()
        return jsonify(sites.delete_site(
            data.get('id'),
            data.get('remove_files', False)
        ))
    
    @app.route('/api/sites/info', methods=['GET'])
    @permission_required('sites.read')
    def get_site_info():
        """Get site information"""
        site_id = int(request.args.get('id', 0))
        return jsonify(sites.get_site(site_id))
    
    @app.route('/api/sites/update', methods=['POST'])
    @permission_required('sites.update')
    def update_site():
        """Update site"""
        data = request.get_json()
        return jsonify(sites.update_site(
            data.get('id'),
            data.get('updates', {})
        ))
    
    @app.route('/api/sites/stats', methods=['GET'])
    @permission_required('sites.read')
    def get_site_stats():
        """Get site statistics"""
        return jsonify(sites.get_site_stats())
    
    # ========== FILE MANAGER ROUTES ==========
    
    @app.route('/api/files/list', methods=['POST'])
    @permission_required('files.read')
    @check_rate_limit('user')
    def list_files():
        """List directory contents"""
        data = request.get_json()
        return jsonify(file_manager.list_files(data.get('path', '')))
    
    @app.route('/api/files/read', methods=['POST'])
    @permission_required('files.read')
    def read_file():
        """Read file"""
        data = request.get_json()
        return jsonify(file_manager.read_file(data.get('path')))
    
    @app.route('/api/files/write', methods=['POST'])
    @permission_required('files.update')
    def write_file():
        """Write file"""
        data = request.get_json()
        return jsonify(file_manager.write_file(
            data.get('path'),
            data.get('content', '')
        ))
    
    @app.route('/api/files/delete', methods=['POST'])
    @permission_required('files.delete')
    def delete_file():
        """Delete file"""
        data = request.get_json()
        return jsonify(file_manager.delete_file(data.get('path')))
    
    @app.route('/api/files/mkdir', methods=['POST'])
    @permission_required('files.create')
    def mkdir():
        """Create directory"""
        data = request.get_json()
        return jsonify(file_manager.create_directory(data.get('path')))
    
    @app.route('/api/files/copy', methods=['POST'])
    @permission_required('files.update')
    def copy_file():
        """Copy file"""
        data = request.get_json()
        return jsonify(file_manager.copy_file(
            data.get('source'),
            data.get('destination')
        ))
    
    @app.route('/api/files/move', methods=['POST'])
    @permission_required('files.update')
    def move_file():
        """Move file"""
        data = request.get_json()
        return jsonify(file_manager.move_file(
            data.get('source'),
            data.get('destination')
        ))
    
    @app.route('/api/files/compress', methods=['POST'])
    @permission_required('files.update')
    def compress_file():
        """Compress file"""
        data = request.get_json()
        return jsonify(file_manager.compress_file(
            data.get('source'),
            data.get('output')
        ))
    
    @app.route('/api/files/extract', methods=['POST'])
    @permission_required('files.update')
    def extract_file():
        """Extract file"""
        data = request.get_json()
        return jsonify(file_manager.extract_file(
            data.get('archive'),
            data.get('destination')
        ))
    
    @app.route('/api/files/info', methods=['GET'])
    @permission_required('files.read')
    def get_file_info():
        """Get file info"""
        path = request.args.get('path', '')
        return jsonify(file_manager.get_file_info(path))
    
    # ========== LOGGING & AUDIT ROUTES ==========
    
    @app.route('/api/logs/access', methods=['GET'])
    @permission_required('logs.read')
    def get_access_logs():
        """Get access logs"""
        limit = request.args.get('limit', 100, type=int)
        status = request.args.get('status', None, type=int)
        logs = logger.get_access_logs(limit, status)
        return jsonify(Public.return_data(True, logs))
    
    @app.route('/api/logs/audit', methods=['GET'])
    @permission_required('audit.read')
    def get_audit_logs():
        """Get audit logs"""
        limit = request.args.get('limit', 100, type=int)
        filter_type = request.args.get('type', None)
        logs = logger.get_audit_logs(limit, filter_type)
        return jsonify(Public.return_data(True, logs))
    
    @app.route('/api/logs/errors', methods=['GET'])
    @permission_required('logs.read')
    def get_error_logs():
        """Get error logs"""
        limit = request.args.get('limit', 100, type=int)
        logs = logger.get_error_logs(limit)
        return jsonify(Public.return_data(True, logs))
    
    @app.route('/api/logs/system', methods=['GET'])
    @permission_required('logs.read')
    def get_system_logs():
        """Get system logs"""
        limit = request.args.get('limit', 100, type=int)
        logs = logger.get_error_logs(limit)  # Using error logs for system logs
        return jsonify(Public.return_data(True, logs))
    
    @app.route('/api/logs/clear', methods=['POST'])
    @permission_required('settings.update')
    def clear_logs():
        """Clear old logs"""
        data = request.get_json()
        days = data.get('days', 30)
        success = logger.clear_old_logs(days)
        if success:
            logger.log_system_event(f'Logs older than {days} days cleared')
            return jsonify(Public.return_msg(True, f'Cleared logs older than {days} days'))
        return jsonify(Public.return_msg(False, 'Failed to clear logs'))
    
    @app.route('/api/waf/status', methods=['GET'])
    @permission_required('waf.read')
    def get_waf_status():
        """Get WAF status"""
        return jsonify(waf_client.get_status())
    
    @app.route('/api/waf/start', methods=['POST'])
    @permission_required('waf.update')
    def start_waf():
        """Start WAF"""
        return jsonify(waf_client.start_service())
    
    @app.route('/api/waf/stop', methods=['POST'])
    @permission_required('waf.update')
    def stop_waf():
        """Stop WAF"""
        return jsonify(waf_client.stop_service())
    
    @app.route('/api/waf/restart', methods=['POST'])
    @permission_required('waf.update')
    def restart_waf():
        """Restart WAF"""
        return jsonify(waf_client.restart_service())
    
    @app.route('/api/waf/config', methods=['GET'])
    @permission_required('waf.read')
    def get_waf_config():
        """Get WAF configuration"""
        return jsonify(waf_config.get_config())
    
    @app.route('/api/waf/config/update', methods=['POST'])
    @permission_required('waf.update')
    def update_waf_config():
        """Update WAF configuration"""
        data = request.get_json()
        return jsonify(waf_config.update_config(data))
    
    @app.route('/api/waf/logs', methods=['POST'])
    @permission_required('waf.read')
    def get_waf_logs():
        """Get WAF logs"""
        data = request.get_json()
        return jsonify(waf_client.get_logs(
            data.get('limit', 100),
            data.get('offset', 0)
        ))
    
    @app.route('/api/waf/stats', methods=['GET'])
    @permission_required('waf.read')
    def get_waf_stats():
        """Get WAF statistics"""
        days = request.args.get('days', 7, type=int)
        return jsonify(waf_client.get_attack_stats(days))
    
    @app.route('/api/waf/rules', methods=['GET'])
    @permission_required('waf.read')
    def get_waf_rules():
        """Get WAF rules"""
        return jsonify(waf_client.get_rules())
    
    @app.route('/api/waf/test', methods=['POST'])
    @permission_required('waf.update')
    def test_waf_payload():
        """Test WAF payload"""
        data = request.get_json()
        return jsonify(waf_client.test_payload(data.get('payload', '')))
    
    @app.route('/api/waf/whitelist/add', methods=['POST'])
    @permission_required('waf.update')
    def waf_whitelist_add():
        """Add IP to WAF whitelist"""
        data = request.get_json()
        return jsonify(waf_client.whitelist_add(data.get('ip')))
    
    @app.route('/api/waf/blacklist/add', methods=['POST'])
    @permission_required('waf.update')
    def waf_blacklist_add():
        """Add IP to WAF blacklist"""
        data = request.get_json()
        return jsonify(waf_client.blacklist_add(
            data.get('ip'),
            data.get('duration')
        ))
    
    # ========== WEB UI ROUTES ==========
    
    @app.route('/', methods=['GET'])
    def dashboard():
        """Dashboard"""
        return render_template('index.html')
    
    @app.route('/sites', methods=['GET'])
    def sites_page():
        """Sites page"""
        return render_template('sites/index.html')
    
    @app.route('/database', methods=['GET'])
    def database_page():
        """Database page"""
        return render_template('database/index.html')
    
    @app.route('/files', methods=['GET'])
    def files_page():
        """File manager page"""
        return render_template('files/index.html')
    
    @app.route('/waf', methods=['GET'])
    def waf_page():
        """WAF page"""
        return render_template('waf/index.html')
    
    @app.route('/waf/logs', methods=['GET'])
    def waf_logs_page():
        """WAF logs page"""
        return render_template('waf/logs.html')
    
    @app.route('/waf/rules', methods=['GET'])
    def waf_rules_page():
        """WAF rules page"""
        return render_template('waf/rules.html')
    
    @app.route('/system', methods=['GET'])
    def system_page():
        """System page"""
        return render_template('system/index.html')
    
    # ========== SSL/CERTIFICATE ROUTES ==========
    
    @app.route('/api/ssl/certificates', methods=['GET'])
    @permission_required('sites.read')
    @check_rate_limit('user')
    def ssl_list_certificates():
        """List all SSL certificates"""
        return jsonify(ssl_manager.list_certificates())
    
    @app.route('/api/ssl/certificates/<domain>', methods=['GET'])
    @permission_required('sites.read')
    @check_rate_limit('user')
    def ssl_get_certificate(domain):
        """Get certificate details"""
        return jsonify(ssl_manager.get_certificate(domain))
    
    @app.route('/api/ssl/certificates', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def ssl_request_certificate():
        """Request Let's Encrypt certificate"""
        data = request.get_json() or {}
        domain = data.get('domain', '').strip()
        if not domain:
            return jsonify(Public.return_msg(False, 'Domain required')), 400
        
        result = ssl_manager.request_certificate(
            domain,
            san_domains=data.get('san_domains', []),
            email=data.get('email'),
            force=data.get('force', False)
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/ssl/certificates/<domain>/upload', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def ssl_upload_certificate(domain):
        """Upload custom certificate"""
        data = request.get_json() or {}
        result = ssl_manager.upload_certificate(
            domain,
            data.get('certificate', ''),
            data.get('private_key', ''),
            data.get('chain', '')
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/ssl/certificates/<domain>/renew', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def ssl_renew_certificate(domain):
        """Renew certificate"""
        return jsonify(ssl_manager.renew_certificate(domain))
    
    @app.route('/api/ssl/certificates/<domain>', methods=['DELETE'])
    @permission_required('sites.delete')
    @check_rate_limit('user')
    def ssl_delete_certificate(domain):
        """Delete certificate"""
        return jsonify(ssl_manager.delete_certificate(domain))
    
    @app.route('/api/ssl/self-signed', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def ssl_generate_self_signed():
        """Generate self-signed certificate"""
        data = request.get_json() or {}
        domain = data.get('domain', '').strip()
        if not domain:
            return jsonify(Public.return_msg(False, 'Domain required')), 400
        
        result = ssl_manager.generate_self_signed(
            domain,
            days=data.get('days', 365)
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/ssl/renewals', methods=['GET'])
    @permission_required('sites.read')
    @check_rate_limit('user')
    def ssl_check_renewals():
        """Check certificates due for renewal"""
        return jsonify(ssl_manager.check_renewals())
    
    @app.route('/api/ssl/config', methods=['GET'])
    @permission_required('system.read')
    @check_rate_limit('user')
    def ssl_get_config():
        """Get SSL configuration"""
        return jsonify(ssl_manager.get_config())
    
    @app.route('/api/ssl/config', methods=['PUT'])
    @permission_required('system.write')
    @check_rate_limit('user')
    def ssl_update_config():
        """Update SSL configuration"""
        data = request.get_json() or {}
        return jsonify(ssl_manager.update_config(data))
    
    # ========== FIREWALL ROUTES ==========
    
    @app.route('/api/firewall/status', methods=['GET'])
    @permission_required('security.read')
    @check_rate_limit('user')
    def firewall_status():
        """Get firewall status"""
        return jsonify(firewall_manager.get_status())
    
    @app.route('/api/firewall/enable', methods=['POST'])
    @permission_required('security.write')
    @check_rate_limit('user')
    def firewall_enable():
        """Enable firewall"""
        return jsonify(firewall_manager.enable())
    
    @app.route('/api/firewall/disable', methods=['POST'])
    @permission_required('security.write')
    @check_rate_limit('user')
    def firewall_disable():
        """Disable firewall"""
        return jsonify(firewall_manager.disable())
    
    @app.route('/api/firewall/ports', methods=['GET'])
    @permission_required('security.read')
    @check_rate_limit('user')
    def firewall_list_ports():
        """List open ports"""
        return jsonify(firewall_manager.list_ports())
    
    @app.route('/api/firewall/ports', methods=['POST'])
    @permission_required('security.write')
    @check_rate_limit('user')
    def firewall_open_port():
        """Open a port"""
        data = request.get_json() or {}
        port = data.get('port')
        if not port:
            return jsonify(Public.return_msg(False, 'Port required')), 400
        
        result = firewall_manager.open_port(
            int(port),
            protocol=data.get('protocol', 'tcp'),
            description=data.get('description', '')
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/firewall/ports/<int:port>', methods=['DELETE'])
    @permission_required('security.write')
    @check_rate_limit('user')
    def firewall_close_port(port):
        """Close a port"""
        protocol = request.args.get('protocol', 'tcp')
        return jsonify(firewall_manager.close_port(port, protocol))
    
    @app.route('/api/firewall/blacklist', methods=['GET'])
    @permission_required('security.read')
    @check_rate_limit('user')
    def firewall_list_blacklist():
        """List blocked IPs"""
        return jsonify(firewall_manager.list_blacklist())
    
    @app.route('/api/firewall/blacklist', methods=['POST'])
    @permission_required('security.write')
    @check_rate_limit('user')
    def firewall_block_ip():
        """Block an IP"""
        data = request.get_json() or {}
        ip = data.get('ip', '').strip()
        if not ip:
            return jsonify(Public.return_msg(False, 'IP address required')), 400
        
        result = firewall_manager.block_ip(ip, reason=data.get('reason', ''))
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/firewall/blacklist/<ip>', methods=['DELETE'])
    @permission_required('security.write')
    @check_rate_limit('user')
    def firewall_unblock_ip(ip):
        """Unblock an IP"""
        return jsonify(firewall_manager.unblock_ip(ip))
    
    @app.route('/api/firewall/whitelist', methods=['GET'])
    @permission_required('security.read')
    @check_rate_limit('user')
    def firewall_list_whitelist():
        """List whitelisted IPs"""
        return jsonify(firewall_manager.list_whitelist())
    
    @app.route('/api/firewall/whitelist', methods=['POST'])
    @permission_required('security.write')
    @check_rate_limit('user')
    def firewall_whitelist_ip():
        """Whitelist an IP"""
        data = request.get_json() or {}
        ip = data.get('ip', '').strip()
        if not ip:
            return jsonify(Public.return_msg(False, 'IP address required')), 400
        
        return jsonify(firewall_manager.whitelist_ip(ip, data.get('description', '')))
    
    @app.route('/api/firewall/rules', methods=['GET'])
    @permission_required('security.read')
    @check_rate_limit('user')
    def firewall_list_rules():
        """List firewall rules"""
        return jsonify(firewall_manager.list_rules())
    
    @app.route('/api/firewall/rules', methods=['POST'])
    @permission_required('security.write')
    @check_rate_limit('user')
    def firewall_add_rule():
        """Add firewall rule"""
        data = request.get_json() or {}
        return jsonify(firewall_manager.add_rule(data))
    
    @app.route('/api/firewall/rules/<int:rule_id>', methods=['DELETE'])
    @permission_required('security.write')
    @check_rate_limit('user')
    def firewall_remove_rule(rule_id):
        """Remove firewall rule"""
        return jsonify(firewall_manager.remove_rule(rule_id))
    
    # ========== BACKUP ROUTES ==========
    
    @app.route('/api/backup', methods=['GET'])
    def backup_root():
        """Backup API root - returns available endpoints"""
        return jsonify({
            'success': True,
            'message': 'Backup API endpoints',
            'endpoints': {
                'GET /api/backup/list': 'List all backups',
                'GET /api/backup/<id>': 'Get specific backup',
                'POST /api/backup/site': 'Create website backup',
                'POST /api/backup/database': 'Create database backup',
                'POST /api/backup/directory': 'Create directory backup',
                'POST /api/backup/<id>/restore': 'Restore backup',
                'DELETE /api/backup/<id>': 'Delete backup',
                'GET /api/backup/schedules': 'List backup schedules',
                'POST /api/backup/schedules': 'Create backup schedule',
                'DELETE /api/backup/schedules/<id>': 'Delete backup schedule',
                'GET /api/backup/statistics': 'Get backup statistics'
            }
        })
    
    @app.route('/api/backup/list', methods=['GET'])
    @permission_required('backup.read')
    @check_rate_limit('user')
    def backup_list():
        """List all backups"""
        backup_type = request.args.get('type')
        limit = int(request.args.get('limit', 50))
        return jsonify(backup_manager.list_backups(backup_type, limit))
    
    @app.route('/api/backup/<int:backup_id>', methods=['GET'])
    @permission_required('backup.read')
    @check_rate_limit('user')
    def backup_get(backup_id):
        """Get backup details"""
        return jsonify(backup_manager.get_backup(backup_id))
    
    @app.route('/api/backup/site', methods=['POST'])
    @permission_required('backup.write')
    @check_rate_limit('operator')
    def backup_create_site():
        """Create site backup"""
        data = request.get_json() or {}
        site_name = data.get('site_name', '').strip()
        site_path = data.get('site_path', '').strip()
        if not site_name or not site_path:
            return jsonify(Public.return_msg(False, 'Site name and path required')), 400
        
        result = backup_manager.backup_site(
            site_name, site_path,
            include_db=data.get('include_db', True),
            db_name=data.get('db_name')
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/backup/database', methods=['POST'])
    @permission_required('backup.write')
    @check_rate_limit('operator')
    def backup_create_database():
        """Create database backup"""
        data = request.get_json() or {}
        db_name = data.get('db_name', '').strip()
        if not db_name:
            return jsonify(Public.return_msg(False, 'Database name required')), 400
        
        result = backup_manager.backup_database(
            db_name,
            db_type=data.get('db_type', 'mysql'),
            host=data.get('host', 'localhost'),
            port=data.get('port', 3306),
            user=data.get('user', 'root'),
            password=data.get('password', '')
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/backup/directory', methods=['POST'])
    @permission_required('backup.write')
    @check_rate_limit('operator')
    def backup_create_directory():
        """Create directory backup"""
        data = request.get_json() or {}
        path = data.get('path', '').strip()
        if not path:
            return jsonify(Public.return_msg(False, 'Path required')), 400
        
        result = backup_manager.backup_directory(path, data.get('name'))
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/backup/<int:backup_id>/restore', methods=['POST'])
    @permission_required('backup.write')
    @check_rate_limit('operator')
    def backup_restore(backup_id):
        """Restore a backup"""
        data = request.get_json() or {}
        result = backup_manager.restore_backup(
            backup_id,
            restore_path=data.get('restore_path'),
            overwrite=data.get('overwrite', False)
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/backup/<int:backup_id>', methods=['DELETE'])
    @permission_required('backup.delete')
    @check_rate_limit('user')
    def backup_delete(backup_id):
        """Delete a backup"""
        return jsonify(backup_manager.delete_backup(backup_id))
    
    @app.route('/api/backup/schedules', methods=['GET'])
    @permission_required('backup.read')
    @check_rate_limit('user')
    def backup_list_schedules():
        """List backup schedules"""
        return jsonify(backup_manager.list_schedules())
    
    @app.route('/api/backup/schedules', methods=['POST'])
    @permission_required('backup.write')
    @check_rate_limit('user')
    def backup_create_schedule():
        """Create backup schedule"""
        data = request.get_json() or {}
        result = backup_manager.create_schedule(
            data.get('name', ''),
            data.get('backup_type', ''),
            data.get('target', ''),
            data.get('frequency', 'daily'),
            data.get('time', '02:00'),
            data.get('keep_count', 7)
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/backup/schedules/<int:schedule_id>', methods=['DELETE'])
    @permission_required('backup.delete')
    @check_rate_limit('user')
    def backup_delete_schedule(schedule_id):
        """Delete backup schedule"""
        return jsonify(backup_manager.delete_schedule(schedule_id))
    
    @app.route('/api/backup/statistics', methods=['GET'])
    @permission_required('backup.read')
    @check_rate_limit('user')
    def backup_statistics():
        """Get backup statistics"""
        return jsonify(backup_manager.get_statistics())
    
    @app.route('/api/backup/config', methods=['GET'])
    @permission_required('backup.read')
    @check_rate_limit('user')
    def backup_get_config():
        """Get backup configuration"""
        return jsonify(backup_manager.get_config())
    
    @app.route('/api/backup/config', methods=['PUT'])
    @permission_required('backup.write')
    @check_rate_limit('user')
    def backup_update_config():
        """Update backup configuration"""
        data = request.get_json() or {}
        return jsonify(backup_manager.update_config(data))
    
    # ========== CRON ROUTES ==========
    
    @app.route('/api/cron/jobs', methods=['GET'])
    @permission_required('cron.read')
    @check_rate_limit('user')
    def cron_list_jobs():
        """List cron jobs"""
        enabled_only = request.args.get('enabled_only', 'false').lower() == 'true'
        return jsonify(cron_manager.list_jobs(enabled_only))
    
    @app.route('/api/cron/jobs/<int:job_id>', methods=['GET'])
    @permission_required('cron.read')
    @check_rate_limit('user')
    def cron_get_job(job_id):
        """Get cron job details"""
        return jsonify(cron_manager.get_job(job_id))
    
    @app.route('/api/cron/jobs', methods=['POST'])
    @permission_required('cron.write')
    @check_rate_limit('user')
    def cron_create_job():
        """Create cron job"""
        data = request.get_json() or {}
        name = data.get('name', '').strip()
        command = data.get('command', '').strip()
        schedule = data.get('schedule', '').strip()
        
        if not name or not command or not schedule:
            return jsonify(Public.return_msg(False, 'Name, command, and schedule required')), 400
        
        result = cron_manager.create_job(
            name, command, schedule,
            description=data.get('description', ''),
            enabled=data.get('enabled', True)
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/cron/jobs/<int:job_id>', methods=['PUT'])
    @permission_required('cron.write')
    @check_rate_limit('user')
    def cron_update_job(job_id):
        """Update cron job"""
        data = request.get_json() or {}
        return jsonify(cron_manager.update_job(job_id, data))
    
    @app.route('/api/cron/jobs/<int:job_id>', methods=['DELETE'])
    @permission_required('cron.delete')
    @check_rate_limit('user')
    def cron_delete_job(job_id):
        """Delete cron job"""
        return jsonify(cron_manager.delete_job(job_id))
    
    @app.route('/api/cron/jobs/<int:job_id>/run', methods=['POST'])
    @permission_required('cron.write')
    @check_rate_limit('operator')
    def cron_run_job(job_id):
        """Run cron job immediately"""
        return jsonify(cron_manager.run_job(job_id))
    
    @app.route('/api/cron/jobs/<int:job_id>/enable', methods=['POST'])
    @permission_required('cron.write')
    @check_rate_limit('user')
    def cron_enable_job(job_id):
        """Enable cron job"""
        return jsonify(cron_manager.enable_job(job_id))
    
    @app.route('/api/cron/jobs/<int:job_id>/disable', methods=['POST'])
    @permission_required('cron.write')
    @check_rate_limit('user')
    def cron_disable_job(job_id):
        """Disable cron job"""
        return jsonify(cron_manager.disable_job(job_id))
    
    @app.route('/api/cron/history', methods=['GET'])
    @permission_required('cron.read')
    @check_rate_limit('user')
    def cron_get_history():
        """Get cron job history"""
        job_id = request.args.get('job_id', type=int)
        limit = request.args.get('limit', 50, type=int)
        status = request.args.get('status')
        return jsonify(cron_manager.get_history(job_id, limit, status))
    
    @app.route('/api/cron/presets', methods=['GET'])
    @permission_required('cron.read')
    @check_rate_limit('user')
    def cron_get_presets():
        """Get schedule presets"""
        return jsonify(cron_manager.get_schedule_presets())
    
    # ========== WEB SERVER ROUTES ==========
    
    @app.route('/api/webserver/status', methods=['GET'])
    @permission_required('sites.read')
    @check_rate_limit('user')
    def webserver_status():
        """Get web server status"""
        return jsonify(webserver_manager.get_status())
    
    @app.route('/api/webserver/start', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('operator')
    def webserver_start():
        """Start web server"""
        return jsonify(webserver_manager.start())
    
    @app.route('/api/webserver/stop', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('operator')
    def webserver_stop():
        """Stop web server"""
        return jsonify(webserver_manager.stop())
    
    @app.route('/api/webserver/restart', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('operator')
    def webserver_restart():
        """Restart web server"""
        return jsonify(webserver_manager.restart())
    
    @app.route('/api/webserver/reload', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def webserver_reload():
        """Reload web server configuration"""
        return jsonify(webserver_manager.reload())
    
    @app.route('/api/webserver/sites', methods=['GET'])
    @permission_required('sites.read')
    @check_rate_limit('user')
    def webserver_list_sites():
        """List all sites"""
        return jsonify(webserver_manager.list_sites())
    
    @app.route('/api/webserver/sites/<domain>', methods=['GET'])
    @permission_required('sites.read')
    @check_rate_limit('user')
    def webserver_get_site(domain):
        """Get site details"""
        return jsonify(webserver_manager.get_site(domain))
    
    @app.route('/api/webserver/sites', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def webserver_create_site():
        """Create new site"""
        data = request.get_json() or {}
        domain = data.get('domain', '').strip()
        if not domain:
            return jsonify(Public.return_msg(False, 'Domain required')), 400
        
        result = webserver_manager.create_site(
            domain,
            root_path=data.get('root_path'),
            php_version=data.get('php_version'),
            ssl=data.get('ssl', False)
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/webserver/sites/<domain>', methods=['DELETE'])
    @permission_required('sites.delete')
    @check_rate_limit('user')
    def webserver_delete_site(domain):
        """Delete site"""
        remove_files = request.args.get('remove_files', 'false').lower() == 'true'
        return jsonify(webserver_manager.delete_site(domain, remove_files))
    
    @app.route('/api/webserver/sites/<domain>/enable', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def webserver_enable_site(domain):
        """Enable site"""
        return jsonify(webserver_manager.enable_site(domain))
    
    @app.route('/api/webserver/sites/<domain>/disable', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def webserver_disable_site(domain):
        """Disable site"""
        return jsonify(webserver_manager.disable_site(domain))
    
    @app.route('/api/webserver/sites/<domain>/ssl', methods=['POST'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def webserver_enable_ssl(domain):
        """Enable SSL for site"""
        data = request.get_json() or {}
        cert_path = data.get('cert_path', '').strip()
        key_path = data.get('key_path', '').strip()
        if not cert_path or not key_path:
            return jsonify(Public.return_msg(False, 'Certificate and key paths required')), 400
        
        return jsonify(webserver_manager.enable_ssl(domain, cert_path, key_path))
    
    @app.route('/api/webserver/sites/<domain>/config', methods=['PUT'])
    @permission_required('sites.write')
    @check_rate_limit('user')
    def webserver_update_site_config(domain):
        """Update site configuration"""
        data = request.get_json() or {}
        config_content = data.get('config', '')
        if not config_content:
            return jsonify(Public.return_msg(False, 'Configuration content required')), 400
        
        return jsonify(webserver_manager.update_site_config(domain, config_content))
    
    # ========== PHP ROUTES ==========
    
    @app.route('/api/php/versions', methods=['GET'])
    @permission_required('system.read')
    @check_rate_limit('user')
    def php_list_versions():
        """List PHP versions"""
        return jsonify(php_manager.list_versions())
    
    @app.route('/api/php/versions/<version>', methods=['GET'])
    @permission_required('system.read')
    @check_rate_limit('user')
    def php_get_version(version):
        """Get PHP version info"""
        return jsonify(php_manager.get_version_info(version))
    
    @app.route('/api/php/versions/<version>/default', methods=['POST'])
    @permission_required('system.write')
    @check_rate_limit('operator')
    def php_set_default(version):
        """Set default PHP version"""
        return jsonify(php_manager.set_default_version(version))
    
    @app.route('/api/php/versions', methods=['POST'])
    @permission_required('system.write')
    @check_rate_limit('operator')
    def php_install_version():
        """Install PHP version"""
        data = request.get_json() or {}
        version = data.get('version', '').strip()
        if not version:
            return jsonify(Public.return_msg(False, 'Version required')), 400
        
        return jsonify(php_manager.install_version(version))
    
    @app.route('/api/php/fpm/<version>/start', methods=['POST'])
    @permission_required('system.write')
    @check_rate_limit('operator')
    def php_start_fpm(version):
        """Start PHP-FPM"""
        return jsonify(php_manager.start_fpm(version))
    
    @app.route('/api/php/fpm/<version>/stop', methods=['POST'])
    @permission_required('system.write')
    @check_rate_limit('operator')
    def php_stop_fpm(version):
        """Stop PHP-FPM"""
        return jsonify(php_manager.stop_fpm(version))
    
    @app.route('/api/php/fpm/<version>/restart', methods=['POST'])
    @permission_required('system.write')
    @check_rate_limit('operator')
    def php_restart_fpm(version):
        """Restart PHP-FPM"""
        return jsonify(php_manager.restart_fpm(version))
    
    @app.route('/api/php/extensions', methods=['GET'])
    @permission_required('system.read')
    @check_rate_limit('user')
    def php_list_extensions():
        """List PHP extensions"""
        version = request.args.get('version')
        return jsonify(php_manager.list_extensions(version))
    
    @app.route('/api/php/extensions', methods=['POST'])
    @permission_required('system.write')
    @check_rate_limit('operator')
    def php_install_extension():
        """Install PHP extension"""
        data = request.get_json() or {}
        extension = data.get('extension', '').strip()
        if not extension:
            return jsonify(Public.return_msg(False, 'Extension name required')), 400
        
        return jsonify(php_manager.install_extension(extension, data.get('version')))
    
    @app.route('/api/php/settings', methods=['GET'])
    @permission_required('system.read')
    @check_rate_limit('user')
    def php_get_settings():
        """Get PHP ini settings"""
        version = request.args.get('version')
        return jsonify(php_manager.get_ini_settings(version))
    
    @app.route('/api/php/settings', methods=['PUT'])
    @permission_required('system.write')
    @check_rate_limit('user')
    def php_update_settings():
        """Update PHP ini settings"""
        data = request.get_json() or {}
        version = data.pop('version', None)
        return jsonify(php_manager.update_ini_settings(data, version))
    
    @app.route('/api/php/composer', methods=['GET'])
    @permission_required('system.read')
    @check_rate_limit('user')
    def php_composer_version():
        """Get Composer version"""
        return jsonify(php_manager.get_composer_version())
    
    # ========== FTP ROUTES ==========
    
    @app.route('/api/ftp/status', methods=['GET'])
    @permission_required('ftp.read')
    @check_rate_limit('user')
    def ftp_status():
        """Get FTP server status"""
        return jsonify(ftp_manager.get_status())
    
    @app.route('/api/ftp/start', methods=['POST'])
    @permission_required('ftp.write')
    @check_rate_limit('operator')
    def ftp_start():
        """Start FTP server"""
        return jsonify(ftp_manager.start())
    
    @app.route('/api/ftp/stop', methods=['POST'])
    @permission_required('ftp.write')
    @check_rate_limit('operator')
    def ftp_stop():
        """Stop FTP server"""
        return jsonify(ftp_manager.stop())
    
    @app.route('/api/ftp/restart', methods=['POST'])
    @permission_required('ftp.write')
    @check_rate_limit('operator')
    def ftp_restart():
        """Restart FTP server"""
        return jsonify(ftp_manager.restart())
    
    @app.route('/api/ftp/users', methods=['GET'])
    @permission_required('ftp.read')
    @check_rate_limit('user')
    def ftp_list_users():
        """List FTP users"""
        return jsonify(ftp_manager.list_users())
    
    @app.route('/api/ftp/users/<username>', methods=['GET'])
    @permission_required('ftp.read')
    @check_rate_limit('user')
    def ftp_get_user(username):
        """Get FTP user details"""
        return jsonify(ftp_manager.get_user(username))
    
    @app.route('/api/ftp/users', methods=['POST'])
    @permission_required('ftp.write')
    @check_rate_limit('user')
    def ftp_create_user():
        """Create FTP user"""
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        password = data.get('password', '')
        home_dir = data.get('home_dir', '').strip()
        
        if not username or not password or not home_dir:
            return jsonify(Public.return_msg(False, 'Username, password, and home directory required')), 400
        
        result = ftp_manager.create_user(
            username, password, home_dir,
            quota_mb=data.get('quota_mb', 0),
            description=data.get('description', '')
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/ftp/users/<username>', methods=['DELETE'])
    @permission_required('ftp.delete')
    @check_rate_limit('user')
    def ftp_delete_user(username):
        """Delete FTP user"""
        remove_home = request.args.get('remove_home', 'false').lower() == 'true'
        return jsonify(ftp_manager.delete_user(username, remove_home))
    
    @app.route('/api/ftp/users/<username>/password', methods=['PUT'])
    @permission_required('ftp.write')
    @check_rate_limit('user')
    def ftp_change_password(username):
        """Change FTP user password"""
        data = request.get_json() or {}
        password = data.get('password', '')
        if not password:
            return jsonify(Public.return_msg(False, 'Password required')), 400
        
        return jsonify(ftp_manager.change_password(username, password))
    
    @app.route('/api/ftp/users/<username>/enable', methods=['POST'])
    @permission_required('ftp.write')
    @check_rate_limit('user')
    def ftp_enable_user(username):
        """Enable FTP user"""
        return jsonify(ftp_manager.enable_user(username))
    
    @app.route('/api/ftp/users/<username>/disable', methods=['POST'])
    @permission_required('ftp.write')
    @check_rate_limit('user')
    def ftp_disable_user(username):
        """Disable FTP user"""
        return jsonify(ftp_manager.disable_user(username))
    
    @app.route('/api/ftp/users/<username>/quota', methods=['PUT'])
    @permission_required('ftp.write')
    @check_rate_limit('user')
    def ftp_set_quota(username):
        """Set FTP user quota"""
        data = request.get_json() or {}
        quota_mb = data.get('quota_mb', 0)
        return jsonify(ftp_manager.set_quota(username, int(quota_mb)))
    
    @app.route('/api/ftp/logs', methods=['GET'])
    @permission_required('ftp.read')
    @check_rate_limit('user')
    def ftp_get_logs():
        """Get FTP logs"""
        lines = request.args.get('lines', 100, type=int)
        return jsonify(ftp_manager.get_logs(lines))
    
    @app.route('/api/ftp/settings', methods=['GET'])
    @permission_required('ftp.read')
    @check_rate_limit('user')
    def ftp_get_settings():
        """Get FTP settings"""
        return jsonify(ftp_manager.get_settings())
    
    @app.route('/api/ftp/settings', methods=['PUT'])
    @permission_required('ftp.write')
    @check_rate_limit('user')
    def ftp_update_settings():
        """Update FTP settings"""
        data = request.get_json() or {}
        return jsonify(ftp_manager.update_settings(data))
    
    # ========== DOCKER ROUTES ==========
    
    @app.route('/api/docker/status', methods=['GET'])
    @permission_required('docker.read')
    @check_rate_limit('user')
    def docker_status():
        """Get Docker status"""
        return jsonify(docker_manager.get_status())
    
    @app.route('/api/docker/containers', methods=['GET'])
    @permission_required('docker.read')
    @check_rate_limit('user')
    def docker_list_containers():
        """List containers"""
        all_containers = request.args.get('all', 'false').lower() == 'true'
        return jsonify(docker_manager.list_containers(all_containers))
    
    @app.route('/api/docker/containers/<container_id>', methods=['GET'])
    @permission_required('docker.read')
    @check_rate_limit('user')
    def docker_get_container(container_id):
        """Get container details"""
        return jsonify(docker_manager.get_container(container_id))
    
    @app.route('/api/docker/containers', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('operator')
    def docker_create_container():
        """Create container"""
        data = request.get_json() or {}
        image = data.get('image', '').strip()
        if not image:
            return jsonify(Public.return_msg(False, 'Image required')), 400
        
        result = docker_manager.create_container(
            image,
            name=data.get('name'),
            ports=data.get('ports'),
            volumes=data.get('volumes'),
            env=data.get('env'),
            network=data.get('network'),
            restart_policy=data.get('restart_policy', 'unless-stopped')
        )
        return jsonify(result), 200 if result.get('success') else 400
    
    @app.route('/api/docker/containers/<container_id>/start', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('user')
    def docker_start_container(container_id):
        """Start container"""
        return jsonify(docker_manager.start_container(container_id))
    
    @app.route('/api/docker/containers/<container_id>/stop', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('user')
    def docker_stop_container(container_id):
        """Stop container"""
        timeout = request.args.get('timeout', 10, type=int)
        return jsonify(docker_manager.stop_container(container_id, timeout))
    
    @app.route('/api/docker/containers/<container_id>/restart', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('user')
    def docker_restart_container(container_id):
        """Restart container"""
        return jsonify(docker_manager.restart_container(container_id))
    
    @app.route('/api/docker/containers/<container_id>', methods=['DELETE'])
    @permission_required('docker.delete')
    @check_rate_limit('user')
    def docker_remove_container(container_id):
        """Remove container"""
        force = request.args.get('force', 'false').lower() == 'true'
        volumes = request.args.get('volumes', 'false').lower() == 'true'
        return jsonify(docker_manager.remove_container(container_id, force, volumes))
    
    @app.route('/api/docker/containers/<container_id>/logs', methods=['GET'])
    @permission_required('docker.read')
    @check_rate_limit('user')
    def docker_container_logs(container_id):
        """Get container logs"""
        tail = request.args.get('tail', 100, type=int)
        return jsonify(docker_manager.get_container_logs(container_id, tail))
    
    @app.route('/api/docker/containers/<container_id>/stats', methods=['GET'])
    @permission_required('docker.read')
    @check_rate_limit('user')
    def docker_container_stats(container_id):
        """Get container stats"""
        return jsonify(docker_manager.get_container_stats(container_id))
    
    @app.route('/api/docker/containers/<container_id>/exec', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('operator')
    def docker_exec_container(container_id):
        """Execute command in container"""
        data = request.get_json() or {}
        command = data.get('command', '').strip()
        if not command:
            return jsonify(Public.return_msg(False, 'Command required')), 400
        
        return jsonify(docker_manager.exec_in_container(container_id, command))
    
    @app.route('/api/docker/images', methods=['GET'])
    @permission_required('docker.read')
    @check_rate_limit('user')
    def docker_list_images():
        """List images"""
        return jsonify(docker_manager.list_images())
    
    @app.route('/api/docker/images/pull', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('operator')
    def docker_pull_image():
        """Pull image"""
        data = request.get_json() or {}
        image = data.get('image', '').strip()
        if not image:
            return jsonify(Public.return_msg(False, 'Image required')), 400
        
        return jsonify(docker_manager.pull_image(image))
    
    @app.route('/api/docker/images/<image_id>', methods=['DELETE'])
    @permission_required('docker.delete')
    @check_rate_limit('user')
    def docker_remove_image(image_id):
        """Remove image"""
        force = request.args.get('force', 'false').lower() == 'true'
        return jsonify(docker_manager.remove_image(image_id, force))
    
    @app.route('/api/docker/networks', methods=['GET'])
    @permission_required('docker.read')
    @check_rate_limit('user')
    def docker_list_networks():
        """List networks"""
        return jsonify(docker_manager.list_networks())
    
    @app.route('/api/docker/networks', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('user')
    def docker_create_network():
        """Create network"""
        data = request.get_json() or {}
        name = data.get('name', '').strip()
        if not name:
            return jsonify(Public.return_msg(False, 'Network name required')), 400
        
        return jsonify(docker_manager.create_network(
            name,
            driver=data.get('driver', 'bridge'),
            subnet=data.get('subnet')
        ))
    
    @app.route('/api/docker/networks/<network_name>', methods=['DELETE'])
    @permission_required('docker.delete')
    @check_rate_limit('user')
    def docker_remove_network(network_name):
        """Remove network"""
        return jsonify(docker_manager.remove_network(network_name))
    
    @app.route('/api/docker/volumes', methods=['GET'])
    @permission_required('docker.read')
    @check_rate_limit('user')
    def docker_list_volumes():
        """List volumes"""
        return jsonify(docker_manager.list_volumes())
    
    @app.route('/api/docker/volumes', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('user')
    def docker_create_volume():
        """Create volume"""
        data = request.get_json() or {}
        name = data.get('name', '').strip()
        if not name:
            return jsonify(Public.return_msg(False, 'Volume name required')), 400
        
        return jsonify(docker_manager.create_volume(name, data.get('driver', 'local')))
    
    @app.route('/api/docker/volumes/<volume_name>', methods=['DELETE'])
    @permission_required('docker.delete')
    @check_rate_limit('user')
    def docker_remove_volume(volume_name):
        """Remove volume"""
        force = request.args.get('force', 'false').lower() == 'true'
        return jsonify(docker_manager.remove_volume(volume_name, force))
    
    @app.route('/api/docker/compose/up', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('operator')
    def docker_compose_up():
        """Run docker-compose up"""
        data = request.get_json() or {}
        compose_file = data.get('compose_file', '').strip()
        if not compose_file:
            return jsonify(Public.return_msg(False, 'Compose file path required')), 400
        
        return jsonify(docker_manager.compose_up(
            compose_file,
            detach=data.get('detach', True),
            build=data.get('build', False)
        ))
    
    @app.route('/api/docker/compose/down', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('operator')
    def docker_compose_down():
        """Run docker-compose down"""
        data = request.get_json() or {}
        compose_file = data.get('compose_file', '').strip()
        if not compose_file:
            return jsonify(Public.return_msg(False, 'Compose file path required')), 400
        
        return jsonify(docker_manager.compose_down(
            compose_file,
            volumes=data.get('volumes', False)
        ))
    
    @app.route('/api/docker/prune', methods=['POST'])
    @permission_required('docker.write')
    @check_rate_limit('operator')
    def docker_system_prune():
        """Clean up unused Docker resources"""
        data = request.get_json() or {}
        return jsonify(docker_manager.system_prune(
            all_unused=data.get('all_unused', False),
            volumes=data.get('volumes', False)
        ))
    
    @app.route('/api/docker/disk-usage', methods=['GET'])
    @permission_required('docker.read')
    @check_rate_limit('user')
    def docker_disk_usage():
        """Get Docker disk usage"""
        return jsonify(docker_manager.get_disk_usage())
    
    # ========== ERROR HANDLERS ==========
    
    @app.errorhandler(400)
    def bad_request(error):
        error_handler.log_error('BAD_REQUEST', str(error), error)
        logger.log_security_event('Bad Request', str(error), 'WARNING')
        return jsonify(error_handler.format_error(
            'VALIDATION_ERROR',
            'Bad request'
        )), 400
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors with helpful information"""
        path = request.path
        method = request.method
        
        # Provide helpful error message
        if path.startswith('/api'):
            return jsonify({
                'success': False,
                'message': f'API endpoint not found: {method} {path}',
                'hint': 'Get API documentation at GET /api',
                'status': 'error'
            }), 404
        else:
            return jsonify(Public.return_msg(False, 'Endpoint not found')), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        error_handler.log_error('INTERNAL_SERVER_ERROR', str(error), error)
        logger.log_system_event('Internal Server Error', str(error), 'CRITICAL')
        return jsonify(error_handler.format_error(
            'SERVER_ERROR',
            'Internal server error'
        )), 500
    
    @app.errorhandler(413)
    def request_entity_too_large(error):
        error_handler.log_error('FILE_TOO_LARGE', str(error), error)
        return jsonify(error_handler.format_error(
            'VALIDATION_ERROR',
            'File too large'
        )), 413
    
    return app, socketio


if __name__ == '__main__':
    app, socketio = create_app()
    # Determine debug mode from environment
    is_debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    socketio.run(app, host='0.0.0.0', port=72323, debug=is_debug, use_reloader=False, log_output=not is_debug)

