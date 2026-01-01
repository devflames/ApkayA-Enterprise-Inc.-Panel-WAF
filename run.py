"""
Apkaya Panel WAF - Main Launcher

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import sys
import json
import argparse
import logging
import importlib.util
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add panel directory to path
PANEL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PANEL_DIR)


def load_module_from_path(module_name, file_path):
    """Load a module from a specific file path (workaround for 'class' folder name)"""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ensure_directories():
    """Ensure all necessary directories exist"""
    dirs = [
        os.path.join(PANEL_DIR, 'config'),
        os.path.join(PANEL_DIR, 'data'),
        os.path.join(PANEL_DIR, 'logs'),
        os.path.join(PANEL_DIR, 'data', 'vhost'),
        os.path.join(PANEL_DIR, 'data', 'backup'),
        os.path.join(PANEL_DIR, 'panel', 'templates'),
        os.path.join(PANEL_DIR, 'panel', 'static'),
        os.path.join(PANEL_DIR, 'ssl'),
        os.path.join(PANEL_DIR, 'backup'),
    ]
    
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)
        logger.debug(f'Directory created/verified: {dir_path}')


def write_json_file(filepath, data):
    """Write JSON data to file"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def ensure_config_files():
    """Ensure all necessary config files exist"""
    config_dir = os.path.join(PANEL_DIR, 'config')
    
    # Database config
    db_config_file = os.path.join(config_dir, 'database.json')
    if not os.path.exists(db_config_file):
        write_json_file(db_config_file, {
            'mysql': [],
            'postgresql': [],
            'mongodb': [],
            'redis': []
        })
        logger.info('Created database config')
    
    # Sites config
    sites_config_file = os.path.join(config_dir, 'sites.json')
    if not os.path.exists(sites_config_file):
        write_json_file(sites_config_file, {'sites': []})
        logger.info('Created sites config')
    
    # WAF config
    waf_config_file = os.path.join(config_dir, 'waf.json')
    if not os.path.exists(waf_config_file):
        write_json_file(waf_config_file, {
            'enabled': True,
            'mode': 'protection',
            'rules': []
        })
        logger.info('Created WAF config')
    
    # Users config
    users_config_file = os.path.join(config_dir, 'users.json')
    if not os.path.exists(users_config_file):
        write_json_file(users_config_file, {'users': []})
        logger.info('Created users config')
    
    # Panel config
    panel_config_file = os.path.join(config_dir, 'panel.json')
    if not os.path.exists(panel_config_file):
        import secrets
        write_json_file(panel_config_file, {
            'secret_key': secrets.token_hex(32),
            'session_timeout': 3600,
            'max_login_attempts': 5
        })
        logger.info('Created panel config')


def run_panel(port=2323, host='0.0.0.0', debug=False):
    """Run the Flask panel application"""
    from panel.app import create_app
    import logging as werkzeug_logging
    
    # Suppress Werkzeug development server warning in production mode
    if not debug:
        werkzeug_logging.getLogger('werkzeug').setLevel(werkzeug_logging.ERROR)
    
    logger.info('Starting Apkaya Panel WAF...')
    
    ensure_directories()
    ensure_config_files()
    
    app, socketio = create_app()
    
    logger.info(f'Panel starting on http://{host}:{port}')
    print(f'\n' + '='*60)
    print(f'  Apkaya Panel WAF - Open Source Edition')
    print(f'  URL: http://localhost:{port}')
    print(f'  Licensed under MIT License')
    print(f'='*60 + '\n')
    
    # Run with explicit port and host settings
    socketio.run(
        app, 
        host=host, 
        port=port, 
        debug=debug, 
        allow_unsafe_werkzeug=True, 
        use_reloader=False,
        log_output=True
    )


def run_waf():
    """Run WAF service (requires Go WAF binary)"""
    logger.info('WAF service runner not implemented in Python')
    logger.info('Run WAF separately: ./waf/main')


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Apkaya Panel WAF - Open Source Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python run.py                    # Start panel on port 2323
  python run.py -p 9999           # Start panel on port 9999
  python run.py --waf             # Start WAF service
  python run.py --debug           # Start in debug mode
        '''
    )
    
    parser.add_argument('-p', '--port', type=int, default=2323,
                       help='Port to run panel on (default: 2323)')
    parser.add_argument('-H', '--host', default='0.0.0.0',
                       help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true',
                       help='Run in debug mode')
    parser.add_argument('--waf', action='store_true',
                       help='Run WAF service instead of panel')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    
    args = parser.parse_args()
    
    try:
        if args.waf:
            run_waf()
        else:
            run_panel(port=args.port, host=args.host, debug=args.debug)
    except KeyboardInterrupt:
        logger.info('Shutting down...')
        sys.exit(0)
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)


if __name__ == '__main__':
    main()
