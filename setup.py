#!/usr/bin/env python3
"""
Apkaya Panel WAF - Setup Script

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License

Initialize the clean codebase for production use.
"""

import os
import sys
import json
import argparse
from pathlib import Path


def create_default_config():
    """Create default configuration files"""
    config_dir = Path('config')
    config_dir.mkdir(exist_ok=True)
    
    # Panel configuration
    panel_config = {
        'panel': {
            'host': '0.0.0.0',
            'port': 8888,
            'ssl': False,
            'ssl_cert': '',
            'ssl_key': ''
        },
        'database': {
            'type': 'sqlite',
            'path': 'data/panel.db'
        },
        'security': {
            'session_timeout': 3600,
            'password_min_length': 12,
            'max_login_attempts': 5,
            'lock_duration': 900
        },
        'features': {
            'pro': True,
            'enterprise': True,
            'waf_integration': True
        }
    }
    
    with open(config_dir / 'panel.json', 'w') as f:
        json.dump(panel_config, f, indent=2)
    
    # Database configuration
    db_config = {
        'mysql': [],
        'postgresql': [],
        'mongodb': [],
        'redis': []
    }
    
    with open(config_dir / 'database.json', 'w') as f:
        json.dump(db_config, f, indent=2)
    
    # WAF configuration
    waf_config = {
        'enabled': True,
        'port': 8379,
        'modules': {
            'sql_injection': True,
            'xss': True,
            'ssrf': True,
            'command_injection': True,
            'file_upload': True,
            'file_inclusion': True,
            'php_injection': True,
            'java_injection': True,
            'template_injection': True,
            'xxe': True
        },
        'rate_limit': {
            'enabled': True,
            'requests_per_second': 60,
            'block_duration': 300
        },
        'logging': {
            'enabled': True,
            'level': 'info',
            'retention_days': 30
        }
    }
    
    with open(config_dir / 'waf.json', 'w') as f:
        json.dump(waf_config, f, indent=2)
    
    print('✓ Configuration files created')


def create_directories():
    """Create necessary directories"""
    dirs = [
        'config',
        'data',
        'data/vhost',
        'data/backup',
        'logs',
        'panel/templates',
        'panel/static',
        'panel/routes',
        'panel/class',
        'panel/class/waf',
        'waf/core',
        'waf/modules',
        'waf/engine'
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    print('✓ Directories created')


def install_dependencies():
    """Install Python dependencies"""
    print('Installing dependencies...')
    os.system('pip install -r requirements.txt')
    print('✓ Dependencies installed')


def main():
    parser = argparse.ArgumentParser(
        description='Apkaya Panel WAF - Setup and Installation'
    )
    parser.add_argument('--no-deps', action='store_true',
                       help='Skip dependency installation')
    parser.add_argument('--quick', action='store_true',
                       help='Quick setup (skip some steps)')
    
    args = parser.parse_args()
    
    print('\n' + '='*60)
    print('  Apkaya Panel WAF - Setup')
    print('  Open Source Edition (MIT License)')
    print('='*60 + '\n')
    
    try:
        create_directories()
        create_default_config()
        
        if not args.no_deps:
            install_dependencies()
        
        print('\n' + '='*60)
        print('  Setup Complete!')
        print('  Start the panel: python run.py')
        print('  Visit: http://localhost:8888')
        print('='*60 + '\n')
        
    except Exception as e:
        print(f'\n✗ Error: {str(e)}')
        sys.exit(1)


if __name__ == '__main__':
    main()
