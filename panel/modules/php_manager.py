"""
ApkayA Enterprise Control Panel - PHP Management Module
PHP version management, extensions, configuration

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import json
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import platform


class PHPManager:
    """Complete PHP version and configuration management"""
    
    def __init__(self, config_path='data/php_config.json'):
        """Initialize PHP manager"""
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.os_type = platform.system().lower()
        
        # Load config
        if not self.config_path.exists():
            self._write_config(self._default_config())
        self.config = self._read_config()
        
        # Detect installed versions
        self._detect_versions()
    
    @staticmethod
    def _default_config() -> dict:
        return {
            'installed_versions': [],
            'default_version': None,
            'extensions': {},
            'disabled_functions': ['exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen']
        }
    
    def _detect_versions(self) -> None:
        """Detect installed PHP versions"""
        versions = []
        
        if self.os_type == 'windows':
            # Check common Windows PHP paths
            paths = [
                'C:/php',
                'C:/php7',
                'C:/php8',
                'C:/xampp/php',
                'C:/laragon/bin/php'
            ]
            for path in paths:
                if Path(path).exists():
                    version = self._get_version_from_path(path)
                    if version:
                        versions.append({'version': version, 'path': path})
        else:
            # Check common Linux paths and alternatives
            try:
                # Check update-alternatives
                result = subprocess.run(
                    ['update-alternatives', '--list', 'php'],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            version = self._get_version_from_path(line)
                            if version:
                                versions.append({'version': version, 'path': line})
            except:
                pass
            
            # Check /usr/bin for phpX.X
            for php_bin in Path('/usr/bin').glob('php*'):
                if re.match(r'php\d+\.\d+$', php_bin.name):
                    version = self._get_version_from_path(str(php_bin))
                    if version and not any(v['version'] == version for v in versions):
                        versions.append({'version': version, 'path': str(php_bin)})
        
        self.config['installed_versions'] = versions
        
        # Set default if not set
        if not self.config.get('default_version') and versions:
            self.config['default_version'] = versions[0]['version']
        
        self._write_config(self.config)
    
    def _get_version_from_path(self, path: str) -> Optional[str]:
        """Get PHP version from executable path"""
        try:
            php_exe = path if path.endswith('php') or path.endswith('php.exe') else f"{path}/php"
            result = subprocess.run([php_exe, '-v'], capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r'PHP (\d+\.\d+\.\d+)', result.stdout)
                if match:
                    return match.group(1)
        except:
            pass
        return None
    
    # ===== Version Management =====
    
    def list_versions(self) -> dict:
        """List installed PHP versions"""
        self._detect_versions()
        
        versions = []
        for v in self.config.get('installed_versions', []):
            version_info = {
                'version': v['version'],
                'path': v['path'],
                'is_default': v['version'] == self.config.get('default_version'),
                'fpm_running': self._is_fpm_running(v['version'])
            }
            versions.append(version_info)
        
        return {
            'success': True,
            'versions': versions,
            'default': self.config.get('default_version'),
            'count': len(versions)
        }
    
    def get_version_info(self, version: str) -> dict:
        """Get detailed info for a PHP version"""
        
        v_info = self._get_version_info(version)
        if not v_info:
            return {'success': False, 'message': f'PHP {version} not installed'}
        
        php_path = v_info['path']
        php_exe = php_path if 'php' in Path(php_path).name else f"{php_path}/php"
        
        try:
            # Get detailed info
            result = subprocess.run([php_exe, '-i'], capture_output=True, text=True)
            php_info = result.stdout
            
            info = {
                'version': version,
                'path': php_path,
                'is_default': version == self.config.get('default_version'),
                'fpm_running': self._is_fpm_running(version),
                'extensions': self._get_installed_extensions(version),
                'config': {
                    'memory_limit': self._extract_ini_value(php_info, 'memory_limit'),
                    'max_execution_time': self._extract_ini_value(php_info, 'max_execution_time'),
                    'upload_max_filesize': self._extract_ini_value(php_info, 'upload_max_filesize'),
                    'post_max_size': self._extract_ini_value(php_info, 'post_max_size'),
                    'display_errors': self._extract_ini_value(php_info, 'display_errors'),
                    'error_reporting': self._extract_ini_value(php_info, 'error_reporting'),
                },
                'ini_path': self._extract_ini_value(php_info, 'Loaded Configuration File')
            }
            
            return {'success': True, 'info': info}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def set_default_version(self, version: str) -> dict:
        """Set default PHP version"""
        
        if not self._get_version_info(version):
            return {'success': False, 'message': f'PHP {version} not installed'}
        
        try:
            if self.os_type != 'windows':
                # Use update-alternatives on Linux
                subprocess.run([
                    'update-alternatives', '--set', 'php',
                    f'/usr/bin/php{version[:3]}'
                ], check=True)
            
            self.config['default_version'] = version
            self._write_config(self.config)
            
            return {'success': True, 'message': f'Default PHP set to {version}'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def install_version(self, version: str) -> dict:
        """Install a PHP version"""
        
        if self.os_type == 'windows':
            return {'success': False, 'message': 'Manual PHP installation required on Windows'}
        
        try:
            # Add PHP repository
            subprocess.run([
                'add-apt-repository', '-y', 'ppa:ondrej/php'
            ], check=True, capture_output=True)
            
            subprocess.run(['apt-get', 'update'], check=True, capture_output=True)
            
            # Install PHP and common extensions
            packages = [
                f'php{version}',
                f'php{version}-fpm',
                f'php{version}-cli',
                f'php{version}-common',
                f'php{version}-mysql',
                f'php{version}-pgsql',
                f'php{version}-curl',
                f'php{version}-gd',
                f'php{version}-mbstring',
                f'php{version}-xml',
                f'php{version}-zip',
                f'php{version}-bcmath',
                f'php{version}-intl'
            ]
            
            subprocess.run(
                ['apt-get', 'install', '-y'] + packages,
                check=True, capture_output=True
            )
            
            # Refresh detected versions
            self._detect_versions()
            
            return {'success': True, 'message': f'PHP {version} installed'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def uninstall_version(self, version: str) -> dict:
        """Uninstall a PHP version"""
        
        if self.os_type == 'windows':
            return {'success': False, 'message': 'Manual PHP removal required on Windows'}
        
        if version == self.config.get('default_version'):
            return {'success': False, 'message': 'Cannot uninstall default PHP version'}
        
        try:
            subprocess.run([
                'apt-get', 'remove', '-y', f'php{version}*'
            ], check=True, capture_output=True)
            
            self._detect_versions()
            
            return {'success': True, 'message': f'PHP {version} uninstalled'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== PHP-FPM Management =====
    
    def start_fpm(self, version: str = None) -> dict:
        """Start PHP-FPM"""
        version = version or self.config.get('default_version')
        
        try:
            if self.os_type == 'windows':
                return {'success': False, 'message': 'PHP-FPM not available on Windows'}
            
            service_name = f'php{version[:3]}-fpm'
            subprocess.run(['systemctl', 'start', service_name], check=True)
            
            return {'success': True, 'message': f'{service_name} started'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def stop_fpm(self, version: str = None) -> dict:
        """Stop PHP-FPM"""
        version = version or self.config.get('default_version')
        
        try:
            service_name = f'php{version[:3]}-fpm'
            subprocess.run(['systemctl', 'stop', service_name], check=True)
            
            return {'success': True, 'message': f'{service_name} stopped'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def restart_fpm(self, version: str = None) -> dict:
        """Restart PHP-FPM"""
        version = version or self.config.get('default_version')
        
        try:
            service_name = f'php{version[:3]}-fpm'
            subprocess.run(['systemctl', 'restart', service_name], check=True)
            
            return {'success': True, 'message': f'{service_name} restarted'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _is_fpm_running(self, version: str) -> bool:
        """Check if PHP-FPM is running"""
        if self.os_type == 'windows':
            return False
        
        try:
            service_name = f'php{version[:3]}-fpm'
            result = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True, text=True
            )
            return result.stdout.strip() == 'active'
        except:
            return False
    
    # ===== Extension Management =====
    
    def list_extensions(self, version: str = None) -> dict:
        """List PHP extensions"""
        version = version or self.config.get('default_version')
        
        installed = self._get_installed_extensions(version)
        available = self._get_available_extensions(version)
        
        return {
            'success': True,
            'installed': installed,
            'available': available,
            'installed_count': len(installed),
            'available_count': len(available)
        }
    
    def _get_installed_extensions(self, version: str) -> List[str]:
        """Get installed extensions for a version"""
        v_info = self._get_version_info(version)
        if not v_info:
            return []
        
        try:
            php_path = v_info['path']
            php_exe = php_path if 'php' in Path(php_path).name else f"{php_path}/php"
            
            result = subprocess.run([php_exe, '-m'], capture_output=True, text=True)
            if result.returncode == 0:
                extensions = [ext.strip() for ext in result.stdout.split('\n') 
                             if ext.strip() and not ext.startswith('[')]
                return sorted(extensions)
        except:
            pass
        
        return []
    
    def _get_available_extensions(self, version: str) -> List[str]:
        """Get available extensions for installation"""
        common_extensions = [
            'bcmath', 'bz2', 'calendar', 'ctype', 'curl', 'dom', 'exif',
            'fileinfo', 'ftp', 'gd', 'gettext', 'gmp', 'iconv', 'imagick',
            'imap', 'intl', 'json', 'ldap', 'mbstring', 'mcrypt', 'memcached',
            'mongodb', 'mysql', 'mysqli', 'mysqlnd', 'opcache', 'openssl',
            'pcntl', 'pdo', 'pdo_mysql', 'pdo_pgsql', 'pdo_sqlite', 'pgsql',
            'phar', 'posix', 'readline', 'redis', 'session', 'shmop',
            'simplexml', 'soap', 'sockets', 'sodium', 'sqlite3', 'ssh2',
            'tidy', 'tokenizer', 'xml', 'xmlreader', 'xmlrpc', 'xmlwriter',
            'xsl', 'zip', 'zlib'
        ]
        
        installed = self._get_installed_extensions(version)
        return [ext for ext in common_extensions if ext.lower() not in [e.lower() for e in installed]]
    
    def install_extension(self, extension: str, version: str = None) -> dict:
        """Install PHP extension"""
        version = version or self.config.get('default_version')
        
        if self.os_type == 'windows':
            return {'success': False, 'message': 'Manual extension installation required on Windows'}
        
        try:
            package = f'php{version[:3]}-{extension}'
            
            subprocess.run([
                'apt-get', 'install', '-y', package
            ], check=True, capture_output=True)
            
            # Restart FPM
            self.restart_fpm(version)
            
            return {'success': True, 'message': f'Extension {extension} installed'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def uninstall_extension(self, extension: str, version: str = None) -> dict:
        """Uninstall PHP extension"""
        version = version or self.config.get('default_version')
        
        if self.os_type == 'windows':
            return {'success': False, 'message': 'Manual extension removal required on Windows'}
        
        try:
            package = f'php{version[:3]}-{extension}'
            
            subprocess.run([
                'apt-get', 'remove', '-y', package
            ], check=True, capture_output=True)
            
            self.restart_fpm(version)
            
            return {'success': True, 'message': f'Extension {extension} removed'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Configuration Management =====
    
    def get_ini_settings(self, version: str = None) -> dict:
        """Get php.ini settings"""
        version = version or self.config.get('default_version')
        
        v_info = self._get_version_info(version)
        if not v_info:
            return {'success': False, 'message': f'PHP {version} not installed'}
        
        try:
            ini_path = self._get_ini_path(version)
            if not ini_path or not Path(ini_path).exists():
                return {'success': False, 'message': 'php.ini not found'}
            
            content = Path(ini_path).read_text()
            
            settings = {
                'memory_limit': self._parse_ini_setting(content, 'memory_limit'),
                'max_execution_time': self._parse_ini_setting(content, 'max_execution_time'),
                'max_input_time': self._parse_ini_setting(content, 'max_input_time'),
                'upload_max_filesize': self._parse_ini_setting(content, 'upload_max_filesize'),
                'post_max_size': self._parse_ini_setting(content, 'post_max_size'),
                'max_input_vars': self._parse_ini_setting(content, 'max_input_vars'),
                'display_errors': self._parse_ini_setting(content, 'display_errors'),
                'error_reporting': self._parse_ini_setting(content, 'error_reporting'),
                'log_errors': self._parse_ini_setting(content, 'log_errors'),
                'date.timezone': self._parse_ini_setting(content, 'date.timezone'),
                'disable_functions': self._parse_ini_setting(content, 'disable_functions'),
                'open_basedir': self._parse_ini_setting(content, 'open_basedir'),
            }
            
            return {
                'success': True,
                'settings': settings,
                'ini_path': ini_path
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def update_ini_setting(self, key: str, value: str, version: str = None) -> dict:
        """Update a php.ini setting"""
        version = version or self.config.get('default_version')
        
        # Security check
        dangerous_settings = ['open_basedir', 'disable_functions']
        if key in dangerous_settings:
            # Additional validation could be added here
            pass
        
        try:
            ini_path = self._get_ini_path(version)
            if not ini_path:
                return {'success': False, 'message': 'php.ini not found'}
            
            content = Path(ini_path).read_text()
            
            # Update or add setting
            pattern = rf'^;?\s*{re.escape(key)}\s*=.*$'
            replacement = f'{key} = {value}'
            
            if re.search(pattern, content, re.MULTILINE):
                content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
            else:
                content += f'\n{replacement}\n'
            
            Path(ini_path).write_text(content)
            
            # Restart FPM
            self.restart_fpm(version)
            
            return {'success': True, 'message': f'{key} updated to {value}'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def update_ini_settings(self, settings: dict, version: str = None) -> dict:
        """Update multiple php.ini settings"""
        version = version or self.config.get('default_version')
        
        results = []
        for key, value in settings.items():
            result = self.update_ini_setting(key, value, version)
            results.append({'key': key, 'success': result['success']})
        
        # Single FPM restart
        self.restart_fpm(version)
        
        return {
            'success': all(r['success'] for r in results),
            'results': results
        }
    
    def _get_ini_path(self, version: str) -> Optional[str]:
        """Get php.ini path for a version"""
        v_info = self._get_version_info(version)
        if not v_info:
            return None
        
        try:
            php_path = v_info['path']
            php_exe = php_path if 'php' in Path(php_path).name else f"{php_path}/php"
            
            result = subprocess.run([php_exe, '-i'], capture_output=True, text=True)
            match = re.search(r'Loaded Configuration File\s*=>\s*(.+)', result.stdout)
            if match:
                return match.group(1).strip()
        except:
            pass
        
        # Fallback paths
        if self.os_type == 'windows':
            return f'{v_info["path"]}/php.ini'
        else:
            return f'/etc/php/{version[:3]}/fpm/php.ini'
    
    def _parse_ini_setting(self, content: str, key: str) -> Optional[str]:
        """Parse setting from ini content"""
        pattern = rf'^{re.escape(key)}\s*=\s*(.+)$'
        match = re.search(pattern, content, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return None
    
    def _extract_ini_value(self, phpinfo: str, key: str) -> Optional[str]:
        """Extract value from phpinfo output"""
        pattern = rf'{re.escape(key)}\s*=>\s*([^\s]+)'
        match = re.search(pattern, phpinfo)
        if match:
            return match.group(1)
        return None
    
    # ===== Security Functions =====
    
    def get_disabled_functions(self, version: str = None) -> dict:
        """Get disabled functions"""
        version = version or self.config.get('default_version')
        
        settings = self.get_ini_settings(version)
        if not settings['success']:
            return settings
        
        disabled = settings['settings'].get('disable_functions', '')
        functions = [f.strip() for f in disabled.split(',') if f.strip()]
        
        return {
            'success': True,
            'disabled_functions': functions,
            'count': len(functions)
        }
    
    def set_disabled_functions(self, functions: List[str], version: str = None) -> dict:
        """Set disabled functions"""
        version = version or self.config.get('default_version')
        
        value = ','.join(functions)
        return self.update_ini_setting('disable_functions', value, version)
    
    # ===== Composer Management =====
    
    def get_composer_version(self) -> dict:
        """Get Composer version"""
        try:
            result = subprocess.run(['composer', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r'Composer version (\S+)', result.stdout)
                if match:
                    return {'success': True, 'version': match.group(1)}
            return {'success': False, 'message': 'Composer not found'}
        except:
            return {'success': False, 'message': 'Composer not installed'}
    
    def install_composer(self) -> dict:
        """Install Composer"""
        if self.os_type == 'windows':
            return {'success': False, 'message': 'Download Composer from getcomposer.org'}
        
        try:
            # Download installer
            subprocess.run([
                'php', '-r', 
                "copy('https://getcomposer.org/installer', 'composer-setup.php');"
            ], check=True)
            
            # Install
            subprocess.run([
                'php', 'composer-setup.php', '--install-dir=/usr/local/bin', '--filename=composer'
            ], check=True)
            
            # Cleanup
            Path('composer-setup.php').unlink(missing_ok=True)
            
            return {'success': True, 'message': 'Composer installed'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Helper Methods =====
    
    def _get_version_info(self, version: str) -> Optional[dict]:
        """Get version info by version string"""
        for v in self.config.get('installed_versions', []):
            if v['version'].startswith(version) or version in v['version']:
                return v
        return None
    
    # ===== File Operations =====
    
    def _read_config(self) -> dict:
        try:
            if self.config_path.exists():
                return json.loads(self.config_path.read_text())
        except:
            pass
        return self._default_config()
    
    def _write_config(self, config: dict) -> None:
        try:
            self.config_path.write_text(json.dumps(config, indent=2))
        except Exception as e:
            print(f"Failed to write PHP config: {e}")


# Global instance
php_manager = PHPManager()
