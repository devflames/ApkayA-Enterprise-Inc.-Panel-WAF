"""
Apkaya Panel WAF - Web Server Management Module
Nginx/Apache configuration, virtual hosts, rewrites, proxy settings

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import json
import subprocess
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import platform


class WebServerManager:
    """Complete web server management for Nginx and Apache"""
    
    def __init__(self, config_path='data/webserver_config.json'):
        """Initialize web server manager"""
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.os_type = platform.system().lower()
        
        # Detect web server
        self.server_type = self._detect_server()
        
        # Path configurations
        self.paths = self._get_default_paths()
        
        # Load config
        if not self.config_path.exists():
            self._write_config(self._default_config())
        self.config = self._read_config()
    
    def _detect_server(self) -> str:
        """Detect installed web server"""
        try:
            result = subprocess.run(['nginx', '-v'], capture_output=True, text=True)
            if result.returncode == 0 or 'nginx' in result.stderr.lower():
                return 'nginx'
        except:
            pass
        
        try:
            result = subprocess.run(['apache2', '-v'], capture_output=True, text=True)
            if result.returncode == 0:
                return 'apache'
        except:
            pass
        
        try:
            result = subprocess.run(['httpd', '-v'], capture_output=True, text=True)
            if result.returncode == 0:
                return 'apache'
        except:
            pass
        
        return 'none'
    
    def _get_default_paths(self) -> dict:
        """Get default paths based on OS and server"""
        if self.os_type == 'windows':
            return {
                'nginx_conf': 'C:/nginx/conf/nginx.conf',
                'nginx_sites': 'C:/nginx/conf/sites-enabled',
                'apache_conf': 'C:/Apache24/conf/httpd.conf',
                'apache_sites': 'C:/Apache24/conf/sites-enabled',
                'www_root': 'C:/www'
            }
        else:
            return {
                'nginx_conf': '/etc/nginx/nginx.conf',
                'nginx_sites': '/etc/nginx/sites-enabled',
                'nginx_available': '/etc/nginx/sites-available',
                'apache_conf': '/etc/apache2/apache2.conf',
                'apache_sites': '/etc/apache2/sites-enabled',
                'apache_available': '/etc/apache2/sites-available',
                'www_root': '/var/www'
            }
    
    @staticmethod
    def _default_config() -> dict:
        return {
            'server_type': 'nginx',
            'sites': [],
            'global_settings': {
                'worker_processes': 'auto',
                'worker_connections': 1024,
                'keepalive_timeout': 65,
                'gzip': True
            }
        }
    
    # ===== Server Status =====
    
    def get_status(self) -> dict:
        """Get web server status"""
        status = {
            'success': True,
            'server_type': self.server_type,
            'running': self._is_running(),
            'version': self._get_version(),
            'config_valid': self._test_config(),
            'sites_count': len(self.config.get('sites', []))
        }
        
        # Add resource info
        if self.server_type == 'nginx':
            status['workers'] = self._get_nginx_workers()
        
        return status
    
    def _is_running(self) -> bool:
        """Check if server is running"""
        try:
            if self.server_type == 'nginx':
                result = subprocess.run(['pgrep', 'nginx'], capture_output=True)
            else:
                result = subprocess.run(['pgrep', '-f', 'apache|httpd'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _get_version(self) -> str:
        """Get server version"""
        try:
            if self.server_type == 'nginx':
                result = subprocess.run(['nginx', '-v'], capture_output=True, text=True)
                return result.stderr.strip()
            else:
                result = subprocess.run(['apache2', '-v'], capture_output=True, text=True)
                return result.stdout.split('\n')[0] if result.stdout else ''
        except:
            return 'unknown'
    
    def _test_config(self) -> bool:
        """Test configuration syntax"""
        try:
            if self.server_type == 'nginx':
                result = subprocess.run(['nginx', '-t'], capture_output=True)
            else:
                result = subprocess.run(['apache2ctl', 'configtest'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _get_nginx_workers(self) -> int:
        """Get number of Nginx workers"""
        try:
            result = subprocess.run(['pgrep', '-c', 'nginx'], capture_output=True, text=True)
            return int(result.stdout.strip()) - 1  # Subtract master process
        except:
            return 0
    
    # ===== Server Control =====
    
    def start(self) -> dict:
        """Start web server"""
        try:
            if self.server_type == 'nginx':
                subprocess.run(['nginx'], check=True)
            else:
                subprocess.run(['systemctl', 'start', 'apache2'], check=True)
            
            return {'success': True, 'message': f'{self.server_type.title()} started'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def stop(self) -> dict:
        """Stop web server"""
        try:
            if self.server_type == 'nginx':
                subprocess.run(['nginx', '-s', 'stop'], check=True)
            else:
                subprocess.run(['systemctl', 'stop', 'apache2'], check=True)
            
            return {'success': True, 'message': f'{self.server_type.title()} stopped'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def restart(self) -> dict:
        """Restart web server"""
        try:
            if self.server_type == 'nginx':
                subprocess.run(['nginx', '-s', 'reload'], check=True)
            else:
                subprocess.run(['systemctl', 'restart', 'apache2'], check=True)
            
            return {'success': True, 'message': f'{self.server_type.title()} restarted'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def reload(self) -> dict:
        """Reload configuration"""
        if not self._test_config():
            return {'success': False, 'message': 'Configuration test failed'}
        
        try:
            if self.server_type == 'nginx':
                subprocess.run(['nginx', '-s', 'reload'], check=True)
            else:
                subprocess.run(['systemctl', 'reload', 'apache2'], check=True)
            
            return {'success': True, 'message': 'Configuration reloaded'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Virtual Host / Site Management =====
    
    def create_site(self, domain: str, root_path: str = None,
                   php_version: str = None, ssl: bool = False) -> dict:
        """Create a new site/virtual host"""
        
        # Validate domain
        if not self._validate_domain(domain):
            return {'success': False, 'message': 'Invalid domain name'}
        
        # Check if exists
        if any(s['domain'] == domain for s in self.config.get('sites', [])):
            return {'success': False, 'message': f'Site {domain} already exists'}
        
        # Set root path
        if not root_path:
            root_path = f"{self.paths['www_root']}/{domain}"
        
        root_path = Path(root_path)
        
        try:
            # Create directory
            root_path.mkdir(parents=True, exist_ok=True)
            
            # Create index file
            index_file = root_path / 'index.html'
            if not index_file.exists():
                index_file.write_text(f'''<!DOCTYPE html>
<html>
<head><title>Welcome to {domain}</title></head>
<body>
<h1>Welcome to {domain}!</h1>
<p>This site is powered by Apkaya Panel.</p>
</body>
</html>
''')
            
            # Generate config
            if self.server_type == 'nginx':
                config_content = self._generate_nginx_site(domain, str(root_path), php_version, ssl)
            else:
                config_content = self._generate_apache_site(domain, str(root_path), php_version, ssl)
            
            # Save config file
            if self.server_type == 'nginx':
                config_file = Path(self.paths['nginx_available']) / f"{domain}.conf"
                enabled_link = Path(self.paths['nginx_sites']) / f"{domain}.conf"
            else:
                config_file = Path(self.paths['apache_available']) / f"{domain}.conf"
                enabled_link = Path(self.paths['apache_sites']) / f"{domain}.conf"
            
            config_file.parent.mkdir(parents=True, exist_ok=True)
            config_file.write_text(config_content)
            
            # Enable site (symlink)
            enabled_link.parent.mkdir(parents=True, exist_ok=True)
            if not enabled_link.exists():
                if self.os_type == 'windows':
                    shutil.copy(config_file, enabled_link)
                else:
                    enabled_link.symlink_to(config_file)
            
            # Save to config
            site_info = {
                'id': len(self.config.get('sites', [])) + 1,
                'domain': domain,
                'root_path': str(root_path),
                'config_file': str(config_file),
                'php_version': php_version,
                'ssl': ssl,
                'enabled': True,
                'created_at': datetime.now().isoformat()
            }
            
            self.config.setdefault('sites', []).append(site_info)
            self._write_config(self.config)
            
            # Reload server
            self.reload()
            
            return {
                'success': True,
                'message': f'Site {domain} created',
                'site': site_info
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to create site: {str(e)}'}
    
    def delete_site(self, domain: str, remove_files: bool = False) -> dict:
        """Delete a site"""
        
        site = self._get_site_by_domain(domain)
        if not site:
            return {'success': False, 'message': 'Site not found'}
        
        try:
            # Remove config files
            config_file = Path(site['config_file'])
            if config_file.exists():
                config_file.unlink()
            
            # Remove enabled link
            if self.server_type == 'nginx':
                enabled_link = Path(self.paths['nginx_sites']) / f"{domain}.conf"
            else:
                enabled_link = Path(self.paths['apache_sites']) / f"{domain}.conf"
            
            if enabled_link.exists():
                enabled_link.unlink()
            
            # Remove site files
            if remove_files:
                root_path = Path(site['root_path'])
                if root_path.exists():
                    shutil.rmtree(root_path)
            
            # Remove from config
            self.config['sites'] = [s for s in self.config['sites'] if s['domain'] != domain]
            self._write_config(self.config)
            
            # Reload server
            self.reload()
            
            return {'success': True, 'message': f'Site {domain} deleted'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to delete site: {str(e)}'}
    
    def enable_site(self, domain: str) -> dict:
        """Enable a site"""
        
        site = self._get_site_by_domain(domain)
        if not site:
            return {'success': False, 'message': 'Site not found'}
        
        try:
            config_file = Path(site['config_file'])
            
            if self.server_type == 'nginx':
                enabled_link = Path(self.paths['nginx_sites']) / f"{domain}.conf"
            else:
                enabled_link = Path(self.paths['apache_sites']) / f"{domain}.conf"
            
            if not enabled_link.exists():
                if self.os_type == 'windows':
                    shutil.copy(config_file, enabled_link)
                else:
                    enabled_link.symlink_to(config_file)
            
            site['enabled'] = True
            self._write_config(self.config)
            self.reload()
            
            return {'success': True, 'message': f'Site {domain} enabled'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def disable_site(self, domain: str) -> dict:
        """Disable a site"""
        
        site = self._get_site_by_domain(domain)
        if not site:
            return {'success': False, 'message': 'Site not found'}
        
        try:
            if self.server_type == 'nginx':
                enabled_link = Path(self.paths['nginx_sites']) / f"{domain}.conf"
            else:
                enabled_link = Path(self.paths['apache_sites']) / f"{domain}.conf"
            
            if enabled_link.exists():
                enabled_link.unlink()
            
            site['enabled'] = False
            self._write_config(self.config)
            self.reload()
            
            return {'success': True, 'message': f'Site {domain} disabled'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def list_sites(self) -> dict:
        """List all sites"""
        sites = self.config.get('sites', [])
        
        # Update status for each site
        for site in sites:
            site['running'] = self._is_site_accessible(site['domain'])
        
        return {
            'success': True,
            'sites': sites,
            'count': len(sites)
        }
    
    def get_site(self, domain: str) -> dict:
        """Get site details"""
        site = self._get_site_by_domain(domain)
        if not site:
            return {'success': False, 'message': 'Site not found'}
        
        # Read current config
        config_file = Path(site['config_file'])
        if config_file.exists():
            site['config_content'] = config_file.read_text()
        
        return {'success': True, 'site': site}
    
    # ===== Site Configuration =====
    
    def update_site_config(self, domain: str, config_content: str) -> dict:
        """Update site configuration"""
        
        site = self._get_site_by_domain(domain)
        if not site:
            return {'success': False, 'message': 'Site not found'}
        
        config_file = Path(site['config_file'])
        
        try:
            # Backup current config
            backup_file = config_file.with_suffix('.conf.bak')
            if config_file.exists():
                shutil.copy(config_file, backup_file)
            
            # Write new config
            config_file.write_text(config_content)
            
            # Test config
            if not self._test_config():
                # Restore backup
                if backup_file.exists():
                    shutil.copy(backup_file, config_file)
                return {'success': False, 'message': 'Configuration syntax error'}
            
            self.reload()
            
            return {'success': True, 'message': 'Configuration updated'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def enable_ssl(self, domain: str, cert_path: str, key_path: str) -> dict:
        """Enable SSL for a site"""
        
        site = self._get_site_by_domain(domain)
        if not site:
            return {'success': False, 'message': 'Site not found'}
        
        if not Path(cert_path).exists():
            return {'success': False, 'message': 'Certificate file not found'}
        
        if not Path(key_path).exists():
            return {'success': False, 'message': 'Private key file not found'}
        
        try:
            # Regenerate config with SSL
            if self.server_type == 'nginx':
                config_content = self._generate_nginx_site(
                    domain, site['root_path'],
                    site.get('php_version'), True,
                    cert_path, key_path
                )
            else:
                config_content = self._generate_apache_site(
                    domain, site['root_path'],
                    site.get('php_version'), True,
                    cert_path, key_path
                )
            
            config_file = Path(site['config_file'])
            config_file.write_text(config_content)
            
            site['ssl'] = True
            site['cert_path'] = cert_path
            site['key_path'] = key_path
            self._write_config(self.config)
            
            self.reload()
            
            return {'success': True, 'message': f'SSL enabled for {domain}'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Rewrite Rules =====
    
    def add_rewrite(self, domain: str, pattern: str, replacement: str,
                   flags: str = 'last') -> dict:
        """Add rewrite rule"""
        
        site = self._get_site_by_domain(domain)
        if not site:
            return {'success': False, 'message': 'Site not found'}
        
        rewrite = {
            'pattern': pattern,
            'replacement': replacement,
            'flags': flags
        }
        
        site.setdefault('rewrites', []).append(rewrite)
        self._write_config(self.config)
        
        # Regenerate config
        self._regenerate_site_config(site)
        
        return {'success': True, 'message': 'Rewrite rule added'}
    
    def list_rewrites(self, domain: str) -> dict:
        """List rewrite rules for a site"""
        site = self._get_site_by_domain(domain)
        if not site:
            return {'success': False, 'message': 'Site not found'}
        
        return {
            'success': True,
            'rewrites': site.get('rewrites', [])
        }
    
    # ===== Proxy Configuration =====
    
    def add_proxy(self, domain: str, path: str, target: str,
                 websocket: bool = False) -> dict:
        """Add reverse proxy location"""
        
        site = self._get_site_by_domain(domain)
        if not site:
            return {'success': False, 'message': 'Site not found'}
        
        proxy = {
            'path': path,
            'target': target,
            'websocket': websocket
        }
        
        site.setdefault('proxies', []).append(proxy)
        self._write_config(self.config)
        
        self._regenerate_site_config(site)
        
        return {'success': True, 'message': 'Proxy configuration added'}
    
    # ===== Config Generators =====
    
    def _generate_nginx_site(self, domain: str, root_path: str,
                            php_version: str = None, ssl: bool = False,
                            cert_path: str = None, key_path: str = None) -> str:
        """Generate Nginx site configuration"""
        
        config = f'''server {{
    listen 80;
    server_name {domain} www.{domain};
    root {root_path};
    index index.html index.htm index.php;
    
    # Logging
    access_log /var/log/nginx/{domain}.access.log;
    error_log /var/log/nginx/{domain}.error.log;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
    
    # Static files
    location ~* \\.(jpg|jpeg|png|gif|ico|css|js|pdf|txt|woff|woff2|ttf|svg)$ {{
        expires 30d;
        add_header Cache-Control "public, immutable";
    }}
    
    # Deny hidden files
    location ~ /\\. {{
        deny all;
    }}
'''
        
        # PHP configuration
        if php_version:
            config += f'''
    # PHP handling
    location ~ \\.php$ {{
        fastcgi_pass unix:/var/run/php/php{php_version}-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
'''
        
        config += '}\n'
        
        # SSL configuration
        if ssl and cert_path and key_path:
            config += f'''
server {{
    listen 443 ssl http2;
    server_name {domain} www.{domain};
    root {root_path};
    index index.html index.htm index.php;
    
    # SSL
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
'''
            if php_version:
                config += f'''
    location ~ \\.php$ {{
        fastcgi_pass unix:/var/run/php/php{php_version}-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
'''
            config += '}\n'
        
        return config
    
    def _generate_apache_site(self, domain: str, root_path: str,
                             php_version: str = None, ssl: bool = False,
                             cert_path: str = None, key_path: str = None) -> str:
        """Generate Apache site configuration"""
        
        config = f'''<VirtualHost *:80>
    ServerName {domain}
    ServerAlias www.{domain}
    DocumentRoot {root_path}
    
    <Directory {root_path}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Logging
    ErrorLog ${{APACHE_LOG_DIR}}/{domain}.error.log
    CustomLog ${{APACHE_LOG_DIR}}/{domain}.access.log combined
    
    # Security headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</VirtualHost>
'''
        
        if ssl and cert_path and key_path:
            config += f'''
<VirtualHost *:443>
    ServerName {domain}
    ServerAlias www.{domain}
    DocumentRoot {root_path}
    
    SSLEngine on
    SSLCertificateFile {cert_path}
    SSLCertificateKeyFile {key_path}
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    
    <Directory {root_path}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
'''
        
        return config
    
    def _regenerate_site_config(self, site: dict) -> None:
        """Regenerate site config with all settings"""
        if self.server_type == 'nginx':
            config = self._generate_nginx_site(
                site['domain'], site['root_path'],
                site.get('php_version'), site.get('ssl'),
                site.get('cert_path'), site.get('key_path')
            )
        else:
            config = self._generate_apache_site(
                site['domain'], site['root_path'],
                site.get('php_version'), site.get('ssl'),
                site.get('cert_path'), site.get('key_path')
            )
        
        config_file = Path(site['config_file'])
        config_file.write_text(config)
        self.reload()
    
    # ===== Helper Methods =====
    
    def _validate_domain(self, domain: str) -> bool:
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def _get_site_by_domain(self, domain: str) -> Optional[dict]:
        for site in self.config.get('sites', []):
            if site['domain'] == domain:
                return site
        return None
    
    def _is_site_accessible(self, domain: str) -> bool:
        try:
            import urllib.request
            response = urllib.request.urlopen(f'http://{domain}', timeout=5)
            return response.status == 200
        except:
            return False
    
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
            print(f"Failed to write webserver config: {e}")


# Global instance
webserver_manager = WebServerManager()
