"""
ApkayA Enterprise Control Panel - FTP Management Module
FTP server management, user accounts, permissions

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import json
import subprocess
import re
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import platform

# Platform-specific password hashing
try:
    import crypt
    HAS_CRYPT = True
except ImportError:
    HAS_CRYPT = False


def hash_password(password: str) -> str:
    """Hash password for FTP - cross-platform"""
    if HAS_CRYPT:
        return crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    else:
        # Windows fallback - use SHA512 with salt
        import secrets
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"$6${salt}${hashed.hex()}"


class FTPManager:
    """Complete FTP server management"""
    
    def __init__(self, config_path='data/ftp_config.json'):
        """Initialize FTP manager"""
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.os_type = platform.system().lower()
        
        # Detect FTP server
        self.server_type = self._detect_server()
        
        # Load config
        if not self.config_path.exists():
            self._write_config(self._default_config())
        self.config = self._read_config()
    
    def _detect_server(self) -> str:
        """Detect installed FTP server"""
        servers = ['vsftpd', 'proftpd', 'pure-ftpd']
        
        for server in servers:
            try:
                result = subprocess.run(['which', server], capture_output=True)
                if result.returncode == 0:
                    return server
            except:
                pass
        
        return 'none'
    
    @staticmethod
    def _default_config() -> dict:
        return {
            'server_type': 'vsftpd',
            'users': [],
            'settings': {
                'anonymous_enable': False,
                'local_enable': True,
                'write_enable': True,
                'chroot_local_user': True,
                'allow_writeable_chroot': True,
                'pasv_min_port': 40000,
                'pasv_max_port': 40100,
                'max_clients': 100,
                'max_per_ip': 5,
                'idle_session_timeout': 600
            }
        }
    
    # ===== Server Status =====
    
    def get_status(self) -> dict:
        """Get FTP server status"""
        return {
            'success': True,
            'server_type': self.server_type,
            'running': self._is_running(),
            'users_count': len(self.config.get('users', [])),
            'settings': self.config.get('settings', {})
        }
    
    def _is_running(self) -> bool:
        """Check if FTP server is running"""
        if self.os_type == 'windows':
            return False
        
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', self.server_type],
                capture_output=True, text=True
            )
            return result.stdout.strip() == 'active'
        except:
            return False
    
    # ===== Server Control =====
    
    def start(self) -> dict:
        """Start FTP server"""
        try:
            subprocess.run(['systemctl', 'start', self.server_type], check=True)
            return {'success': True, 'message': f'{self.server_type} started'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def stop(self) -> dict:
        """Stop FTP server"""
        try:
            subprocess.run(['systemctl', 'stop', self.server_type], check=True)
            return {'success': True, 'message': f'{self.server_type} stopped'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def restart(self) -> dict:
        """Restart FTP server"""
        try:
            subprocess.run(['systemctl', 'restart', self.server_type], check=True)
            return {'success': True, 'message': f'{self.server_type} restarted'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== User Management =====
    
    def create_user(self, username: str, password: str, home_dir: str,
                   quota_mb: int = 0, description: str = '') -> dict:
        """Create FTP user"""
        
        # Validate username
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,31}$', username):
            return {'success': False, 'message': 'Invalid username format'}
        
        # Check if exists
        if any(u['username'] == username for u in self.config.get('users', [])):
            return {'success': False, 'message': f'User {username} already exists'}
        
        try:
            home_path = Path(home_dir)
            home_path.mkdir(parents=True, exist_ok=True)
            
            if self.os_type != 'windows':
                # Create system user (for vsftpd)
                if self.server_type == 'vsftpd':
                    # Create user with nologin shell
                    subprocess.run([
                        'useradd', '-d', str(home_path),
                        '-s', '/sbin/nologin',
                        '-c', description or 'FTP User',
                        username
                    ], check=True, capture_output=True)
                    
                    # Set password
                    process = subprocess.Popen(
                        ['chpasswd'],
                        stdin=subprocess.PIPE,
                        text=True
                    )
                    process.communicate(f'{username}:{password}')
                    
                    # Set ownership
                    subprocess.run(['chown', f'{username}:{username}', str(home_path)])
                    subprocess.run(['chmod', '755', str(home_path)])
                
                elif self.server_type == 'pure-ftpd':
                    # Create virtual user
                    subprocess.run([
                        'pure-pw', 'useradd', username,
                        '-u', 'ftp', '-d', str(home_path),
                        '-m'
                    ], check=True, input=f'{password}\n{password}\n'.encode())
                    
                    # Update database
                    subprocess.run(['pure-pw', 'mkdb'], check=True)
            
            # Save to config
            user_info = {
                'id': len(self.config.get('users', [])) + 1,
                'username': username,
                'home_dir': str(home_path),
                'quota_mb': quota_mb,
                'description': description,
                'enabled': True,
                'created_at': datetime.now().isoformat()
            }
            
            self.config.setdefault('users', []).append(user_info)
            self._write_config(self.config)
            
            return {
                'success': True,
                'message': f'FTP user {username} created',
                'user': user_info
            }
            
        except subprocess.CalledProcessError as e:
            return {'success': False, 'message': f'Failed to create user: {e.stderr if hasattr(e, "stderr") else str(e)}'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def delete_user(self, username: str, remove_home: bool = False) -> dict:
        """Delete FTP user"""
        
        user = self._get_user(username)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        try:
            if self.os_type != 'windows':
                if self.server_type == 'vsftpd':
                    # Delete system user
                    cmd = ['userdel']
                    if remove_home:
                        cmd.append('-r')
                    cmd.append(username)
                    subprocess.run(cmd, capture_output=True)
                
                elif self.server_type == 'pure-ftpd':
                    subprocess.run(['pure-pw', 'userdel', username], capture_output=True)
                    subprocess.run(['pure-pw', 'mkdb'], capture_output=True)
            
            # Remove from config
            self.config['users'] = [u for u in self.config['users'] if u['username'] != username]
            self._write_config(self.config)
            
            return {'success': True, 'message': f'User {username} deleted'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def change_password(self, username: str, new_password: str) -> dict:
        """Change FTP user password"""
        
        user = self._get_user(username)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        try:
            if self.os_type != 'windows':
                if self.server_type == 'vsftpd':
                    process = subprocess.Popen(
                        ['chpasswd'],
                        stdin=subprocess.PIPE,
                        text=True
                    )
                    process.communicate(f'{username}:{new_password}')
                
                elif self.server_type == 'pure-ftpd':
                    subprocess.run([
                        'pure-pw', 'passwd', username
                    ], input=f'{new_password}\n{new_password}\n'.encode(), check=True)
                    subprocess.run(['pure-pw', 'mkdb'], check=True)
            
            return {'success': True, 'message': 'Password changed'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def enable_user(self, username: str) -> dict:
        """Enable FTP user"""
        user = self._get_user(username)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        user['enabled'] = True
        self._write_config(self.config)
        
        # Actually enable in FTP server
        if self.os_type != 'windows' and self.server_type == 'vsftpd':
            # Remove from denied users list if present
            denied_file = Path('/etc/vsftpd/user_list')
            if denied_file.exists():
                content = denied_file.read_text()
                content = '\n'.join([line for line in content.split('\n') if line.strip() != username])
                denied_file.write_text(content)
        
        return {'success': True, 'message': f'User {username} enabled'}
    
    def disable_user(self, username: str) -> dict:
        """Disable FTP user"""
        user = self._get_user(username)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        user['enabled'] = False
        self._write_config(self.config)
        
        # Actually disable in FTP server
        if self.os_type != 'windows' and self.server_type == 'vsftpd':
            denied_file = Path('/etc/vsftpd/user_list')
            denied_file.parent.mkdir(parents=True, exist_ok=True)
            with open(denied_file, 'a') as f:
                f.write(f'{username}\n')
        
        return {'success': True, 'message': f'User {username} disabled'}
    
    def list_users(self) -> dict:
        """List all FTP users"""
        return {
            'success': True,
            'users': self.config.get('users', []),
            'count': len(self.config.get('users', []))
        }
    
    def get_user(self, username: str) -> dict:
        """Get FTP user details"""
        user = self._get_user(username)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        return {'success': True, 'user': user}
    
    def update_user(self, username: str, updates: dict) -> dict:
        """Update FTP user"""
        user = self._get_user(username)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        allowed = ['quota_mb', 'description', 'home_dir']
        for key in allowed:
            if key in updates:
                user[key] = updates[key]
        
        self._write_config(self.config)
        
        return {'success': True, 'message': 'User updated', 'user': user}
    
    # ===== Quota Management =====
    
    def set_quota(self, username: str, quota_mb: int) -> dict:
        """Set user quota"""
        user = self._get_user(username)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        try:
            if self.os_type != 'windows' and quota_mb > 0:
                # Set disk quota using setquota
                quota_blocks = quota_mb * 1024  # Convert to 1K blocks
                subprocess.run([
                    'setquota', '-u', username,
                    str(quota_blocks), str(quota_blocks),
                    '0', '0', '/'
                ], capture_output=True)
            
            user['quota_mb'] = quota_mb
            self._write_config(self.config)
            
            return {'success': True, 'message': f'Quota set to {quota_mb}MB'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def get_quota_usage(self, username: str) -> dict:
        """Get quota usage for user"""
        user = self._get_user(username)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        try:
            if self.os_type != 'windows':
                result = subprocess.run(
                    ['quota', '-u', username],
                    capture_output=True, text=True
                )
                # Parse quota output
                # Simplified - real implementation would parse properly
            
            # Calculate actual directory size
            home_path = Path(user['home_dir'])
            if home_path.exists():
                total_size = sum(f.stat().st_size for f in home_path.rglob('*') if f.is_file())
                used_mb = total_size / (1024 * 1024)
            else:
                used_mb = 0
            
            return {
                'success': True,
                'username': username,
                'used_mb': round(used_mb, 2),
                'quota_mb': user.get('quota_mb', 0),
                'percentage': round((used_mb / user['quota_mb'] * 100) if user.get('quota_mb') else 0, 1)
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Server Configuration =====
    
    def get_settings(self) -> dict:
        """Get FTP server settings"""
        return {
            'success': True,
            'settings': self.config.get('settings', {})
        }
    
    def update_settings(self, settings: dict) -> dict:
        """Update FTP server settings"""
        
        allowed = [
            'anonymous_enable', 'local_enable', 'write_enable',
            'chroot_local_user', 'allow_writeable_chroot',
            'pasv_min_port', 'pasv_max_port',
            'max_clients', 'max_per_ip', 'idle_session_timeout'
        ]
        
        current = self.config.get('settings', {})
        
        for key in allowed:
            if key in settings:
                current[key] = settings[key]
        
        self.config['settings'] = current
        self._write_config(self.config)
        
        # Apply to server config
        if self.server_type == 'vsftpd':
            self._apply_vsftpd_config(current)
        
        return {'success': True, 'message': 'Settings updated'}
    
    def _apply_vsftpd_config(self, settings: dict) -> None:
        """Apply settings to vsftpd.conf"""
        config_file = Path('/etc/vsftpd.conf')
        if not config_file.exists():
            config_file = Path('/etc/vsftpd/vsftpd.conf')
        
        if not config_file.exists():
            return
        
        try:
            content = config_file.read_text()
            
            mappings = {
                'anonymous_enable': 'anonymous_enable',
                'local_enable': 'local_enable',
                'write_enable': 'write_enable',
                'chroot_local_user': 'chroot_local_user',
                'allow_writeable_chroot': 'allow_writeable_chroot',
                'pasv_min_port': 'pasv_min_port',
                'pasv_max_port': 'pasv_max_port',
                'max_clients': 'max_clients',
                'max_per_ip': 'max_per_ip',
                'idle_session_timeout': 'idle_session_timeout'
            }
            
            for key, vsftpd_key in mappings.items():
                if key in settings:
                    value = settings[key]
                    if isinstance(value, bool):
                        value = 'YES' if value else 'NO'
                    
                    pattern = rf'^#?{vsftpd_key}=.*$'
                    replacement = f'{vsftpd_key}={value}'
                    
                    if re.search(pattern, content, re.MULTILINE):
                        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
                    else:
                        content += f'\n{replacement}'
            
            config_file.write_text(content)
            self.restart()
            
        except Exception as e:
            print(f"Failed to apply vsftpd config: {e}")
    
    # ===== Logging =====
    
    def get_logs(self, lines: int = 100) -> dict:
        """Get FTP server logs"""
        
        log_paths = [
            '/var/log/vsftpd.log',
            '/var/log/proftpd/proftpd.log',
            '/var/log/pure-ftpd/transfer.log',
            '/var/log/xferlog'
        ]
        
        for log_path in log_paths:
            if Path(log_path).exists():
                try:
                    with open(log_path, 'r') as f:
                        all_lines = f.readlines()
                        recent = all_lines[-lines:] if len(all_lines) > lines else all_lines
                        return {
                            'success': True,
                            'log_file': log_path,
                            'lines': [line.strip() for line in recent]
                        }
                except:
                    pass
        
        return {'success': True, 'log_file': None, 'lines': []}
    
    def get_transfer_history(self, username: str = None, limit: int = 50) -> dict:
        """Get FTP transfer history"""
        
        # Parse xferlog format
        xferlog = Path('/var/log/xferlog')
        if not xferlog.exists():
            return {'success': True, 'transfers': []}
        
        transfers = []
        
        try:
            with open(xferlog, 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 17:
                        transfer = {
                            'timestamp': ' '.join(parts[0:5]),
                            'duration': parts[5],
                            'host': parts[6],
                            'size': int(parts[7]) if parts[7].isdigit() else 0,
                            'filename': parts[8],
                            'direction': 'upload' if parts[11] == 'i' else 'download',
                            'user': parts[13]
                        }
                        
                        if username and transfer['user'] != username:
                            continue
                        
                        transfers.append(transfer)
            
            # Return most recent
            transfers = transfers[-limit:]
            transfers.reverse()
            
            return {
                'success': True,
                'transfers': transfers,
                'count': len(transfers)
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Connection Info =====
    
    def get_active_connections(self) -> dict:
        """Get active FTP connections"""
        
        connections = []
        
        try:
            # Check with netstat
            result = subprocess.run(
                ['netstat', '-tnp'],
                capture_output=True, text=True
            )
            
            for line in result.stdout.split('\n'):
                if ':21' in line or ':20' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        connections.append({
                            'local': parts[3],
                            'remote': parts[4],
                            'state': parts[5] if len(parts) > 5 else 'UNKNOWN'
                        })
            
            return {
                'success': True,
                'connections': connections,
                'count': len(connections)
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Helper Methods =====
    
    def _get_user(self, username: str) -> Optional[dict]:
        """Get user by username"""
        for user in self.config.get('users', []):
            if user['username'] == username:
                return user
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
            print(f"Failed to write FTP config: {e}")


# Global instance
ftp_manager = FTPManager()
