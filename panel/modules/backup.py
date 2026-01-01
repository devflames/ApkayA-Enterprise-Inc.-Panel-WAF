"""
ApkayA Enterprise Control Panel - Backup Management Module
Full system backup, site backups, database backups with scheduling and cloud storage

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
"""

import os
import json
import subprocess
import shutil
import tarfile
import gzip
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import threading


class BackupManager:
    """Complete backup management system"""
    
    def __init__(self, config_path='data/backup_config.json', backup_path='backup'):
        """Initialize backup manager"""
        self.config_path = Path(config_path)
        self.backup_path = Path(backup_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_path.mkdir(parents=True, exist_ok=True)
        
        # Load config
        if not self.config_path.exists():
            self._write_config(self._default_config())
        self.config = self._read_config()
    
    @staticmethod
    def _default_config() -> dict:
        return {
            'auto_backup': True,
            'retention_days': 30,
            'compression': 'gzip',
            'backups': [],
            'schedules': [],
            'cloud_storage': {},
            'exclude_patterns': ['*.log', '*.tmp', '__pycache__', '.git']
        }
    
    # ===== Site Backups =====
    
    def backup_site(self, site_name: str, site_path: str, 
                   include_db: bool = True, db_name: str = None) -> dict:
        """Create backup of a website"""
        
        if not Path(site_path).exists():
            return {'success': False, 'message': f'Site path not found: {site_path}'}
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"site_{site_name}_{timestamp}"
            backup_dir = self.backup_path / 'sites' / site_name
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Create archive
            archive_path = backup_dir / f"{backup_name}.tar.gz"
            
            with tarfile.open(archive_path, 'w:gz') as tar:
                tar.add(site_path, arcname=site_name, 
                       filter=lambda x: self._exclude_filter(x))
            
            # Calculate size and hash
            size = archive_path.stat().st_size
            file_hash = self._calculate_hash(archive_path)
            
            # Backup database if requested
            db_backup_path = None
            if include_db and db_name:
                db_result = self.backup_database(db_name)
                if db_result['success']:
                    db_backup_path = db_result.get('path')
            
            # Record backup
            backup_info = {
                'id': len(self.config['backups']) + 1,
                'type': 'site',
                'name': backup_name,
                'site_name': site_name,
                'path': str(archive_path),
                'db_backup': db_backup_path,
                'size': size,
                'size_human': self._human_size(size),
                'hash': file_hash,
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=self.config['retention_days'])).isoformat()
            }
            
            self.config['backups'].append(backup_info)
            self._write_config(self.config)
            self._cleanup_old_backups()
            
            return {
                'success': True,
                'message': f'Site backup created: {backup_name}',
                'backup': backup_info
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Backup failed: {str(e)}'}
    
    # ===== Database Backups =====
    
    def backup_database(self, db_name: str, db_type: str = 'mysql',
                       host: str = 'localhost', port: int = 3306,
                       user: str = 'root', password: str = '') -> dict:
        """Create database backup"""
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"db_{db_name}_{timestamp}"
            backup_dir = self.backup_path / 'databases'
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            dump_path = backup_dir / f"{backup_name}.sql"
            archive_path = backup_dir / f"{backup_name}.sql.gz"
            
            if db_type == 'mysql':
                # MySQL dump
                cmd = [
                    'mysqldump',
                    f'--host={host}',
                    f'--port={port}',
                    f'--user={user}',
                ]
                if password:
                    cmd.append(f'--password={password}')
                cmd.extend([
                    '--single-transaction',
                    '--quick',
                    '--lock-tables=false',
                    db_name
                ])
                
                with open(dump_path, 'w') as f:
                    result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
                
                if result.returncode != 0:
                    return {'success': False, 'message': f'mysqldump failed: {result.stderr}'}
            
            elif db_type == 'postgresql':
                # PostgreSQL dump
                env = os.environ.copy()
                if password:
                    env['PGPASSWORD'] = password
                
                cmd = [
                    'pg_dump',
                    f'--host={host}',
                    f'--port={port}',
                    f'--username={user}',
                    '--format=plain',
                    db_name
                ]
                
                with open(dump_path, 'w') as f:
                    result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, 
                                          text=True, env=env)
                
                if result.returncode != 0:
                    return {'success': False, 'message': f'pg_dump failed: {result.stderr}'}
            
            elif db_type == 'sqlite':
                # SQLite backup
                shutil.copy2(db_name, dump_path)
            
            else:
                return {'success': False, 'message': f'Unsupported database type: {db_type}'}
            
            # Compress
            with open(dump_path, 'rb') as f_in:
                with gzip.open(archive_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove uncompressed dump
            dump_path.unlink()
            
            # Calculate size and hash
            size = archive_path.stat().st_size
            file_hash = self._calculate_hash(archive_path)
            
            # Record backup
            backup_info = {
                'id': len(self.config['backups']) + 1,
                'type': 'database',
                'name': backup_name,
                'db_name': db_name,
                'db_type': db_type,
                'path': str(archive_path),
                'size': size,
                'size_human': self._human_size(size),
                'hash': file_hash,
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=self.config['retention_days'])).isoformat()
            }
            
            self.config['backups'].append(backup_info)
            self._write_config(self.config)
            
            return {
                'success': True,
                'message': f'Database backup created: {backup_name}',
                'backup': backup_info,
                'path': str(archive_path)
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Database backup failed: {str(e)}'}
    
    # ===== Directory Backups =====
    
    def backup_directory(self, path: str, name: str = None) -> dict:
        """Create backup of a directory"""
        
        source_path = Path(path)
        if not source_path.exists():
            return {'success': False, 'message': f'Path not found: {path}'}
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = name or source_path.name
            full_name = f"dir_{backup_name}_{timestamp}"
            backup_dir = self.backup_path / 'directories'
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            archive_path = backup_dir / f"{full_name}.tar.gz"
            
            with tarfile.open(archive_path, 'w:gz') as tar:
                tar.add(path, arcname=backup_name,
                       filter=lambda x: self._exclude_filter(x))
            
            size = archive_path.stat().st_size
            file_hash = self._calculate_hash(archive_path)
            
            backup_info = {
                'id': len(self.config['backups']) + 1,
                'type': 'directory',
                'name': full_name,
                'source_path': str(path),
                'path': str(archive_path),
                'size': size,
                'size_human': self._human_size(size),
                'hash': file_hash,
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=self.config['retention_days'])).isoformat()
            }
            
            self.config['backups'].append(backup_info)
            self._write_config(self.config)
            
            return {
                'success': True,
                'message': f'Directory backup created: {full_name}',
                'backup': backup_info
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Directory backup failed: {str(e)}'}
    
    # ===== Restore Operations =====
    
    def restore_backup(self, backup_id: int, restore_path: str = None,
                      overwrite: bool = False) -> dict:
        """Restore a backup"""
        
        backup = self._get_backup_by_id(backup_id)
        if not backup:
            return {'success': False, 'message': 'Backup not found'}
        
        backup_file = Path(backup['path'])
        if not backup_file.exists():
            return {'success': False, 'message': 'Backup file not found'}
        
        try:
            # Verify hash
            current_hash = self._calculate_hash(backup_file)
            if current_hash != backup.get('hash'):
                return {'success': False, 'message': 'Backup file integrity check failed'}
            
            if backup['type'] == 'database':
                return self._restore_database(backup, overwrite)
            else:
                return self._restore_files(backup, restore_path, overwrite)
            
        except Exception as e:
            return {'success': False, 'message': f'Restore failed: {str(e)}'}
    
    def _restore_files(self, backup: dict, restore_path: str, overwrite: bool) -> dict:
        """Restore file-based backup"""
        
        target_path = Path(restore_path) if restore_path else Path(backup.get('source_path', '/tmp/restore'))
        
        if target_path.exists() and not overwrite:
            return {'success': False, 'message': 'Target path exists. Use overwrite=True to replace'}
        
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        with tarfile.open(backup['path'], 'r:gz') as tar:
            tar.extractall(target_path.parent)
        
        return {
            'success': True,
            'message': f'Backup restored to {target_path}',
            'restore_path': str(target_path)
        }
    
    def _restore_database(self, backup: dict, overwrite: bool) -> dict:
        """Restore database backup"""
        
        db_name = backup.get('db_name')
        db_type = backup.get('db_type', 'mysql')
        
        # Decompress
        backup_file = Path(backup['path'])
        sql_file = backup_file.with_suffix('')  # Remove .gz
        
        with gzip.open(backup_file, 'rb') as f_in:
            with open(sql_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        try:
            if db_type == 'mysql':
                cmd = ['mysql', db_name]
                with open(sql_file, 'r') as f:
                    result = subprocess.run(cmd, stdin=f, capture_output=True, text=True)
                
                if result.returncode != 0:
                    return {'success': False, 'message': f'MySQL restore failed: {result.stderr}'}
            
            elif db_type == 'postgresql':
                cmd = ['psql', '-d', db_name]
                with open(sql_file, 'r') as f:
                    result = subprocess.run(cmd, stdin=f, capture_output=True, text=True)
                
                if result.returncode != 0:
                    return {'success': False, 'message': f'PostgreSQL restore failed: {result.stderr}'}
            
            return {
                'success': True,
                'message': f'Database {db_name} restored successfully'
            }
            
        finally:
            # Cleanup temp file
            if sql_file.exists():
                sql_file.unlink()
    
    # ===== Backup Management =====
    
    def list_backups(self, backup_type: str = None, 
                    limit: int = 50) -> dict:
        """List all backups"""
        
        backups = self.config.get('backups', [])
        
        if backup_type:
            backups = [b for b in backups if b.get('type') == backup_type]
        
        # Sort by date descending
        backups = sorted(backups, key=lambda x: x.get('created_at', ''), reverse=True)
        
        # Limit
        backups = backups[:limit]
        
        # Add status
        for backup in backups:
            backup['status'] = 'valid' if Path(backup['path']).exists() else 'missing'
            backup['expired'] = datetime.now() > datetime.fromisoformat(backup.get('expires_at', datetime.max.isoformat()))
        
        return {
            'success': True,
            'backups': backups,
            'count': len(backups),
            'total_size': sum(b.get('size', 0) for b in backups),
            'total_size_human': self._human_size(sum(b.get('size', 0) for b in backups))
        }
    
    def get_backup(self, backup_id: int) -> dict:
        """Get backup details"""
        
        backup = self._get_backup_by_id(backup_id)
        if not backup:
            return {'success': False, 'message': 'Backup not found'}
        
        backup['status'] = 'valid' if Path(backup['path']).exists() else 'missing'
        
        return {'success': True, 'backup': backup}
    
    def delete_backup(self, backup_id: int, delete_file: bool = True) -> dict:
        """Delete a backup"""
        
        backup = self._get_backup_by_id(backup_id)
        if not backup:
            return {'success': False, 'message': 'Backup not found'}
        
        try:
            if delete_file:
                backup_file = Path(backup['path'])
                if backup_file.exists():
                    backup_file.unlink()
            
            self.config['backups'] = [b for b in self.config['backups'] if b.get('id') != backup_id]
            self._write_config(self.config)
            
            return {'success': True, 'message': 'Backup deleted'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to delete backup: {str(e)}'}
    
    def _cleanup_old_backups(self) -> None:
        """Remove expired backups"""
        now = datetime.now()
        to_remove = []
        
        for backup in self.config.get('backups', []):
            expires_at = backup.get('expires_at')
            if expires_at:
                try:
                    if now > datetime.fromisoformat(expires_at):
                        to_remove.append(backup)
                except:
                    pass
        
        for backup in to_remove:
            self.delete_backup(backup['id'])
    
    # ===== Scheduled Backups =====
    
    def create_schedule(self, name: str, backup_type: str, target: str,
                       frequency: str, time: str = '02:00',
                       keep_count: int = 7) -> dict:
        """Create backup schedule"""
        
        valid_frequencies = ['daily', 'weekly', 'monthly']
        if frequency not in valid_frequencies:
            return {'success': False, 'message': f'Invalid frequency. Use: {valid_frequencies}'}
        
        schedule = {
            'id': len(self.config.get('schedules', [])) + 1,
            'name': name,
            'backup_type': backup_type,
            'target': target,
            'frequency': frequency,
            'time': time,
            'keep_count': keep_count,
            'enabled': True,
            'last_run': None,
            'next_run': self._calculate_next_run(frequency, time),
            'created_at': datetime.now().isoformat()
        }
        
        self.config.setdefault('schedules', []).append(schedule)
        self._write_config(self.config)
        
        return {
            'success': True,
            'message': f'Schedule created: {name}',
            'schedule': schedule
        }
    
    def list_schedules(self) -> dict:
        """List backup schedules"""
        return {
            'success': True,
            'schedules': self.config.get('schedules', []),
            'count': len(self.config.get('schedules', []))
        }
    
    def delete_schedule(self, schedule_id: int) -> dict:
        """Delete backup schedule"""
        self.config['schedules'] = [
            s for s in self.config.get('schedules', [])
            if s.get('id') != schedule_id
        ]
        self._write_config(self.config)
        return {'success': True, 'message': 'Schedule deleted'}
    
    def run_scheduled_backups(self) -> dict:
        """Run due scheduled backups"""
        now = datetime.now()
        results = []
        
        for schedule in self.config.get('schedules', []):
            if not schedule.get('enabled'):
                continue
            
            next_run = schedule.get('next_run')
            if not next_run:
                continue
            
            try:
                if now >= datetime.fromisoformat(next_run):
                    # Run backup
                    if schedule['backup_type'] == 'site':
                        result = self.backup_site(schedule['target'], schedule.get('site_path', ''))
                    elif schedule['backup_type'] == 'database':
                        result = self.backup_database(schedule['target'])
                    elif schedule['backup_type'] == 'directory':
                        result = self.backup_directory(schedule['target'])
                    else:
                        result = {'success': False, 'message': 'Unknown backup type'}
                    
                    results.append({
                        'schedule': schedule['name'],
                        'result': result
                    })
                    
                    # Update schedule
                    schedule['last_run'] = now.isoformat()
                    schedule['next_run'] = self._calculate_next_run(
                        schedule['frequency'], schedule['time']
                    )
            except:
                pass
        
        self._write_config(self.config)
        
        return {
            'success': True,
            'executed': len(results),
            'results': results
        }
    
    def _calculate_next_run(self, frequency: str, time: str) -> str:
        """Calculate next run time"""
        now = datetime.now()
        hour, minute = map(int, time.split(':'))
        
        next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        
        if next_run <= now:
            if frequency == 'daily':
                next_run += timedelta(days=1)
            elif frequency == 'weekly':
                next_run += timedelta(weeks=1)
            elif frequency == 'monthly':
                next_run += timedelta(days=30)
        
        return next_run.isoformat()
    
    # ===== Cloud Storage =====
    
    def upload_to_cloud(self, backup_id: int, provider: str) -> dict:
        """Upload backup to cloud storage"""
        
        backup = self._get_backup_by_id(backup_id)
        if not backup:
            return {'success': False, 'message': 'Backup not found'}
        
        cloud_config = self.config.get('cloud_storage', {}).get(provider)
        if not cloud_config:
            return {'success': False, 'message': f'Cloud provider {provider} not configured'}
        
        # Provider-specific upload (simplified)
        if provider == 's3':
            return self._upload_to_s3(backup, cloud_config)
        elif provider == 'azure':
            return self._upload_to_azure(backup, cloud_config)
        elif provider == 'gcs':
            return self._upload_to_gcs(backup, cloud_config)
        elif provider == 'ftp':
            return self._upload_to_ftp(backup, cloud_config)
        
        return {'success': False, 'message': f'Unsupported provider: {provider}'}
    
    def configure_cloud(self, provider: str, config: dict) -> dict:
        """Configure cloud storage provider"""
        
        required = {
            's3': ['bucket', 'access_key', 'secret_key', 'region'],
            'azure': ['container', 'connection_string'],
            'gcs': ['bucket', 'credentials_file'],
            'ftp': ['host', 'user', 'password', 'path']
        }
        
        if provider not in required:
            return {'success': False, 'message': f'Unknown provider: {provider}'}
        
        for field in required[provider]:
            if field not in config:
                return {'success': False, 'message': f'Missing required field: {field}'}
        
        self.config.setdefault('cloud_storage', {})[provider] = config
        self._write_config(self.config)
        
        return {'success': True, 'message': f'{provider} configured successfully'}
    
    def _upload_to_s3(self, backup: dict, config: dict) -> dict:
        """Upload to AWS S3"""
        try:
            import boto3
            
            s3 = boto3.client(
                's3',
                aws_access_key_id=config['access_key'],
                aws_secret_access_key=config['secret_key'],
                region_name=config['region']
            )
            
            backup_file = Path(backup['path'])
            key = f"backups/{backup['type']}/{backup_file.name}"
            
            s3.upload_file(str(backup_file), config['bucket'], key)
            
            return {'success': True, 'message': f'Uploaded to S3: {key}'}
            
        except ImportError:
            return {'success': False, 'message': 'boto3 not installed'}
        except Exception as e:
            return {'success': False, 'message': f'S3 upload failed: {str(e)}'}
    
    def _upload_to_azure(self, backup: dict, config: dict) -> dict:
        """Upload to Azure Blob Storage"""
        try:
            from azure.storage.blob import BlobServiceClient
            
            blob_service = BlobServiceClient.from_connection_string(config['connection_string'])
            container = blob_service.get_container_client(config['container'])
            
            backup_file = Path(backup['path'])
            blob_name = f"backups/{backup['type']}/{backup_file.name}"
            
            with open(backup_file, 'rb') as f:
                container.upload_blob(blob_name, f, overwrite=True)
            
            return {'success': True, 'message': f'Uploaded to Azure: {blob_name}'}
            
        except ImportError:
            return {'success': False, 'message': 'azure-storage-blob not installed'}
        except Exception as e:
            return {'success': False, 'message': f'Azure upload failed: {str(e)}'}
    
    def _upload_to_gcs(self, backup: dict, config: dict) -> dict:
        """Upload to Google Cloud Storage"""
        try:
            from google.cloud import storage
            
            client = storage.Client.from_service_account_json(config['credentials_file'])
            bucket = client.bucket(config['bucket'])
            
            backup_file = Path(backup['path'])
            blob_name = f"backups/{backup['type']}/{backup_file.name}"
            
            blob = bucket.blob(blob_name)
            blob.upload_from_filename(str(backup_file))
            
            return {'success': True, 'message': f'Uploaded to GCS: {blob_name}'}
            
        except ImportError:
            return {'success': False, 'message': 'google-cloud-storage not installed'}
        except Exception as e:
            return {'success': False, 'message': f'GCS upload failed: {str(e)}'}
    
    def _upload_to_ftp(self, backup: dict, config: dict) -> dict:
        """Upload to FTP server"""
        try:
            import ftplib
            
            ftp = ftplib.FTP(config['host'])
            ftp.login(config['user'], config['password'])
            
            if config.get('path'):
                ftp.cwd(config['path'])
            
            backup_file = Path(backup['path'])
            
            with open(backup_file, 'rb') as f:
                ftp.storbinary(f'STOR {backup_file.name}', f)
            
            ftp.quit()
            
            return {'success': True, 'message': f'Uploaded to FTP: {backup_file.name}'}
            
        except Exception as e:
            return {'success': False, 'message': f'FTP upload failed: {str(e)}'}
    
    # ===== Configuration =====
    
    def update_config(self, updates: dict) -> dict:
        """Update backup configuration"""
        allowed = ['auto_backup', 'retention_days', 'compression', 'exclude_patterns']
        
        for key, value in updates.items():
            if key in allowed:
                self.config[key] = value
        
        self._write_config(self.config)
        return {'success': True, 'message': 'Configuration updated'}
    
    def get_config(self) -> dict:
        """Get backup configuration"""
        return {
            'success': True,
            'config': {
                'auto_backup': self.config.get('auto_backup', True),
                'retention_days': self.config.get('retention_days', 30),
                'compression': self.config.get('compression', 'gzip'),
                'exclude_patterns': self.config.get('exclude_patterns', []),
                'backup_path': str(self.backup_path),
                'total_backups': len(self.config.get('backups', []))
            }
        }
    
    # ===== Statistics =====
    
    def get_statistics(self) -> dict:
        """Get backup statistics"""
        backups = self.config.get('backups', [])
        
        stats = {
            'total_backups': len(backups),
            'total_size': sum(b.get('size', 0) for b in backups),
            'by_type': {},
            'recent_backups': [],
            'storage_usage': {}
        }
        
        # By type
        for backup in backups:
            t = backup.get('type', 'unknown')
            if t not in stats['by_type']:
                stats['by_type'][t] = {'count': 0, 'size': 0}
            stats['by_type'][t]['count'] += 1
            stats['by_type'][t]['size'] += backup.get('size', 0)
        
        # Recent backups (last 5)
        recent = sorted(backups, key=lambda x: x.get('created_at', ''), reverse=True)[:5]
        stats['recent_backups'] = [
            {'name': b['name'], 'type': b['type'], 'created_at': b['created_at']}
            for b in recent
        ]
        
        # Human readable sizes
        stats['total_size_human'] = self._human_size(stats['total_size'])
        for t in stats['by_type']:
            stats['by_type'][t]['size_human'] = self._human_size(stats['by_type'][t]['size'])
        
        return {'success': True, 'statistics': stats}
    
    # ===== Helper Methods =====
    
    def _get_backup_by_id(self, backup_id: int) -> Optional[dict]:
        for backup in self.config.get('backups', []):
            if backup.get('id') == backup_id:
                return backup
        return None
    
    def _exclude_filter(self, tarinfo):
        """Filter for tar exclusions"""
        for pattern in self.config.get('exclude_patterns', []):
            if pattern.startswith('*'):
                if tarinfo.name.endswith(pattern[1:]):
                    return None
            elif pattern in tarinfo.name:
                return None
        return tarinfo
    
    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _human_size(self, size: int) -> str:
        """Convert bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
    
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
            print(f"Failed to write backup config: {e}")


# Global instance
backup_manager = BackupManager()
