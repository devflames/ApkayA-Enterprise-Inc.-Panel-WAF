"""
Apkaya Panel WAF - Cron Job Scheduler Module
Task scheduling, cron management, job history

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import json
import subprocess
import re
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Callable
import platform


class CronManager:
    """Complete cron job management"""
    
    def __init__(self, config_path='data/cron_config.json'):
        """Initialize cron manager"""
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.os_type = platform.system().lower()
        
        # Load config
        if not self.config_path.exists():
            self._write_config(self._default_config())
        self.config = self._read_config()
        
        # Internal scheduler
        self._scheduler_running = False
        self._scheduler_thread = None
    
    @staticmethod
    def _default_config() -> dict:
        return {
            'jobs': [],
            'history': [],
            'max_history': 1000,
            'enabled': True
        }
    
    # ===== Job Management =====
    
    def create_job(self, name: str, command: str, schedule: str,
                  description: str = '', user: str = None,
                  enabled: bool = True) -> dict:
        """Create a new cron job"""
        
        # Validate schedule
        if not self._validate_schedule(schedule):
            return {'success': False, 'message': 'Invalid cron schedule format'}
        
        # Check for duplicate name
        if any(j['name'] == name for j in self.config.get('jobs', [])):
            return {'success': False, 'message': f'Job with name "{name}" already exists'}
        
        job = {
            'id': len(self.config.get('jobs', [])) + 1,
            'name': name,
            'command': command,
            'schedule': schedule,
            'schedule_human': self._schedule_to_human(schedule),
            'description': description,
            'user': user or 'root',
            'enabled': enabled,
            'created_at': datetime.now().isoformat(),
            'last_run': None,
            'next_run': self._calculate_next_run(schedule),
            'run_count': 0,
            'last_status': None
        }
        
        # Add to system crontab
        if self.os_type != 'windows':
            result = self._add_to_crontab(job)
            if not result['success']:
                return result
        
        self.config.setdefault('jobs', []).append(job)
        self._write_config(self.config)
        
        return {
            'success': True,
            'message': f'Job "{name}" created',
            'job': job
        }
    
    def update_job(self, job_id: int, updates: dict) -> dict:
        """Update an existing job"""
        
        job = self._get_job_by_id(job_id)
        if not job:
            return {'success': False, 'message': 'Job not found'}
        
        # Validate schedule if being updated
        if 'schedule' in updates:
            if not self._validate_schedule(updates['schedule']):
                return {'success': False, 'message': 'Invalid cron schedule format'}
        
        # Remove from crontab first
        if self.os_type != 'windows':
            self._remove_from_crontab(job)
        
        # Update fields
        allowed_fields = ['name', 'command', 'schedule', 'description', 'user', 'enabled']
        for field in allowed_fields:
            if field in updates:
                job[field] = updates[field]
        
        # Update computed fields
        if 'schedule' in updates:
            job['schedule_human'] = self._schedule_to_human(job['schedule'])
            job['next_run'] = self._calculate_next_run(job['schedule'])
        
        # Re-add to crontab
        if self.os_type != 'windows' and job['enabled']:
            self._add_to_crontab(job)
        
        self._write_config(self.config)
        
        return {
            'success': True,
            'message': f'Job "{job["name"]}" updated',
            'job': job
        }
    
    def delete_job(self, job_id: int) -> dict:
        """Delete a cron job"""
        
        job = self._get_job_by_id(job_id)
        if not job:
            return {'success': False, 'message': 'Job not found'}
        
        # Remove from crontab
        if self.os_type != 'windows':
            self._remove_from_crontab(job)
        
        self.config['jobs'] = [j for j in self.config['jobs'] if j['id'] != job_id]
        self._write_config(self.config)
        
        return {'success': True, 'message': f'Job "{job["name"]}" deleted'}
    
    def enable_job(self, job_id: int) -> dict:
        """Enable a job"""
        return self.update_job(job_id, {'enabled': True})
    
    def disable_job(self, job_id: int) -> dict:
        """Disable a job"""
        return self.update_job(job_id, {'enabled': False})
    
    def list_jobs(self, enabled_only: bool = False) -> dict:
        """List all cron jobs"""
        
        jobs = self.config.get('jobs', [])
        
        if enabled_only:
            jobs = [j for j in jobs if j.get('enabled')]
        
        # Update next run times
        for job in jobs:
            job['next_run'] = self._calculate_next_run(job['schedule'])
        
        return {
            'success': True,
            'jobs': jobs,
            'count': len(jobs)
        }
    
    def get_job(self, job_id: int) -> dict:
        """Get job details"""
        
        job = self._get_job_by_id(job_id)
        if not job:
            return {'success': False, 'message': 'Job not found'}
        
        job['next_run'] = self._calculate_next_run(job['schedule'])
        
        return {'success': True, 'job': job}
    
    # ===== Job Execution =====
    
    def run_job(self, job_id: int) -> dict:
        """Run a job immediately"""
        
        job = self._get_job_by_id(job_id)
        if not job:
            return {'success': False, 'message': 'Job not found'}
        
        return self._execute_job(job)
    
    def _execute_job(self, job: dict) -> dict:
        """Execute a job and record result"""
        
        start_time = datetime.now()
        
        try:
            # Execute command
            if self.os_type == 'windows':
                result = subprocess.run(
                    job['command'],
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=3600  # 1 hour timeout
                )
            else:
                # On Linux, may run as specific user
                if job.get('user') and job['user'] != 'root':
                    cmd = f"su - {job['user']} -c '{job['command']}'"
                else:
                    cmd = job['command']
                
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=3600
                )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Determine status
            status = 'success' if result.returncode == 0 else 'failed'
            
            # Update job
            job['last_run'] = start_time.isoformat()
            job['last_status'] = status
            job['run_count'] = job.get('run_count', 0) + 1
            job['next_run'] = self._calculate_next_run(job['schedule'])
            
            # Record history
            history_entry = {
                'job_id': job['id'],
                'job_name': job['name'],
                'command': job['command'],
                'status': status,
                'exit_code': result.returncode,
                'stdout': result.stdout[:5000] if result.stdout else '',
                'stderr': result.stderr[:5000] if result.stderr else '',
                'started_at': start_time.isoformat(),
                'ended_at': end_time.isoformat(),
                'duration': duration
            }
            
            self._add_history(history_entry)
            self._write_config(self.config)
            
            return {
                'success': True,
                'status': status,
                'exit_code': result.returncode,
                'duration': duration,
                'output': result.stdout[:1000],
                'error': result.stderr[:1000] if result.stderr else None
            }
            
        except subprocess.TimeoutExpired:
            job['last_run'] = start_time.isoformat()
            job['last_status'] = 'timeout'
            self._write_config(self.config)
            
            return {
                'success': False,
                'status': 'timeout',
                'message': 'Job exceeded timeout limit'
            }
            
        except Exception as e:
            job['last_run'] = start_time.isoformat()
            job['last_status'] = 'error'
            self._write_config(self.config)
            
            return {
                'success': False,
                'status': 'error',
                'message': str(e)
            }
    
    # ===== Job History =====
    
    def get_history(self, job_id: int = None, limit: int = 50,
                   status: str = None) -> dict:
        """Get job execution history"""
        
        history = self.config.get('history', [])
        
        if job_id:
            history = [h for h in history if h.get('job_id') == job_id]
        
        if status:
            history = [h for h in history if h.get('status') == status]
        
        # Sort by date descending
        history = sorted(history, key=lambda x: x.get('started_at', ''), reverse=True)
        
        return {
            'success': True,
            'history': history[:limit],
            'count': len(history)
        }
    
    def clear_history(self, job_id: int = None, older_than_days: int = None) -> dict:
        """Clear job history"""
        
        if job_id:
            self.config['history'] = [
                h for h in self.config.get('history', [])
                if h.get('job_id') != job_id
            ]
        elif older_than_days:
            cutoff = (datetime.now() - timedelta(days=older_than_days)).isoformat()
            self.config['history'] = [
                h for h in self.config.get('history', [])
                if h.get('started_at', '') > cutoff
            ]
        else:
            self.config['history'] = []
        
        self._write_config(self.config)
        
        return {'success': True, 'message': 'History cleared'}
    
    def _add_history(self, entry: dict) -> None:
        """Add entry to history with cleanup"""
        history = self.config.setdefault('history', [])
        history.insert(0, entry)
        
        # Keep only max_history entries
        max_history = self.config.get('max_history', 1000)
        if len(history) > max_history:
            self.config['history'] = history[:max_history]
    
    # ===== Schedule Helpers =====
    
    def _validate_schedule(self, schedule: str) -> bool:
        """Validate cron schedule format"""
        # Standard cron: minute hour day month weekday
        # Also support @reboot, @hourly, @daily, @weekly, @monthly, @yearly
        
        special = ['@reboot', '@hourly', '@daily', '@weekly', '@monthly', '@yearly', '@annually']
        if schedule in special:
            return True
        
        parts = schedule.split()
        if len(parts) != 5:
            return False
        
        # Basic validation for each field
        patterns = [
            r'^(\*|[0-9]|[1-5][0-9])(/\d+)?(,(\*|[0-9]|[1-5][0-9]))*$',  # minute
            r'^(\*|[0-9]|1[0-9]|2[0-3])(/\d+)?(,(\*|[0-9]|1[0-9]|2[0-3]))*$',  # hour
            r'^(\*|[1-9]|[12][0-9]|3[01])(/\d+)?(,(\*|[1-9]|[12][0-9]|3[01]))*$',  # day
            r'^(\*|[1-9]|1[0-2])(/\d+)?(,(\*|[1-9]|1[0-2]))*$',  # month
            r'^(\*|[0-7])(/\d+)?(,(\*|[0-7]))*$',  # weekday
        ]
        
        for part, pattern in zip(parts, patterns):
            # Allow ranges and wildcards
            if part == '*' or part.startswith('*/'):
                continue
            if '-' in part:
                continue
            if not re.match(pattern, part):
                return False
        
        return True
    
    def _schedule_to_human(self, schedule: str) -> str:
        """Convert cron schedule to human readable"""
        
        special = {
            '@reboot': 'On system reboot',
            '@hourly': 'Every hour',
            '@daily': 'Every day at midnight',
            '@weekly': 'Every week on Sunday',
            '@monthly': 'First day of every month',
            '@yearly': 'First day of every year',
            '@annually': 'First day of every year'
        }
        
        if schedule in special:
            return special[schedule]
        
        parts = schedule.split()
        if len(parts) != 5:
            return schedule
        
        minute, hour, day, month, weekday = parts
        
        # Build description
        desc_parts = []
        
        if minute == '*':
            desc_parts.append('Every minute')
        elif minute.startswith('*/'):
            desc_parts.append(f'Every {minute[2:]} minutes')
        else:
            desc_parts.append(f'At minute {minute}')
        
        if hour == '*':
            desc_parts.append('every hour')
        elif hour.startswith('*/'):
            desc_parts.append(f'every {hour[2:]} hours')
        elif hour != '*':
            desc_parts.append(f'at {hour}:00')
        
        if day != '*':
            desc_parts.append(f'on day {day}')
        
        if month != '*':
            months = ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
            try:
                desc_parts.append(f'in {months[int(month)]}')
            except:
                desc_parts.append(f'in month {month}')
        
        if weekday != '*':
            days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
            try:
                desc_parts.append(f'on {days[int(weekday)]}')
            except:
                desc_parts.append(f'on weekday {weekday}')
        
        return ' '.join(desc_parts)
    
    def _calculate_next_run(self, schedule: str) -> str:
        """Calculate next run time from schedule"""
        
        now = datetime.now()
        
        special = {
            '@hourly': timedelta(hours=1),
            '@daily': timedelta(days=1),
            '@weekly': timedelta(weeks=1),
            '@monthly': timedelta(days=30),
            '@yearly': timedelta(days=365),
            '@annually': timedelta(days=365)
        }
        
        if schedule in special:
            return (now + special[schedule]).isoformat()
        
        if schedule == '@reboot':
            return 'On next reboot'
        
        # Parse cron expression (simplified)
        parts = schedule.split()
        if len(parts) != 5:
            return 'Invalid'
        
        minute, hour, day, month, weekday = parts
        
        # Simple calculation - find next matching time
        next_run = now.replace(second=0, microsecond=0)
        
        # Parse minute
        if minute == '*':
            target_minute = next_run.minute
        elif minute.startswith('*/'):
            interval = int(minute[2:])
            target_minute = ((next_run.minute // interval) + 1) * interval
            if target_minute >= 60:
                target_minute = 0
                next_run += timedelta(hours=1)
        else:
            target_minute = int(minute.split(',')[0].split('-')[0])
        
        # Parse hour
        if hour == '*':
            target_hour = next_run.hour
        elif hour.startswith('*/'):
            interval = int(hour[2:])
            target_hour = ((next_run.hour // interval) + 1) * interval
            if target_hour >= 24:
                target_hour = 0
                next_run += timedelta(days=1)
        else:
            target_hour = int(hour.split(',')[0].split('-')[0])
        
        next_run = next_run.replace(minute=target_minute, hour=target_hour)
        
        # If in the past, move to next occurrence
        if next_run <= now:
            if minute != '*' and not minute.startswith('*/'):
                next_run += timedelta(hours=1)
            elif hour != '*' and not hour.startswith('*/'):
                next_run += timedelta(days=1)
            else:
                next_run += timedelta(minutes=1)
        
        return next_run.isoformat()
    
    # ===== System Crontab Operations =====
    
    def _add_to_crontab(self, job: dict) -> dict:
        """Add job to system crontab"""
        
        try:
            # Create cron entry with identifier comment
            entry = f"# APKAYA_JOB_{job['id']}\n{job['schedule']} {job['command']}\n"
            
            # Get current crontab
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            current = result.stdout if result.returncode == 0 else ''
            
            # Add new entry
            new_crontab = current.rstrip() + '\n' + entry
            
            # Install new crontab
            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate(new_crontab)
            
            return {'success': True}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _remove_from_crontab(self, job: dict) -> dict:
        """Remove job from system crontab"""
        
        try:
            # Get current crontab
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'success': True}  # No crontab
            
            lines = result.stdout.split('\n')
            new_lines = []
            skip_next = False
            
            for line in lines:
                if f'APKAYA_JOB_{job["id"]}' in line:
                    skip_next = True
                    continue
                if skip_next:
                    skip_next = False
                    continue
                new_lines.append(line)
            
            # Install new crontab
            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate('\n'.join(new_lines))
            
            return {'success': True}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def sync_from_system(self) -> dict:
        """Sync jobs from system crontab"""
        
        if self.os_type == 'windows':
            return self._sync_windows_tasks()
        
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'success': True, 'imported': 0}
            
            imported = 0
            lines = result.stdout.split('\n')
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse cron entry
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                
                schedule = ' '.join(parts[:5])
                command = parts[5]
                
                # Check if already tracked
                existing = [j for j in self.config['jobs'] if j['command'] == command]
                if not existing:
                    self.create_job(
                        name=f'Imported_{imported + 1}',
                        command=command,
                        schedule=schedule,
                        description='Imported from system crontab'
                    )
                    imported += 1
            
            return {'success': True, 'imported': imported}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _sync_windows_tasks(self) -> dict:
        """Sync from Windows Task Scheduler"""
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'csv', '/v'],
                capture_output=True, text=True
            )
            # Parse CSV output (simplified)
            return {'success': True, 'imported': 0, 'message': 'Windows sync not fully implemented'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Internal Scheduler =====
    
    def start_scheduler(self) -> dict:
        """Start internal job scheduler"""
        
        if self._scheduler_running:
            return {'success': False, 'message': 'Scheduler already running'}
        
        self._scheduler_running = True
        self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._scheduler_thread.start()
        
        return {'success': True, 'message': 'Scheduler started'}
    
    def stop_scheduler(self) -> dict:
        """Stop internal job scheduler"""
        
        self._scheduler_running = False
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
        
        return {'success': True, 'message': 'Scheduler stopped'}
    
    def _scheduler_loop(self) -> None:
        """Main scheduler loop"""
        
        while self._scheduler_running:
            now = datetime.now()
            
            for job in self.config.get('jobs', []):
                if not job.get('enabled'):
                    continue
                
                next_run = job.get('next_run')
                if not next_run or next_run == 'On next reboot':
                    continue
                
                try:
                    if now >= datetime.fromisoformat(next_run):
                        # Run job in separate thread
                        threading.Thread(
                            target=self._execute_job,
                            args=(job,),
                            daemon=True
                        ).start()
                except:
                    pass
            
            # Sleep for 30 seconds
            time.sleep(30)
    
    # ===== Presets =====
    
    def get_schedule_presets(self) -> dict:
        """Get common schedule presets"""
        return {
            'success': True,
            'presets': [
                {'name': 'Every minute', 'schedule': '* * * * *'},
                {'name': 'Every 5 minutes', 'schedule': '*/5 * * * *'},
                {'name': 'Every 15 minutes', 'schedule': '*/15 * * * *'},
                {'name': 'Every 30 minutes', 'schedule': '*/30 * * * *'},
                {'name': 'Every hour', 'schedule': '0 * * * *'},
                {'name': 'Every 2 hours', 'schedule': '0 */2 * * *'},
                {'name': 'Every 6 hours', 'schedule': '0 */6 * * *'},
                {'name': 'Every 12 hours', 'schedule': '0 */12 * * *'},
                {'name': 'Daily at midnight', 'schedule': '0 0 * * *'},
                {'name': 'Daily at 3 AM', 'schedule': '0 3 * * *'},
                {'name': 'Weekly on Sunday', 'schedule': '0 0 * * 0'},
                {'name': 'Monthly on 1st', 'schedule': '0 0 1 * *'},
                {'name': 'On system reboot', 'schedule': '@reboot'}
            ]
        }
    
    # ===== Helper Methods =====
    
    def _get_job_by_id(self, job_id: int) -> Optional[dict]:
        for job in self.config.get('jobs', []):
            if job.get('id') == job_id:
                return job
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
            print(f"Failed to write cron config: {e}")


# Global instance
cron_manager = CronManager()
