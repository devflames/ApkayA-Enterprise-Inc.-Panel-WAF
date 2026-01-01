"""
ApkayA Enterprise Control Panel - Website Management Module

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import json
import time
import socket
from typing import Dict, List, Optional
from .public import Public, return_msg, return_data, read_json, write_json, md5


class Sites:
    """Website management module"""
    
    def __init__(self):
        self.config_file = os.path.join(Public.get_config_path(), 'sites.json')
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load sites configuration"""
        if os.path.exists(self.config_file):
            return read_json(self.config_file) or {'sites': []}
        return {'sites': []}
    
    def _save_config(self) -> bool:
        """Save sites configuration"""
        return write_json(self.config_file, self.config)
    
    def list_sites(self) -> Dict:
        """List all websites"""
        sites = self.config.get('sites', [])
        return return_data(True, sites, f'{len(sites)} websites found')
    
    def add_site(self, domain: str, root_path: str, php_version: str = '8.0', 
                 server_type: str = 'nginx', ssl: bool = False) -> Dict:
        """Add new website"""
        if not domain or not root_path:
            return return_msg(False, 'Domain and root path are required')
        
        # Validate domain
        if not self._is_valid_domain(domain):
            return return_msg(False, 'Invalid domain format')
        
        # Check if domain already exists
        for site in self.config.get('sites', []):
            if site['domain'] == domain:
                return return_msg(False, 'Domain already exists')
        
        # Create site object
        site = {
            'id': int(time.time()),
            'domain': domain,
            'root_path': root_path,
            'php_version': php_version,
            'server_type': server_type,
            'ssl': ssl,
            'status': 'enabled',
            'created': Public.get_timestamp(),
            'databases': [],
            'ssl_certificate': None,
            'backup_count': 0
        }
        
        # Create root directory if not exists
        try:
            os.makedirs(root_path, exist_ok=True)
        except Exception as e:
            return return_msg(False, f'Failed to create directory: {str(e)}')
        
        self.config['sites'].append(site)
        self._save_config()
        
        return return_msg(True, 'Website added successfully', site['id'])
    
    def delete_site(self, site_id: int, remove_files: bool = False) -> Dict:
        """Delete website"""
        site = self.get_site(site_id)
        if not site.get('status'):
            return site
        
        site_data = site.get('data', {})
        
        if remove_files:
            try:
                import shutil
                shutil.rmtree(site_data['root_path'], ignore_errors=True)
            except Exception as e:
                return return_msg(False, f'Failed to remove directory: {str(e)}')
        
        self.config['sites'] = [s for s in self.config.get('sites', []) if s['id'] != site_id]
        self._save_config()
        
        return return_msg(True, 'Website deleted successfully')
    
    def get_site(self, site_id: int) -> Dict:
        """Get site information"""
        for site in self.config.get('sites', []):
            if site['id'] == site_id:
                return return_data(True, site)
        
        return return_msg(False, 'Website not found')
    
    def update_site(self, site_id: int, updates: Dict) -> Dict:
        """Update site configuration"""
        for i, site in enumerate(self.config.get('sites', [])):
            if site['id'] == site_id:
                # Update allowed fields
                allowed_fields = ['php_version', 'server_type', 'status', 'root_path']
                for field, value in updates.items():
                    if field in allowed_fields:
                        site[field] = value
                
                self.config['sites'][i] = site
                self._save_config()
                return return_msg(True, 'Website updated successfully')
        
        return return_msg(False, 'Website not found')
    
    def get_site_by_domain(self, domain: str) -> Dict:
        """Get site by domain name"""
        for site in self.config.get('sites', []):
            if site['domain'] == domain:
                return return_data(True, site)
        
        return return_msg(False, 'Website not found')
    
    def bind_database(self, site_id: int, database_id: int, db_type: str) -> Dict:
        """Bind database to website"""
        site = self.get_site(site_id)
        if not site.get('status'):
            return site
        
        site_data = site.get('data', {})
        
        if database_id not in site_data.get('databases', []):
            site_data['databases'].append({
                'id': database_id,
                'type': db_type,
                'bound_at': Public.get_timestamp()
            })
            
            self.update_site(site_id, {'databases': site_data['databases']})
            return return_msg(True, 'Database bound successfully')
        
        return return_msg(False, 'Database already bound')
    
    def unbind_database(self, site_id: int, database_id: int) -> Dict:
        """Unbind database from website"""
        site = self.get_site(site_id)
        if not site.get('status'):
            return site
        
        site_data = site.get('data', {})
        site_data['databases'] = [db for db in site_data.get('databases', []) 
                                 if db['id'] != database_id]
        
        self.update_site(site_id, {'databases': site_data['databases']})
        return return_msg(True, 'Database unbound successfully')
    
    def get_site_stats(self) -> Dict:
        """Get website statistics"""
        sites = self.config.get('sites', [])
        enabled = len([s for s in sites if s.get('status') == 'enabled'])
        disabled = len([s for s in sites if s.get('status') == 'disabled'])
        ssl_enabled = len([s for s in sites if s.get('ssl')])
        
        stats = {
            'total': len(sites),
            'enabled': enabled,
            'disabled': disabled,
            'ssl_enabled': ssl_enabled
        }
        
        return return_data(True, stats)
    
    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Validate domain format"""
        import re
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(pattern, domain):
            return True
        # Allow wildcard domains
        if domain.startswith('*.') and len(domain) > 3:
            return re.match(pattern, domain[2:]) is not None
        return False


# Global instance
sites = Sites()
