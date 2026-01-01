"""
Apkaya Panel WAF - WAF Integration Module
Web Application Firewall configuration and API client

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
"""

import os
import json
import time
import requests
from typing import Dict, List, Optional
from ..public import Public, return_msg, return_data, read_json, write_json


class WAFConfig:
    """WAF Configuration Management"""
    
    def __init__(self):
        self.config_file = os.path.join(Public.get_config_path(), 'waf.json')
        self.waf_host = '127.0.0.1'
        self.waf_port = 8379
        self.api_url = f'http://{self.waf_host}:{self.waf_port}/api'
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load WAF configuration"""
        if os.path.exists(self.config_file):
            return read_json(self.config_file) or self._default_config()
        return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default WAF configuration"""
        return {
            'enabled': True,
            'port': self.waf_port,
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
            'decoding': {
                'url': True,
                'unicode': True,
                'base64': True,
                'hex': True,
                'json': True,
                'gzip': True,
                'max_layers': 3
            },
            'logging': {
                'enabled': True,
                'level': 'info',
                'max_size': '100MB',
                'retention_days': 30
            },
            'whitelist': {
                'ips': [],
                'urls': [],
                'user_agents': []
            },
            'blacklist': {
                'ips': [],
                'urls': [],
                'user_agents': []
            }
        }
    
    def _save_config(self) -> bool:
        """Save WAF configuration"""
        return write_json(self.config_file, self.config)
    
    def get_config(self) -> Dict:
        """Get full WAF configuration"""
        return return_data(True, self.config, 'WAF configuration retrieved')
    
    def update_config(self, updates: Dict) -> Dict:
        """Update WAF configuration"""
        # Deep merge updates
        def deep_merge(original, updates):
            for key, value in updates.items():
                if isinstance(value, dict) and key in original:
                    deep_merge(original[key], value)
                else:
                    original[key] = value
        
        deep_merge(self.config, updates)
        
        if self._save_config():
            return return_msg(True, 'WAF configuration updated')
        else:
            return return_msg(False, 'Failed to save configuration')
    
    def enable_module(self, module: str) -> Dict:
        """Enable WAF module"""
        if module not in self.config.get('modules', {}):
            return return_msg(False, f'Module {module} not found')
        
        self.config['modules'][module] = True
        self._save_config()
        return return_msg(True, f'Module {module} enabled')
    
    def disable_module(self, module: str) -> Dict:
        """Disable WAF module"""
        if module not in self.config.get('modules', {}):
            return return_msg(False, f'Module {module} not found')
        
        self.config['modules'][module] = False
        self._save_config()
        return return_msg(True, f'Module {module} disabled')
    
    def add_ip_to_whitelist(self, ip: str) -> Dict:
        """Add IP to whitelist"""
        ips = self.config.setdefault('whitelist', {}).setdefault('ips', [])
        
        if ip in ips:
            return return_msg(False, 'IP already in whitelist')
        
        ips.append(ip)
        self._save_config()
        return return_msg(True, 'IP added to whitelist')
    
    def remove_ip_from_whitelist(self, ip: str) -> Dict:
        """Remove IP from whitelist"""
        ips = self.config.setdefault('whitelist', {}).setdefault('ips', [])
        
        if ip not in ips:
            return return_msg(False, 'IP not in whitelist')
        
        ips.remove(ip)
        self._save_config()
        return return_msg(True, 'IP removed from whitelist')
    
    def add_ip_to_blacklist(self, ip: str, duration: Optional[int] = None) -> Dict:
        """Add IP to blacklist"""
        ips = self.config.setdefault('blacklist', {}).setdefault('ips', [])
        
        ip_entry = {
            'ip': ip,
            'added': Public.get_timestamp()
        }
        
        if duration:
            ip_entry['duration'] = duration
        
        # Check if already exists
        for entry in ips:
            if isinstance(entry, dict) and entry.get('ip') == ip:
                return return_msg(False, 'IP already in blacklist')
            elif entry == ip:
                return return_msg(False, 'IP already in blacklist')
        
        ips.append(ip_entry)
        self._save_config()
        return return_msg(True, 'IP added to blacklist')
    
    def remove_ip_from_blacklist(self, ip: str) -> Dict:
        """Remove IP from blacklist"""
        ips = self.config.setdefault('blacklist', {}).setdefault('ips', [])
        
        self.config['blacklist']['ips'] = [
            entry for entry in ips
            if (isinstance(entry, dict) and entry.get('ip') != ip) or 
               (isinstance(entry, str) and entry != ip)
        ]
        
        self._save_config()
        return return_msg(True, 'IP removed from blacklist')


class WAFClient:
    """WAF API Client"""
    
    def __init__(self):
        self.config = WAFConfig()
        self.api_url = self.config.api_url
        self.timeout = 10
    
    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Make API request to WAF"""
        url = f'{self.api_url}{endpoint}'
        
        try:
            if method == 'GET':
                response = requests.get(url, timeout=self.timeout)
            elif method == 'POST':
                response = requests.post(url, json=data, timeout=self.timeout)
            else:
                return return_msg(False, 'Invalid HTTP method')
            
            if response.status_code == 200:
                return response.json()
            else:
                return return_msg(False, f'WAF API error: {response.status_code}')
        except requests.ConnectionError:
            return return_msg(False, 'Cannot connect to WAF service')
        except Exception as e:
            return return_msg(False, f'API error: {str(e)}')
    
    def get_status(self) -> Dict:
        """Get WAF service status"""
        return self._request('GET', '/status')
    
    def start_service(self) -> Dict:
        """Start WAF service"""
        return self._request('POST', '/start')
    
    def stop_service(self) -> Dict:
        """Stop WAF service"""
        return self._request('POST', '/stop')
    
    def restart_service(self) -> Dict:
        """Restart WAF service"""
        return self._request('POST', '/restart')
    
    def get_logs(self, limit: int = 100, offset: int = 0) -> Dict:
        """Get WAF logs"""
        return self._request('POST', '/logs', {
            'limit': limit,
            'offset': offset
        })
    
    def get_attack_stats(self, days: int = 7) -> Dict:
        """Get attack statistics"""
        return self._request('POST', '/stats', {
            'days': days
        })
    
    def get_rules(self) -> Dict:
        """Get active WAF rules"""
        return self._request('GET', '/rules')
    
    def update_rules(self, rules: List[Dict]) -> Dict:
        """Update WAF rules"""
        return self._request('POST', '/rules/update', {
            'rules': rules
        })
    
    def test_payload(self, payload: str) -> Dict:
        """Test if payload would be blocked"""
        return self._request('POST', '/test', {
            'payload': payload
        })
    
    def whitelist_add(self, ip: str) -> Dict:
        """Add IP to WAF whitelist"""
        return self._request('POST', '/whitelist/add', {'ip': ip})
    
    def whitelist_remove(self, ip: str) -> Dict:
        """Remove IP from WAF whitelist"""
        return self._request('POST', '/whitelist/remove', {'ip': ip})
    
    def blacklist_add(self, ip: str, duration: Optional[int] = None) -> Dict:
        """Add IP to WAF blacklist"""
        return self._request('POST', '/blacklist/add', {
            'ip': ip,
            'duration': duration
        })
    
    def blacklist_remove(self, ip: str) -> Dict:
        """Remove IP from WAF blacklist"""
        return self._request('POST', '/blacklist/remove', {'ip': ip})


# Global instances
waf_config = WAFConfig()
waf_client = WAFClient()
