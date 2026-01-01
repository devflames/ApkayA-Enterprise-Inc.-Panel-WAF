"""
Apkaya Panel WAF - Firewall Management Module
Comprehensive firewall control for iptables, firewalld, Windows Firewall

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
"""

import os
import json
import subprocess
import re
import platform
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class FirewallManager:
    """Cross-platform firewall management"""
    
    def __init__(self, config_path='data/firewall_config.json'):
        """Initialize firewall manager"""
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Detect OS and firewall backend
        self.os_type = platform.system().lower()
        self.backend = self._detect_backend()
        
        # Load config
        if not self.config_path.exists():
            self._write_config(self._default_config())
        self.config = self._read_config()
    
    @staticmethod
    def _default_config() -> dict:
        return {
            'enabled': True,
            'default_policy': 'drop',
            'rules': [],
            'ip_blacklist': [],
            'ip_whitelist': [],
            'port_rules': [],
            'rate_limits': {},
            'country_blocks': []
        }
    
    def _detect_backend(self) -> str:
        """Detect available firewall backend"""
        if self.os_type == 'windows':
            return 'windows'
        
        # Check for firewalld
        try:
            result = subprocess.run(['firewall-cmd', '--version'], 
                                   capture_output=True, text=True)
            if result.returncode == 0:
                return 'firewalld'
        except:
            pass
        
        # Check for iptables
        try:
            result = subprocess.run(['iptables', '--version'],
                                   capture_output=True, text=True)
            if result.returncode == 0:
                return 'iptables'
        except:
            pass
        
        # Check for nftables
        try:
            result = subprocess.run(['nft', '--version'],
                                   capture_output=True, text=True)
            if result.returncode == 0:
                return 'nftables'
        except:
            pass
        
        return 'none'
    
    # ===== Status and Info =====
    
    def get_status(self) -> dict:
        """Get firewall status"""
        status = {
            'success': True,
            'enabled': self.config.get('enabled', False),
            'backend': self.backend,
            'os': self.os_type,
            'rules_count': len(self.config.get('rules', [])),
            'blacklist_count': len(self.config.get('ip_blacklist', [])),
            'whitelist_count': len(self.config.get('ip_whitelist', []))
        }
        
        # Get actual firewall status
        if self.backend == 'firewalld':
            status['active'] = self._firewalld_active()
        elif self.backend == 'iptables':
            status['active'] = self._iptables_active()
        elif self.backend == 'windows':
            status['active'] = self._windows_fw_active()
        else:
            status['active'] = False
        
        return status
    
    def enable(self) -> dict:
        """Enable firewall"""
        try:
            if self.backend == 'firewalld':
                subprocess.run(['systemctl', 'start', 'firewalld'], check=True)
            elif self.backend == 'iptables':
                # Apply default rules
                self._apply_iptables_defaults()
            elif self.backend == 'windows':
                subprocess.run([
                    'netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'
                ], check=True)
            
            self.config['enabled'] = True
            self._write_config(self.config)
            return {'success': True, 'message': 'Firewall enabled'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to enable firewall: {str(e)}'}
    
    def disable(self) -> dict:
        """Disable firewall"""
        try:
            if self.backend == 'firewalld':
                subprocess.run(['systemctl', 'stop', 'firewalld'], check=True)
            elif self.backend == 'iptables':
                subprocess.run(['iptables', '-F'], check=True)
                subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
            elif self.backend == 'windows':
                subprocess.run([
                    'netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'off'
                ], check=True)
            
            self.config['enabled'] = False
            self._write_config(self.config)
            return {'success': True, 'message': 'Firewall disabled'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to disable firewall: {str(e)}'}
    
    # ===== Port Management =====
    
    def list_ports(self) -> dict:
        """List open ports"""
        ports = []
        
        if self.backend == 'firewalld':
            ports = self._firewalld_list_ports()
        elif self.backend == 'iptables':
            ports = self._iptables_list_ports()
        elif self.backend == 'windows':
            ports = self._windows_list_ports()
        
        # Merge with config
        for port_rule in self.config.get('port_rules', []):
            found = False
            for p in ports:
                if p['port'] == port_rule['port'] and p['protocol'] == port_rule['protocol']:
                    p['description'] = port_rule.get('description', '')
                    found = True
                    break
            if not found:
                ports.append(port_rule)
        
        return {'success': True, 'ports': ports, 'count': len(ports)}
    
    def open_port(self, port: int, protocol: str = 'tcp', 
                  description: str = '', permanent: bool = True) -> dict:
        """Open a port"""
        
        if not self._validate_port(port):
            return {'success': False, 'message': 'Invalid port number (1-65535)'}
        
        protocol = protocol.lower()
        if protocol not in ['tcp', 'udp', 'both']:
            return {'success': False, 'message': 'Protocol must be tcp, udp, or both'}
        
        try:
            if protocol == 'both':
                self._open_port_impl(port, 'tcp', permanent)
                self._open_port_impl(port, 'udp', permanent)
            else:
                self._open_port_impl(port, protocol, permanent)
            
            # Save to config
            rule = {
                'port': port,
                'protocol': protocol,
                'description': description,
                'created_at': datetime.now().isoformat(),
                'status': 'open'
            }
            
            # Remove existing rule for same port/protocol
            self.config['port_rules'] = [
                r for r in self.config.get('port_rules', [])
                if not (r['port'] == port and r['protocol'] in [protocol, 'both'])
            ]
            self.config['port_rules'].append(rule)
            self._write_config(self.config)
            
            return {'success': True, 'message': f'Port {port}/{protocol} opened'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to open port: {str(e)}'}
    
    def close_port(self, port: int, protocol: str = 'tcp', permanent: bool = True) -> dict:
        """Close a port"""
        
        if not self._validate_port(port):
            return {'success': False, 'message': 'Invalid port number'}
        
        try:
            if protocol == 'both':
                self._close_port_impl(port, 'tcp', permanent)
                self._close_port_impl(port, 'udp', permanent)
            else:
                self._close_port_impl(port, protocol.lower(), permanent)
            
            # Remove from config
            self.config['port_rules'] = [
                r for r in self.config.get('port_rules', [])
                if not (r['port'] == port and r['protocol'] in [protocol, 'both'])
            ]
            self._write_config(self.config)
            
            return {'success': True, 'message': f'Port {port}/{protocol} closed'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to close port: {str(e)}'}
    
    def _open_port_impl(self, port: int, protocol: str, permanent: bool) -> None:
        """Backend-specific port opening"""
        if self.backend == 'firewalld':
            cmd = ['firewall-cmd', f'--add-port={port}/{protocol}']
            if permanent:
                cmd.append('--permanent')
            subprocess.run(cmd, check=True)
            if permanent:
                subprocess.run(['firewall-cmd', '--reload'], check=True)
        
        elif self.backend == 'iptables':
            subprocess.run([
                'iptables', '-A', 'INPUT', '-p', protocol,
                '--dport', str(port), '-j', 'ACCEPT'
            ], check=True)
        
        elif self.backend == 'windows':
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=Port {port} {protocol.upper()}',
                'dir=in', 'action=allow',
                f'protocol={protocol}', f'localport={port}'
            ], check=True)
    
    def _close_port_impl(self, port: int, protocol: str, permanent: bool) -> None:
        """Backend-specific port closing"""
        if self.backend == 'firewalld':
            cmd = ['firewall-cmd', f'--remove-port={port}/{protocol}']
            if permanent:
                cmd.append('--permanent')
            subprocess.run(cmd, check=True)
            if permanent:
                subprocess.run(['firewall-cmd', '--reload'], check=True)
        
        elif self.backend == 'iptables':
            subprocess.run([
                'iptables', '-D', 'INPUT', '-p', protocol,
                '--dport', str(port), '-j', 'ACCEPT'
            ], check=True)
        
        elif self.backend == 'windows':
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name=Port {port} {protocol.upper()}'
            ], capture_output=True)
    
    # ===== IP Management =====
    
    def block_ip(self, ip: str, reason: str = '', permanent: bool = True) -> dict:
        """Block an IP address"""
        
        if not self._validate_ip(ip):
            return {'success': False, 'message': 'Invalid IP address'}
        
        # Check whitelist
        if ip in self.config.get('ip_whitelist', []):
            return {'success': False, 'message': 'IP is in whitelist, remove from whitelist first'}
        
        try:
            self._block_ip_impl(ip, permanent)
            
            # Add to blacklist
            if ip not in [b['ip'] for b in self.config.get('ip_blacklist', [])]:
                self.config.setdefault('ip_blacklist', []).append({
                    'ip': ip,
                    'reason': reason,
                    'blocked_at': datetime.now().isoformat()
                })
                self._write_config(self.config)
            
            return {'success': True, 'message': f'IP {ip} blocked'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to block IP: {str(e)}'}
    
    def unblock_ip(self, ip: str, permanent: bool = True) -> dict:
        """Unblock an IP address"""
        
        if not self._validate_ip(ip):
            return {'success': False, 'message': 'Invalid IP address'}
        
        try:
            self._unblock_ip_impl(ip, permanent)
            
            # Remove from blacklist
            self.config['ip_blacklist'] = [
                b for b in self.config.get('ip_blacklist', [])
                if b['ip'] != ip
            ]
            self._write_config(self.config)
            
            return {'success': True, 'message': f'IP {ip} unblocked'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to unblock IP: {str(e)}'}
    
    def _block_ip_impl(self, ip: str, permanent: bool) -> None:
        """Backend-specific IP blocking"""
        if self.backend == 'firewalld':
            cmd = ['firewall-cmd', f'--add-rich-rule=rule family="ipv4" source address="{ip}" reject']
            if permanent:
                cmd.append('--permanent')
            subprocess.run(cmd, check=True)
            if permanent:
                subprocess.run(['firewall-cmd', '--reload'], check=True)
        
        elif self.backend == 'iptables':
            subprocess.run([
                'iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'
            ], check=True)
        
        elif self.backend == 'windows':
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=Block IP {ip}',
                'dir=in', 'action=block',
                f'remoteip={ip}'
            ], check=True)
    
    def _unblock_ip_impl(self, ip: str, permanent: bool) -> None:
        """Backend-specific IP unblocking"""
        if self.backend == 'firewalld':
            cmd = ['firewall-cmd', f'--remove-rich-rule=rule family="ipv4" source address="{ip}" reject']
            if permanent:
                cmd.append('--permanent')
            subprocess.run(cmd, capture_output=True)
            if permanent:
                subprocess.run(['firewall-cmd', '--reload'], capture_output=True)
        
        elif self.backend == 'iptables':
            subprocess.run([
                'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'
            ], capture_output=True)
        
        elif self.backend == 'windows':
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name=Block IP {ip}'
            ], capture_output=True)
    
    def whitelist_ip(self, ip: str, description: str = '') -> dict:
        """Add IP to whitelist"""
        
        if not self._validate_ip(ip):
            return {'success': False, 'message': 'Invalid IP address'}
        
        # Remove from blacklist if present
        self.config['ip_blacklist'] = [
            b for b in self.config.get('ip_blacklist', [])
            if b['ip'] != ip
        ]
        
        if ip not in [w['ip'] for w in self.config.get('ip_whitelist', [])]:
            self.config.setdefault('ip_whitelist', []).append({
                'ip': ip,
                'description': description,
                'added_at': datetime.now().isoformat()
            })
            self._write_config(self.config)
        
        return {'success': True, 'message': f'IP {ip} whitelisted'}
    
    def remove_from_whitelist(self, ip: str) -> dict:
        """Remove IP from whitelist"""
        self.config['ip_whitelist'] = [
            w for w in self.config.get('ip_whitelist', [])
            if w['ip'] != ip
        ]
        self._write_config(self.config)
        return {'success': True, 'message': f'IP {ip} removed from whitelist'}
    
    def list_blacklist(self) -> dict:
        """List blocked IPs"""
        return {
            'success': True,
            'blacklist': self.config.get('ip_blacklist', []),
            'count': len(self.config.get('ip_blacklist', []))
        }
    
    def list_whitelist(self) -> dict:
        """List whitelisted IPs"""
        return {
            'success': True,
            'whitelist': self.config.get('ip_whitelist', []),
            'count': len(self.config.get('ip_whitelist', []))
        }
    
    # ===== Custom Rules =====
    
    def add_rule(self, rule: dict) -> dict:
        """Add custom firewall rule"""
        required = ['action', 'direction', 'protocol']
        
        for field in required:
            if field not in rule:
                return {'success': False, 'message': f'Missing required field: {field}'}
        
        rule['id'] = len(self.config.get('rules', [])) + 1
        rule['created_at'] = datetime.now().isoformat()
        rule['enabled'] = True
        
        try:
            self._apply_rule(rule)
            self.config.setdefault('rules', []).append(rule)
            self._write_config(self.config)
            
            return {'success': True, 'message': 'Rule added', 'rule_id': rule['id']}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to add rule: {str(e)}'}
    
    def remove_rule(self, rule_id: int) -> dict:
        """Remove custom rule"""
        rules = self.config.get('rules', [])
        rule = next((r for r in rules if r.get('id') == rule_id), None)
        
        if not rule:
            return {'success': False, 'message': 'Rule not found'}
        
        try:
            self._remove_rule(rule)
            self.config['rules'] = [r for r in rules if r.get('id') != rule_id]
            self._write_config(self.config)
            
            return {'success': True, 'message': 'Rule removed'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to remove rule: {str(e)}'}
    
    def list_rules(self) -> dict:
        """List all custom rules"""
        return {
            'success': True,
            'rules': self.config.get('rules', []),
            'count': len(self.config.get('rules', []))
        }
    
    def _apply_rule(self, rule: dict) -> None:
        """Apply a custom rule"""
        if self.backend == 'iptables':
            cmd = ['iptables']
            
            # Direction
            if rule['direction'] == 'in':
                cmd.extend(['-A', 'INPUT'])
            else:
                cmd.extend(['-A', 'OUTPUT'])
            
            # Protocol
            cmd.extend(['-p', rule['protocol']])
            
            # Source/Destination
            if 'source' in rule:
                cmd.extend(['-s', rule['source']])
            if 'destination' in rule:
                cmd.extend(['-d', rule['destination']])
            
            # Port
            if 'port' in rule:
                cmd.extend(['--dport', str(rule['port'])])
            
            # Action
            action = 'ACCEPT' if rule['action'] == 'allow' else 'DROP'
            cmd.extend(['-j', action])
            
            subprocess.run(cmd, check=True)
        
        elif self.backend == 'windows':
            cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule']
            cmd.append(f'name=Rule_{rule.get("id", "custom")}')
            cmd.append(f'dir={"in" if rule["direction"] == "in" else "out"}')
            cmd.append(f'action={"allow" if rule["action"] == "allow" else "block"}')
            cmd.append(f'protocol={rule["protocol"]}')
            
            if 'port' in rule:
                cmd.append(f'localport={rule["port"]}')
            if 'source' in rule:
                cmd.append(f'remoteip={rule["source"]}')
            
            subprocess.run(cmd, check=True)
    
    def _remove_rule(self, rule: dict) -> None:
        """Remove a custom rule"""
        if self.backend == 'windows':
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name=Rule_{rule.get("id", "custom")}'
            ], capture_output=True)
    
    # ===== Rate Limiting =====
    
    def set_rate_limit(self, port: int, limit: str, burst: int = 10) -> dict:
        """Set rate limit for a port (e.g., '10/minute')"""
        
        if self.backend != 'iptables':
            return {'success': False, 'message': 'Rate limiting only supported with iptables'}
        
        try:
            # Parse limit
            match = re.match(r'(\d+)/(second|minute|hour)', limit)
            if not match:
                return {'success': False, 'message': 'Invalid limit format. Use: N/second, N/minute, or N/hour'}
            
            count, period = match.groups()
            
            # Apply rate limit
            subprocess.run([
                'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port),
                '-m', 'limit', '--limit', limit, '--limit-burst', str(burst),
                '-j', 'ACCEPT'
            ], check=True)
            
            subprocess.run([
                'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port),
                '-j', 'DROP'
            ], check=True)
            
            # Save config
            self.config.setdefault('rate_limits', {})[str(port)] = {
                'limit': limit,
                'burst': burst
            }
            self._write_config(self.config)
            
            return {'success': True, 'message': f'Rate limit set for port {port}'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to set rate limit: {str(e)}'}
    
    # ===== Helper Methods =====
    
    def _validate_port(self, port: int) -> bool:
        return isinstance(port, int) and 1 <= port <= 65535
    
    def _validate_ip(self, ip: str) -> bool:
        # IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        # IPv6 simplified
        ipv6_pattern = r'^[0-9a-fA-F:]+(/\d{1,3})?$'
        return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))
    
    def _firewalld_active(self) -> bool:
        try:
            result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True)
            return 'running' in result.stdout.lower()
        except:
            return False
    
    def _iptables_active(self) -> bool:
        try:
            result = subprocess.run(['iptables', '-L', '-n'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _windows_fw_active(self) -> bool:
        try:
            result = subprocess.run([
                'netsh', 'advfirewall', 'show', 'allprofiles', 'state'
            ], capture_output=True, text=True)
            return 'ON' in result.stdout.upper()
        except:
            return False
    
    def _firewalld_list_ports(self) -> List[dict]:
        ports = []
        try:
            result = subprocess.run(['firewall-cmd', '--list-ports'], capture_output=True, text=True)
            for item in result.stdout.strip().split():
                if '/' in item:
                    port, proto = item.split('/')
                    ports.append({'port': int(port), 'protocol': proto, 'status': 'open'})
        except:
            pass
        return ports
    
    def _iptables_list_ports(self) -> List[dict]:
        ports = []
        try:
            result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                match = re.search(r'(tcp|udp)\s+dpt:(\d+)', line)
                if match:
                    proto, port = match.groups()
                    ports.append({'port': int(port), 'protocol': proto, 'status': 'open'})
        except:
            pass
        return ports
    
    def _windows_list_ports(self) -> List[dict]:
        ports = []
        try:
            result = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'
            ], capture_output=True, text=True)
            # Parse output (simplified)
            current = {}
            for line in result.stdout.split('\n'):
                if 'LocalPort:' in line:
                    port_str = line.split(':')[1].strip()
                    if port_str.isdigit():
                        current['port'] = int(port_str)
                elif 'Protocol:' in line:
                    current['protocol'] = line.split(':')[1].strip().lower()
                elif 'Action:' in line:
                    if 'allow' in line.lower():
                        current['status'] = 'open'
                    if 'port' in current:
                        ports.append(current)
                    current = {}
        except:
            pass
        return ports
    
    def _apply_iptables_defaults(self) -> None:
        """Apply default iptables rules"""
        commands = [
            ['iptables', '-P', 'INPUT', 'DROP'],
            ['iptables', '-P', 'FORWARD', 'DROP'],
            ['iptables', '-P', 'OUTPUT', 'ACCEPT'],
            ['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
            ['iptables', '-A', 'INPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
            ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'],
            ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'],
        ]
        for cmd in commands:
            subprocess.run(cmd, capture_output=True)
    
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
            print(f"Failed to write firewall config: {e}")


# Global instance
firewall_manager = FirewallManager()
