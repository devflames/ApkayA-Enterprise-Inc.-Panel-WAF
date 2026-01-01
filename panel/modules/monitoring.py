"""
Apkaya Panel WAF - Monitoring Module
Extended monitoring capabilities

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import psutil
import json
from datetime import datetime
from pathlib import Path


class AdvancedMonitoring:
    """Advanced system monitoring with metrics collection"""
    
    def __init__(self, metrics_dir='data/metrics'):
        """Initialize monitoring"""
        self.metrics_dir = Path(metrics_dir)
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_history = []
    
    # Process Monitoring
    def get_top_processes_by_cpu(self, top_n=5):
        """Get top N processes by CPU usage"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu_percent': proc.info['cpu_percent']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU and get top N
            sorted_procs = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)
            return sorted_procs[:top_n]
        except Exception as e:
            return []
    
    def get_top_processes_by_memory(self, top_n=5):
        """Get top N processes by memory usage"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'memory_percent': proc.info['memory_percent']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by memory and get top N
            sorted_procs = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)
            return sorted_procs[:top_n]
        except Exception as e:
            return []
    
    def get_process_details(self, pid):
        """Get detailed information about a process"""
        try:
            proc = psutil.Process(pid)
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'status': proc.status(),
                'cpu_percent': proc.cpu_percent(interval=1),
                'memory_percent': proc.memory_percent(),
                'memory_info': {
                    'rss': proc.memory_info().rss,  # Resident Set Size
                    'vms': proc.memory_info().vms   # Virtual Memory Size
                },
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'num_threads': proc.num_threads(),
                'connections': len(proc.connections())
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    # Port Monitoring
    def get_listening_ports(self):
        """Get all listening ports"""
        try:
            listening_ports = []
            for conn in psutil.net_connections():
                if conn.status == 'LISTEN':
                    listening_ports.append({
                        'address': conn.laddr.ip,
                        'port': conn.laddr.port,
                        'protocol': conn.type,
                        'pid': conn.pid
                    })
            return listening_ports
        except Exception as e:
            return []
    
    def is_port_in_use(self, port):
        """Check if port is in use"""
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port and conn.status == 'LISTEN':
                    return True
            return False
        except Exception:
            return False
    
    def get_port_info(self, port):
        """Get information about a specific port"""
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port:
                    return {
                        'port': port,
                        'address': conn.laddr.ip,
                        'protocol': conn.type,
                        'status': conn.status,
                        'pid': conn.pid
                    }
            return None
        except Exception:
            return None
    
    # Network Monitoring
    def get_network_interfaces_detailed(self):
        """Get detailed network interface information"""
        try:
            interfaces = {}
            for iface_name, iface_addrs in psutil.net_if_addrs().items():
                interfaces[iface_name] = {
                    'addresses': [
                        {
                            'family': str(addr.family),
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        }
                        for addr in iface_addrs
                    ]
                }
            
            # Add stats
            stats = psutil.net_if_stats()
            for iface_name in interfaces:
                if iface_name in stats:
                    stat = stats[iface_name]
                    interfaces[iface_name]['stats'] = {
                        'is_up': stat.isup,
                        'mtu': stat.mtu,
                        'speed': stat.speed,
                        'packets_sent': stat.packets_sent,
                        'packets_recv': stat.packets_recv,
                        'errors_in': stat.errin,
                        'errors_out': stat.errout,
                        'drops_in': stat.dropin,
                        'drops_out': stat.dropout
                    }
            
            return interfaces
        except Exception as e:
            return {}
    
    # Disk Monitoring
    def get_disk_io_stats(self):
        """Get disk I/O statistics"""
        try:
            io_stats = psutil.disk_io_counters(perdisk=True)
            result = {}
            
            for disk_name, stats in io_stats.items():
                result[disk_name] = {
                    'read_count': stats.read_count,
                    'write_count': stats.write_count,
                    'read_bytes': stats.read_bytes,
                    'write_bytes': stats.write_bytes,
                    'read_time': stats.read_time,
                    'write_time': stats.write_time
                }
            
            return result
        except Exception:
            return {}
    
    def get_partition_usage_detailed(self):
        """Get detailed partition usage"""
        try:
            partitions = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    partitions.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
                except (OSError, PermissionError):
                    continue
            
            return partitions
        except Exception:
            return []
    
    # CPU Monitoring
    def get_cpu_stats_detailed(self):
        """Get detailed CPU statistics"""
        try:
            return {
                'physical_count': psutil.cpu_count(logical=False),
                'logical_count': psutil.cpu_count(logical=True),
                'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
                'stats': psutil.cpu_stats()._asdict(),
                'times': psutil.cpu_times()._asdict(),
                'times_percent': psutil.cpu_times_percent(interval=1)._asdict()
            }
        except Exception:
            return {}
    
    # Memory Monitoring
    def get_memory_stats_detailed(self):
        """Get detailed memory statistics"""
        try:
            virtual_mem = psutil.virtual_memory()
            swap_mem = psutil.swap_memory()
            
            return {
                'virtual': {
                    'total': virtual_mem.total,
                    'available': virtual_mem.available,
                    'used': virtual_mem.used,
                    'free': virtual_mem.free,
                    'percent': virtual_mem.percent,
                    'active': virtual_mem.active,
                    'inactive': virtual_mem.inactive,
                    'buffers': virtual_mem.buffers,
                    'cached': virtual_mem.cached
                },
                'swap': {
                    'total': swap_mem.total,
                    'used': swap_mem.used,
                    'free': swap_mem.free,
                    'percent': swap_mem.percent
                }
            }
        except Exception:
            return {}
    
    # Metrics Collection
    def collect_system_metrics(self):
        """Collect comprehensive system metrics"""
        timestamp = datetime.now().isoformat()
        
        metrics = {
            'timestamp': timestamp,
            'cpu': self.get_cpu_stats_detailed(),
            'memory': self.get_memory_stats_detailed(),
            'disk': self.get_disk_io_stats(),
            'network': self.get_network_interfaces_detailed(),
            'processes': {
                'cpu_top': self.get_top_processes_by_cpu(),
                'memory_top': self.get_top_processes_by_memory()
            }
        }
        
        self.metrics_history.append(metrics)
        
        # Keep only last 1000 metrics (~16 hours with 1-minute intervals)
        if len(self.metrics_history) > 1000:
            self.metrics_history.pop(0)
        
        return metrics
    
    def get_metrics_history(self, limit=100):
        """Get metrics history"""
        return self.metrics_history[-limit:]
    
    def save_metrics_to_disk(self):
        """Save metrics to disk for persistence"""
        try:
            metrics_file = self.metrics_dir / 'system_metrics.json'
            with open(metrics_file, 'w', encoding='utf-8') as f:
                json.dump(self.metrics_history[-100:], f, indent=2)
            return True
        except Exception:
            return False
    
    def load_metrics_from_disk(self):
        """Load metrics from disk"""
        try:
            metrics_file = self.metrics_dir / 'system_metrics.json'
            if metrics_file.exists():
                with open(metrics_file, 'r', encoding='utf-8') as f:
                    self.metrics_history = json.load(f)
            return True
        except Exception:
            return False


# Global monitoring instance
monitoring = AdvancedMonitoring()
