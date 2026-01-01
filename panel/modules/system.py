"""
ApkayA Enterprise Control Panel - System Information Module

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import psutil
import platform
import socket
from typing import Dict
from .public import Public, return_data


class System:
    """System information and monitoring"""
    
    @staticmethod
    def get_cpu_info() -> Dict:
        """Get CPU information and usage"""
        return {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
            'usage': psutil.cpu_percent(interval=1),
            'usage_per_cpu': psutil.cpu_percent(percpu=True, interval=1),
            'processor': platform.processor()
        }
    
    @staticmethod
    def get_memory_info() -> Dict:
        """Get memory information and usage"""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'total': memory.total,
            'used': memory.used,
            'available': memory.available,
            'percent': memory.percent,
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_free': swap.free,
            'swap_percent': swap.percent
        }
    
    @staticmethod
    def get_disk_info() -> Dict:
        """Get disk information and usage"""
        disks = {}
        
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks[partition.mountpoint] = {
                    'device': partition.device,
                    'fstype': partition.fstype,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent
                }
            except PermissionError:
                continue
        
        return disks
    
    @staticmethod
    def get_network_info() -> Dict:
        """Get network information"""
        net_io = psutil.net_io_counters()
        
        interfaces = {}
        for interface_name, interface_addrs in psutil.net_if_addrs().items():
            interfaces[interface_name] = []
            for addr in interface_addrs:
                interfaces[interface_name].append({
                    'family': addr.family.name,
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })
        
        return {
            'interfaces': interfaces,
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errors_in': net_io.errin,
            'errors_out': net_io.errout,
            'dropped_in': net_io.dropin,
            'dropped_out': net_io.dropout
        }
    
    @staticmethod
    def get_os_info() -> Dict:
        """Get operating system information"""
        return {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'hostname': socket.gethostname(),
            'platform': platform.platform()
        }
    
    @staticmethod
    def get_process_info() -> Dict:
        """Get process information"""
        return {
            'total_processes': len(psutil.pids()),
            'top_cpu': [
                {
                    'pid': p.pid,
                    'name': p.name(),
                    'cpu_percent': p.cpu_percent()
                }
                for p in sorted(
                    psutil.process_iter(['pid', 'name', 'cpu_percent']),
                    key=lambda x: x.info['cpu_percent'],
                    reverse=True
                )[:5]
            ],
            'top_memory': [
                {
                    'pid': p.pid,
                    'name': p.name(),
                    'memory_percent': p.memory_percent()
                }
                for p in sorted(
                    psutil.process_iter(['pid', 'name', 'memory_percent']),
                    key=lambda x: x.info['memory_percent'],
                    reverse=True
                )[:5]
            ]
        }
    
    @staticmethod
    def get_system_uptime() -> int:
        """Get system uptime in seconds"""
        return int(time.time() - psutil.boot_time())
    
    @staticmethod
    def get_full_system_info() -> Dict:
        """Get comprehensive system information"""
        return return_data(True, {
            'os': System.get_os_info(),
            'cpu': System.get_cpu_info(),
            'memory': System.get_memory_info(),
            'disk': System.get_disk_info(),
            'network': System.get_network_info(),
            'processes': System.get_process_info(),
            'uptime': System.get_system_uptime(),
            'timestamp': Public.get_timestamp()
        }, 'System information retrieved')


# Global instance
import time
system = System()
