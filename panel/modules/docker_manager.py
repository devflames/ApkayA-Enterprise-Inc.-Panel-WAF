"""
Apkaya Panel WAF - Docker Management Module
Container management, images, compose, networks

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


class DockerManager:
    """Complete Docker container management"""
    
    def __init__(self, config_path='data/docker_config.json'):
        """Initialize Docker manager"""
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.os_type = platform.system().lower()
        
        # Check Docker availability
        self.docker_available = self._check_docker()
        self.compose_available = self._check_compose()
        
        # Load config
        if not self.config_path.exists():
            self._write_config(self._default_config())
        self.config = self._read_config()
    
    def _check_docker(self) -> bool:
        """Check if Docker is available"""
        try:
            result = subprocess.run(['docker', '--version'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_compose(self) -> bool:
        """Check if Docker Compose is available"""
        try:
            # Try docker compose (v2)
            result = subprocess.run(['docker', 'compose', 'version'], capture_output=True)
            if result.returncode == 0:
                return True
            
            # Try docker-compose (v1)
            result = subprocess.run(['docker-compose', '--version'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def _default_config() -> dict:
        return {
            'projects': [],
            'registries': [],
            'default_network': 'bridge'
        }
    
    # ===== Docker Status =====
    
    def get_status(self) -> dict:
        """Get Docker status"""
        if not self.docker_available:
            return {
                'success': False,
                'message': 'Docker is not installed or not running'
            }
        
        try:
            # Get Docker info
            result = subprocess.run(['docker', 'info', '--format', '{{json .}}'],
                                   capture_output=True, text=True)
            
            info = json.loads(result.stdout) if result.returncode == 0 else {}
            
            # Get version
            version_result = subprocess.run(['docker', 'version', '--format', '{{json .}}'],
                                           capture_output=True, text=True)
            version = json.loads(version_result.stdout) if version_result.returncode == 0 else {}
            
            return {
                'success': True,
                'running': True,
                'version': version.get('Client', {}).get('Version', 'unknown'),
                'api_version': version.get('Client', {}).get('ApiVersion', 'unknown'),
                'containers': {
                    'total': info.get('Containers', 0),
                    'running': info.get('ContainersRunning', 0),
                    'paused': info.get('ContainersPaused', 0),
                    'stopped': info.get('ContainersStopped', 0)
                },
                'images': info.get('Images', 0),
                'storage_driver': info.get('Driver', 'unknown'),
                'compose_available': self.compose_available
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Container Management =====
    
    def list_containers(self, all_containers: bool = False) -> dict:
        """List containers"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'ps', '--format', '{{json .}}']
            if all_containers:
                cmd.insert(2, '-a')
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    container = json.loads(line)
                    containers.append({
                        'id': container.get('ID'),
                        'name': container.get('Names'),
                        'image': container.get('Image'),
                        'status': container.get('Status'),
                        'state': container.get('State'),
                        'ports': container.get('Ports'),
                        'created': container.get('CreatedAt'),
                        'size': container.get('Size')
                    })
            
            return {
                'success': True,
                'containers': containers,
                'count': len(containers)
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def get_container(self, container_id: str) -> dict:
        """Get container details"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            result = subprocess.run(
                ['docker', 'inspect', container_id],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                return {'success': False, 'message': 'Container not found'}
            
            info = json.loads(result.stdout)[0]
            
            return {
                'success': True,
                'container': {
                    'id': info.get('Id'),
                    'name': info.get('Name', '').lstrip('/'),
                    'image': info.get('Config', {}).get('Image'),
                    'state': info.get('State', {}),
                    'network': info.get('NetworkSettings', {}),
                    'mounts': info.get('Mounts', []),
                    'config': info.get('Config', {}),
                    'host_config': info.get('HostConfig', {})
                }
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def create_container(self, image: str, name: str = None,
                        ports: Dict[str, str] = None,
                        volumes: Dict[str, str] = None,
                        env: Dict[str, str] = None,
                        network: str = None,
                        restart_policy: str = 'unless-stopped') -> dict:
        """Create and start a container"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'run', '-d']
            
            if name:
                cmd.extend(['--name', name])
            
            if restart_policy:
                cmd.extend(['--restart', restart_policy])
            
            if network:
                cmd.extend(['--network', network])
            
            if ports:
                for host_port, container_port in ports.items():
                    cmd.extend(['-p', f'{host_port}:{container_port}'])
            
            if volumes:
                for host_path, container_path in volumes.items():
                    cmd.extend(['-v', f'{host_path}:{container_path}'])
            
            if env:
                for key, value in env.items():
                    cmd.extend(['-e', f'{key}={value}'])
            
            cmd.append(image)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            container_id = result.stdout.strip()[:12]
            
            return {
                'success': True,
                'message': f'Container created: {container_id}',
                'container_id': container_id
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def start_container(self, container_id: str) -> dict:
        """Start a container"""
        return self._container_action(container_id, 'start')
    
    def stop_container(self, container_id: str, timeout: int = 10) -> dict:
        """Stop a container"""
        return self._container_action(container_id, 'stop', ['-t', str(timeout)])
    
    def restart_container(self, container_id: str) -> dict:
        """Restart a container"""
        return self._container_action(container_id, 'restart')
    
    def pause_container(self, container_id: str) -> dict:
        """Pause a container"""
        return self._container_action(container_id, 'pause')
    
    def unpause_container(self, container_id: str) -> dict:
        """Unpause a container"""
        return self._container_action(container_id, 'unpause')
    
    def remove_container(self, container_id: str, force: bool = False,
                        remove_volumes: bool = False) -> dict:
        """Remove a container"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'rm']
            if force:
                cmd.append('-f')
            if remove_volumes:
                cmd.append('-v')
            cmd.append(container_id)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {'success': True, 'message': f'Container {container_id} removed'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _container_action(self, container_id: str, action: str, 
                         extra_args: List[str] = None) -> dict:
        """Generic container action"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', action]
            if extra_args:
                cmd.extend(extra_args)
            cmd.append(container_id)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {'success': True, 'message': f'Container {action} successful'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def get_container_logs(self, container_id: str, tail: int = 100,
                          timestamps: bool = True) -> dict:
        """Get container logs"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'logs', '--tail', str(tail)]
            if timestamps:
                cmd.append('--timestamps')
            cmd.append(container_id)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return {
                'success': True,
                'logs': result.stdout + result.stderr,
                'container_id': container_id
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def get_container_stats(self, container_id: str) -> dict:
        """Get container resource stats"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            result = subprocess.run([
                'docker', 'stats', '--no-stream', '--format', '{{json .}}',
                container_id
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': 'Container not found or not running'}
            
            stats = json.loads(result.stdout.strip())
            
            return {
                'success': True,
                'stats': {
                    'container': stats.get('Name'),
                    'cpu': stats.get('CPUPerc'),
                    'memory': stats.get('MemUsage'),
                    'memory_percent': stats.get('MemPerc'),
                    'network_io': stats.get('NetIO'),
                    'block_io': stats.get('BlockIO'),
                    'pids': stats.get('PIDs')
                }
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def exec_in_container(self, container_id: str, command: str,
                         interactive: bool = False) -> dict:
        """Execute command in container"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'exec']
            if interactive:
                cmd.extend(['-it'])
            cmd.extend([container_id, 'sh', '-c', command])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'exit_code': result.returncode
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Image Management =====
    
    def list_images(self) -> dict:
        """List Docker images"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            result = subprocess.run([
                'docker', 'images', '--format', '{{json .}}'
            ], capture_output=True, text=True)
            
            images = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    image = json.loads(line)
                    images.append({
                        'id': image.get('ID'),
                        'repository': image.get('Repository'),
                        'tag': image.get('Tag'),
                        'created': image.get('CreatedAt'),
                        'size': image.get('Size')
                    })
            
            return {
                'success': True,
                'images': images,
                'count': len(images)
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def pull_image(self, image: str) -> dict:
        """Pull Docker image"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            result = subprocess.run(
                ['docker', 'pull', image],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {
                'success': True,
                'message': f'Image {image} pulled successfully',
                'output': result.stdout
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def remove_image(self, image_id: str, force: bool = False) -> dict:
        """Remove Docker image"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'rmi']
            if force:
                cmd.append('-f')
            cmd.append(image_id)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {'success': True, 'message': f'Image {image_id} removed'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def build_image(self, dockerfile_path: str, tag: str, 
                   build_args: Dict[str, str] = None) -> dict:
        """Build Docker image"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'build', '-t', tag]
            
            if build_args:
                for key, value in build_args.items():
                    cmd.extend(['--build-arg', f'{key}={value}'])
            
            cmd.append(dockerfile_path)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {
                'success': True,
                'message': f'Image {tag} built successfully',
                'output': result.stdout
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Docker Compose =====
    
    def compose_up(self, compose_file: str, detach: bool = True,
                  build: bool = False) -> dict:
        """Run docker-compose up"""
        if not self.compose_available:
            return {'success': False, 'message': 'Docker Compose not available'}
        
        try:
            # Use docker compose (v2) or docker-compose (v1)
            cmd = self._get_compose_cmd()
            cmd.extend(['-f', compose_file, 'up'])
            
            if detach:
                cmd.append('-d')
            if build:
                cmd.append('--build')
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {
                'success': True,
                'message': 'Compose project started',
                'output': result.stdout
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def compose_down(self, compose_file: str, volumes: bool = False) -> dict:
        """Run docker-compose down"""
        if not self.compose_available:
            return {'success': False, 'message': 'Docker Compose not available'}
        
        try:
            cmd = self._get_compose_cmd()
            cmd.extend(['-f', compose_file, 'down'])
            
            if volumes:
                cmd.append('-v')
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {
                'success': True,
                'message': 'Compose project stopped',
                'output': result.stdout
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def compose_ps(self, compose_file: str) -> dict:
        """List compose project containers"""
        if not self.compose_available:
            return {'success': False, 'message': 'Docker Compose not available'}
        
        try:
            cmd = self._get_compose_cmd()
            cmd.extend(['-f', compose_file, 'ps', '--format', 'json'])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        containers.append(json.loads(line))
                    except:
                        pass
            
            return {
                'success': True,
                'containers': containers,
                'count': len(containers)
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _get_compose_cmd(self) -> List[str]:
        """Get docker compose command"""
        try:
            result = subprocess.run(['docker', 'compose', 'version'], capture_output=True)
            if result.returncode == 0:
                return ['docker', 'compose']
        except:
            pass
        return ['docker-compose']
    
    # ===== Network Management =====
    
    def list_networks(self) -> dict:
        """List Docker networks"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            result = subprocess.run([
                'docker', 'network', 'ls', '--format', '{{json .}}'
            ], capture_output=True, text=True)
            
            networks = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    network = json.loads(line)
                    networks.append({
                        'id': network.get('ID'),
                        'name': network.get('Name'),
                        'driver': network.get('Driver'),
                        'scope': network.get('Scope')
                    })
            
            return {
                'success': True,
                'networks': networks,
                'count': len(networks)
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def create_network(self, name: str, driver: str = 'bridge',
                      subnet: str = None) -> dict:
        """Create Docker network"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'network', 'create', '--driver', driver]
            
            if subnet:
                cmd.extend(['--subnet', subnet])
            
            cmd.append(name)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {
                'success': True,
                'message': f'Network {name} created',
                'network_id': result.stdout.strip()[:12]
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def remove_network(self, network_name: str) -> dict:
        """Remove Docker network"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            result = subprocess.run([
                'docker', 'network', 'rm', network_name
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {'success': True, 'message': f'Network {network_name} removed'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Volume Management =====
    
    def list_volumes(self) -> dict:
        """List Docker volumes"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            result = subprocess.run([
                'docker', 'volume', 'ls', '--format', '{{json .}}'
            ], capture_output=True, text=True)
            
            volumes = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    volume = json.loads(line)
                    volumes.append({
                        'name': volume.get('Name'),
                        'driver': volume.get('Driver'),
                        'mountpoint': volume.get('Mountpoint')
                    })
            
            return {
                'success': True,
                'volumes': volumes,
                'count': len(volumes)
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def create_volume(self, name: str, driver: str = 'local') -> dict:
        """Create Docker volume"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            result = subprocess.run([
                'docker', 'volume', 'create', '--driver', driver, name
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {'success': True, 'message': f'Volume {name} created'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def remove_volume(self, volume_name: str, force: bool = False) -> dict:
        """Remove Docker volume"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'volume', 'rm']
            if force:
                cmd.append('-f')
            cmd.append(volume_name)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
            
            return {'success': True, 'message': f'Volume {volume_name} removed'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== System Cleanup =====
    
    def system_prune(self, all_unused: bool = False, volumes: bool = False) -> dict:
        """Clean up unused Docker resources"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            cmd = ['docker', 'system', 'prune', '-f']
            
            if all_unused:
                cmd.append('-a')
            if volumes:
                cmd.append('--volumes')
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return {
                'success': True,
                'message': 'System pruned',
                'output': result.stdout
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def get_disk_usage(self) -> dict:
        """Get Docker disk usage"""
        if not self.docker_available:
            return {'success': False, 'message': 'Docker not available'}
        
        try:
            result = subprocess.run([
                'docker', 'system', 'df', '--format', '{{json .}}'
            ], capture_output=True, text=True)
            
            usage = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    usage.append(json.loads(line))
            
            return {
                'success': True,
                'disk_usage': usage
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
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
            print(f"Failed to write Docker config: {e}")


# Global instance
docker_manager = DockerManager()
