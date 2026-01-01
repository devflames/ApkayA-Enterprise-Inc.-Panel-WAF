"""
ApkayA Enterprise Control Panel - File Manager Module

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import shutil
import zipfile
import time
from typing import Dict, List, Optional
from .public import Public, return_msg, return_data, sanitize_path


class FileManager:
    """File management module"""
    
    def __init__(self):
        self.base_path = os.path.join(Public.get_panel_path(), 'data', 'vhost')
        os.makedirs(self.base_path, exist_ok=True)
    
    def list_files(self, path: str = '') -> Dict:
        """List files in directory"""
        path = sanitize_path(path)
        full_path = os.path.join(self.base_path, path)
        
        # Security check - prevent directory traversal
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied')
        
        if not os.path.exists(full_path):
            return return_msg(False, 'Directory not found')
        
        if not os.path.isdir(full_path):
            return return_msg(False, 'Not a directory')
        
        try:
            items = []
            for item in os.listdir(full_path):
                item_path = os.path.join(full_path, item)
                is_dir = os.path.isdir(item_path)
                
                stat = os.stat(item_path)
                items.append({
                    'name': item,
                    'path': os.path.join(path, item).replace('\\', '/'),
                    'type': 'directory' if is_dir else 'file',
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'permissions': oct(stat.st_mode)[-3:]
                })
            
            # Sort: directories first, then by name
            items.sort(key=lambda x: (x['type'] != 'directory', x['name'].lower()))
            
            return return_data(True, items, f'{len(items)} items found')
        except Exception as e:
            return return_msg(False, f'Error listing directory: {str(e)}')
    
    def read_file(self, path: str) -> Dict:
        """Read file contents"""
        path = sanitize_path(path)
        full_path = os.path.join(self.base_path, path)
        
        # Security check
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied')
        
        if not os.path.exists(full_path):
            return return_msg(False, 'File not found')
        
        if not os.path.isfile(full_path):
            return return_msg(False, 'Not a file')
        
        # Check file size (max 10MB)
        if os.path.getsize(full_path) > 10 * 1024 * 1024:
            return return_msg(False, 'File too large to read (max 10MB)')
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return return_data(True, {
                'content': content,
                'size': len(content),
                'path': path
            })
        except Exception as e:
            return return_msg(False, f'Error reading file: {str(e)}')
    
    def write_file(self, path: str, content: str) -> Dict:
        """Write to file"""
        path = sanitize_path(path)
        full_path = os.path.join(self.base_path, path)
        
        # Security check
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied')
        
        # Create directory if needed
        dir_path = os.path.dirname(full_path)
        try:
            os.makedirs(dir_path, exist_ok=True)
        except Exception as e:
            return return_msg(False, f'Error creating directory: {str(e)}')
        
        try:
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return return_msg(True, 'File written successfully')
        except Exception as e:
            return return_msg(False, f'Error writing file: {str(e)}')
    
    def delete_file(self, path: str) -> Dict:
        """Delete file"""
        path = sanitize_path(path)
        full_path = os.path.join(self.base_path, path)
        
        # Security check
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied')
        
        if not os.path.exists(full_path):
            return return_msg(False, 'File not found')
        
        try:
            if os.path.isfile(full_path):
                os.remove(full_path)
            elif os.path.isdir(full_path):
                shutil.rmtree(full_path)
            
            return return_msg(True, 'File/directory deleted successfully')
        except Exception as e:
            return return_msg(False, f'Error deleting: {str(e)}')
    
    def create_directory(self, path: str) -> Dict:
        """Create new directory"""
        path = sanitize_path(path)
        full_path = os.path.join(self.base_path, path)
        
        # Security check
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied')
        
        if os.path.exists(full_path):
            return return_msg(False, 'Directory already exists')
        
        try:
            os.makedirs(full_path, exist_ok=True)
            return return_msg(True, 'Directory created successfully')
        except Exception as e:
            return return_msg(False, f'Error creating directory: {str(e)}')
    
    def copy_file(self, source: str, destination: str) -> Dict:
        """Copy file or directory"""
        source = sanitize_path(source)
        destination = sanitize_path(destination)
        
        full_source = os.path.join(self.base_path, source)
        full_dest = os.path.join(self.base_path, destination)
        
        # Security checks
        if not os.path.abspath(full_source).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied - source')
        if not os.path.abspath(full_dest).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied - destination')
        
        if not os.path.exists(full_source):
            return return_msg(False, 'Source not found')
        
        if os.path.exists(full_dest):
            return return_msg(False, 'Destination already exists')
        
        try:
            if os.path.isfile(full_source):
                shutil.copy2(full_source, full_dest)
            else:
                shutil.copytree(full_source, full_dest)
            
            return return_msg(True, 'Copied successfully')
        except Exception as e:
            return return_msg(False, f'Error copying: {str(e)}')
    
    def move_file(self, source: str, destination: str) -> Dict:
        """Move file or directory"""
        source = sanitize_path(source)
        destination = sanitize_path(destination)
        
        full_source = os.path.join(self.base_path, source)
        full_dest = os.path.join(self.base_path, destination)
        
        # Security checks
        if not os.path.abspath(full_source).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied - source')
        if not os.path.abspath(full_dest).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied - destination')
        
        if not os.path.exists(full_source):
            return return_msg(False, 'Source not found')
        
        if os.path.exists(full_dest):
            return return_msg(False, 'Destination already exists')
        
        try:
            shutil.move(full_source, full_dest)
            return return_msg(True, 'Moved successfully')
        except Exception as e:
            return return_msg(False, f'Error moving: {str(e)}')
    
    def compress_file(self, source: str, output: str) -> Dict:
        """Compress file or directory to ZIP"""
        source = sanitize_path(source)
        output = sanitize_path(output)
        
        full_source = os.path.join(self.base_path, source)
        full_output = os.path.join(self.base_path, output)
        
        # Security checks
        if not os.path.abspath(full_source).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied - source')
        if not os.path.abspath(full_output).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied - output')
        
        if not os.path.exists(full_source):
            return return_msg(False, 'Source not found')
        
        try:
            with zipfile.ZipFile(full_output, 'w', zipfile.ZIP_DEFLATED) as zipf:
                if os.path.isfile(full_source):
                    zipf.write(full_source, os.path.basename(full_source))
                else:
                    for root, dirs, files in os.walk(full_source):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, os.path.dirname(full_source))
                            zipf.write(file_path, arcname)
            
            return return_msg(True, 'Compressed successfully')
        except Exception as e:
            return return_msg(False, f'Error compressing: {str(e)}')
    
    def extract_file(self, archive: str, destination: str) -> Dict:
        """Extract ZIP file"""
        archive = sanitize_path(archive)
        destination = sanitize_path(destination)
        
        full_archive = os.path.join(self.base_path, archive)
        full_dest = os.path.join(self.base_path, destination)
        
        # Security checks
        if not os.path.abspath(full_archive).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied - archive')
        if not os.path.abspath(full_dest).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied - destination')
        
        if not os.path.exists(full_archive):
            return return_msg(False, 'Archive not found')
        
        try:
            os.makedirs(full_dest, exist_ok=True)
            with zipfile.ZipFile(full_archive, 'r') as zipf:
                zipf.extractall(full_dest)
            
            return return_msg(True, 'Extracted successfully')
        except Exception as e:
            return return_msg(False, f'Error extracting: {str(e)}')
    
    def get_file_info(self, path: str) -> Dict:
        """Get detailed file information"""
        path = sanitize_path(path)
        full_path = os.path.join(self.base_path, path)
        
        # Security check
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.base_path)):
            return return_msg(False, 'Access denied')
        
        if not os.path.exists(full_path):
            return return_msg(False, 'File not found')
        
        try:
            stat = os.stat(full_path)
            info = {
                'name': os.path.basename(full_path),
                'path': path,
                'type': 'directory' if os.path.isdir(full_path) else 'file',
                'size': stat.st_size,
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'accessed': stat.st_atime,
                'permissions': oct(stat.st_mode)[-3:],
                'is_symlink': os.path.islink(full_path)
            }
            
            if info['type'] == 'directory':
                info['item_count'] = len(os.listdir(full_path))
            
            return return_data(True, info)
        except Exception as e:
            return return_msg(False, f'Error getting file info: {str(e)}')


# Global instance
file_manager = FileManager()
