"""
ApkayA Enterprise Control Panel - Database Management Module

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import os
import json
import time
import pymysql
import redis
from typing import Any, Dict, List, Optional, Tuple
from .public import Public, return_msg, return_data, read_json, write_json


class Database:
    """Database management - supports MySQL, PostgreSQL, MongoDB, Redis"""
    
    def __init__(self):
        self.config_file = os.path.join(Public.get_config_path(), 'database.json')
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load database configuration"""
        if os.path.exists(self.config_file):
            return read_json(self.config_file) or {}
        return {
            'mysql': [],
            'postgresql': [],
            'mongodb': [],
            'redis': []
        }
    
    def _save_config(self) -> bool:
        """Save database configuration"""
        return write_json(self.config_file, self.config)
    
    # ========== MYSQL OPERATIONS ==========
    
    def list_mysql(self) -> Dict:
        """List all MySQL databases"""
        return return_data(True, self.config.get('mysql', []), 'MySQL databases retrieved')
    
    def add_mysql(self, name: str, host: str, user: str, password: str, port: int = 3306) -> Dict:
        """Add MySQL database"""
        if not name or not host or not user:
            return return_msg(False, 'Database name, host, and user are required')
        
        # Test connection
        try:
            conn = pymysql.connect(
                host=host,
                user=user,
                password=password,
                port=port,
                connect_timeout=5
            )
            conn.close()
        except Exception as e:
            return return_msg(False, f'Connection failed: {str(e)}')
        
        # Add to config
        db_item = {
            'id': int(time.time()),
            'name': name,
            'host': host,
            'user': user,
            'password': password,
            'port': port,
            'created': Public.get_timestamp()
        }
        
        if 'mysql' not in self.config:
            self.config['mysql'] = []
        
        self.config['mysql'].append(db_item)
        self._save_config()
        
        return return_msg(True, 'MySQL database added successfully', db_item['id'])
    
    def delete_mysql(self, db_id: int) -> Dict:
        """Delete MySQL database"""
        if 'mysql' not in self.config:
            return return_msg(False, 'No MySQL databases found')
        
        self.config['mysql'] = [db for db in self.config['mysql'] if db.get('id') != db_id]
        self._save_config()
        return return_msg(True, 'MySQL database removed')
    
    def get_mysql_info(self, db_id: int) -> Dict:
        """Get MySQL database information"""
        if 'mysql' not in self.config:
            return return_msg(False, 'MySQL database not found')
        
        for db in self.config['mysql']:
            if db.get('id') == db_id:
                return return_data(True, db)
        
        return return_msg(False, 'MySQL database not found')
    
    def execute_mysql_query(self, db_id: int, query: str) -> Dict:
        """Execute query on MySQL database"""
        db_info = self.get_mysql_info(db_id)
        if not db_info.get('status'):
            return db_info
        
        db = db_info.get('data', {})
        
        try:
            conn = pymysql.connect(
                host=db['host'],
                user=db['user'],
                password=db['password'],
                port=db['port'],
                connect_timeout=5
            )
            cursor = conn.cursor()
            cursor.execute(query)
            
            if query.strip().upper().startswith('SELECT'):
                result = cursor.fetchall()
                return return_data(True, result)
            else:
                conn.commit()
                return return_msg(True, f'Query executed. Rows affected: {cursor.rowcount}')
        except Exception as e:
            return return_msg(False, f'Query error: {str(e)}')
        finally:
            try:
                cursor.close()
                conn.close()
            except:
                pass
    
    # ========== REDIS OPERATIONS ==========
    
    def list_redis(self) -> Dict:
        """List all Redis instances"""
        return return_data(True, self.config.get('redis', []), 'Redis instances retrieved')
    
    def add_redis(self, name: str, host: str, port: int = 6379, password: str = '') -> Dict:
        """Add Redis instance"""
        if not name or not host:
            return return_msg(False, 'Instance name and host are required')
        
        # Test connection
        try:
            r = redis.Redis(host=host, port=port, password=password or None, 
                          decode_responses=True, socket_connect_timeout=5)
            r.ping()
        except Exception as e:
            return return_msg(False, f'Connection failed: {str(e)}')
        
        # Add to config
        redis_item = {
            'id': int(time.time()),
            'name': name,
            'host': host,
            'port': port,
            'password': password,
            'created': Public.get_timestamp()
        }
        
        if 'redis' not in self.config:
            self.config['redis'] = []
        
        self.config['redis'].append(redis_item)
        self._save_config()
        
        return return_msg(True, 'Redis instance added successfully', redis_item['id'])
    
    def delete_redis(self, redis_id: int) -> Dict:
        """Delete Redis instance"""
        if 'redis' not in self.config:
            return return_msg(False, 'No Redis instances found')
        
        self.config['redis'] = [r for r in self.config['redis'] if r.get('id') != redis_id]
        self._save_config()
        return return_msg(True, 'Redis instance removed')
    
    def get_redis_info(self, redis_id: int) -> Dict:
        """Get Redis instance information"""
        if 'redis' not in self.config:
            return return_msg(False, 'Redis instance not found')
        
        for r in self.config['redis']:
            if r.get('id') == redis_id:
                return return_data(True, r)
        
        return return_msg(False, 'Redis instance not found')
    
    def redis_command(self, redis_id: int, command: str, *args) -> Dict:
        """Execute Redis command"""
        info = self.get_redis_info(redis_id)
        if not info.get('status'):
            return info
        
        r_data = info.get('data', {})
        
        try:
            r = redis.Redis(host=r_data['host'], port=r_data['port'], 
                          password=r_data.get('password') or None,
                          decode_responses=True)
            
            # Execute command
            result = r.execute_command(command, *args)
            return return_data(True, result)
        except Exception as e:
            return return_msg(False, f'Redis error: {str(e)}')
    
    # ========== DATABASE STATISTICS ==========
    
    def get_database_stats(self) -> Dict:
        """Get database statistics"""
        stats = {
            'mysql_count': len(self.config.get('mysql', [])),
            'postgresql_count': len(self.config.get('postgresql', [])),
            'mongodb_count': len(self.config.get('mongodb', [])),
            'redis_count': len(self.config.get('redis', [])),
            'total': (len(self.config.get('mysql', [])) +
                     len(self.config.get('postgresql', [])) +
                     len(self.config.get('mongodb', [])) +
                     len(self.config.get('redis', [])))
        }
        return return_data(True, stats)


# Global instance
database = Database()
