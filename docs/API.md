# API Reference - Apkaya Panel WAF

> **Developed by Albert Camings** | Full Stack Developer

## Base URLs

- **Panel API**: `http://localhost:8888/api`
- **WAF API**: `http://localhost:8379/api`

## Response Format

All API endpoints return JSON in the following format:

```json
{
  "status": true,
  "msg": "Success message",
  "data": {}
}
```

## System Endpoints

### Get System Information
- **Endpoint**: `GET /api/system/info`
- **Response**: Complete system information (CPU, memory, disk, network)

### Get System Status
- **Endpoint**: `GET /api/system/status`
- **Response**: Real-time system metrics

## Database Endpoints

### List Databases
- **Endpoint**: `GET /api/database/list?type=mysql`
- **Parameters**:
  - `type`: `mysql`, `redis`, or `all`
- **Response**: Array of database connections

### Add Database
- **Endpoint**: `POST /api/database/add`
- **Body**:
  ```json
  {
    "type": "mysql",
    "name": "production",
    "host": "localhost",
    "user": "root",
    "password": "password",
    "port": 3306
  }
  ```

### Delete Database
- **Endpoint**: `POST /api/database/delete`
- **Body**:
  ```json
  {
    "type": "mysql",
    "id": 1234567890
  }
  ```

### Get Database Info
- **Endpoint**: `GET /api/database/info?type=mysql&id=1234567890`
- **Response**: Database connection details

## Website Endpoints

### List Websites
- **Endpoint**: `GET /api/sites/list`
- **Response**: Array of configured websites

### Add Website
- **Endpoint**: `POST /api/sites/add`
- **Body**:
  ```json
  {
    "domain": "example.com",
    "root_path": "/var/www/example.com",
    "php_version": "8.0",
    "server_type": "nginx",
    "ssl": false
  }
  ```

### Delete Website
- **Endpoint**: `POST /api/sites/delete`
- **Body**:
  ```json
  {
    "id": 1234567890,
    "remove_files": false
  }
  ```

### Update Website
- **Endpoint**: `POST /api/sites/update`
- **Body**:
  ```json
  {
    "id": 1234567890,
    "updates": {
      "status": "disabled",
      "php_version": "8.1"
    }
  }
  ```

### Get Site Statistics
- **Endpoint**: `GET /api/sites/stats`
- **Response**: Statistics for all websites

## File Manager Endpoints

### List Files
- **Endpoint**: `POST /api/files/list`
- **Body**:
  ```json
  {
    "path": "/var/www"
  }
  ```

### Read File
- **Endpoint**: `POST /api/files/read`
- **Body**:
  ```json
  {
    "path": "/var/www/index.html"
  }
  ```

### Write File
- **Endpoint**: `POST /api/files/write`
- **Body**:
  ```json
  {
    "path": "/var/www/index.html",
    "content": "<html>...</html>"
  }
  ```

### Delete File
- **Endpoint**: `POST /api/files/delete`
- **Body**:
  ```json
  {
    "path": "/var/www/index.html"
  }
  ```

### Create Directory
- **Endpoint**: `POST /api/files/mkdir`
- **Body**:
  ```json
  {
    "path": "/var/www/newdir"
  }
  ```

### Copy File
- **Endpoint**: `POST /api/files/copy`
- **Body**:
  ```json
  {
    "source": "/var/www/file.txt",
    "destination": "/var/www/file.bak"
  }
  ```

### Move File
- **Endpoint**: `POST /api/files/move`
- **Body**:
  ```json
  {
    "source": "/var/www/file.txt",
    "destination": "/var/www/moved/file.txt"
  }
  ```

### Compress File
- **Endpoint**: `POST /api/files/compress`
- **Body**:
  ```json
  {
    "source": "/var/www",
    "output": "/var/www/backup.zip"
  }
  ```

### Extract File
- **Endpoint**: `POST /api/files/extract`
- **Body**:
  ```json
  {
    "archive": "/var/www/backup.zip",
    "destination": "/var/www/restored"
  }
  ```

### Get File Info
- **Endpoint**: `GET /api/files/info?path=/var/www/file.txt`
- **Response**: Detailed file information

## WAF Endpoints

### Get WAF Status
- **Endpoint**: `GET /api/waf/status`
- **Response**: Current WAF service status

### Start WAF
- **Endpoint**: `POST /api/waf/start`
- **Response**: Service start confirmation

### Stop WAF
- **Endpoint**: `POST /api/waf/stop`
- **Response**: Service stop confirmation

### Get WAF Configuration
- **Endpoint**: `GET /api/waf/config`
- **Response**: Current WAF configuration

### Update WAF Configuration
- **Endpoint**: `POST /api/waf/config/update`
- **Body**:
  ```json
  {
    "modules": {
      "sql_injection": false,
      "xss": true
    },
    "rate_limit": {
      "enabled": true,
      "requests_per_second": 100
    }
  }
  ```

### Get WAF Logs
- **Endpoint**: `POST /api/waf/logs`
- **Body**:
  ```json
  {
    "limit": 100,
    "offset": 0
  }
  ```

### Get WAF Statistics
- **Endpoint**: `GET /api/waf/stats?days=7`
- **Parameters**:
  - `days`: Number of days to retrieve (default: 7)
- **Response**: Attack statistics for the period

### Get WAF Rules
- **Endpoint**: `GET /api/waf/rules`
- **Response**: Current WAF detection rules

### Test Payload
- **Endpoint**: `POST /api/waf/test`
- **Body**:
  ```json
  {
    "payload": "' OR '1'='1"
  }
  ```
- **Response**: Whether payload would be blocked

### Add to Whitelist
- **Endpoint**: `POST /api/waf/whitelist/add`
- **Body**:
  ```json
  {
    "ip": "192.168.1.1"
  }
  ```

### Add to Blacklist
- **Endpoint**: `POST /api/waf/blacklist/add`
- **Body**:
  ```json
  {
    "ip": "192.168.1.100",
    "duration": 3600
  }
  ```

## Error Responses

### 400 Bad Request
```json
{
  "status": false,
  "msg": "Invalid request parameters"
}
```

### 404 Not Found
```json
{
  "status": false,
  "msg": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "status": false,
  "msg": "Internal server error"
}
```

## Authentication

Currently, all endpoints are accessible without authentication. For production use, implement:

- JWT token authentication
- API key authentication
- Session-based authentication
- Rate limiting per user/IP

## Rate Limiting

Currently: No rate limiting on API endpoints.

Recommended for production:
- 100 requests per minute per IP
- 1000 requests per minute per authenticated user

## Pagination

Endpoints that return large datasets support pagination:

```json
{
  "limit": 100,
  "offset": 0,
  "total": 1000
}
```

## Webhooks

WAF can send webhooks on detected attacks:

```json
POST /webhook/security
{
  "event": "attack_detected",
  "timestamp": 1234567890,
  "attack_type": "sql_injection",
  "source_ip": "192.168.1.1",
  "target_url": "/admin/login"
}
```
