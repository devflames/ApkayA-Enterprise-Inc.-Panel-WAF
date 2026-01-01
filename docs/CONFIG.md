# Apkaya Panel WAF - Configuration Guide

> **Developed by Albert Camings** | Full Stack Developer

## Quick Start

### Installation

```bash
# Clone or extract the repository
cd apkaya-Panel-WAF

# Run setup
python setup.py

# Start the panel
python run.py
```

Access the panel at: `http://localhost:8888`

## Configuration Files

All configuration files are located in the `config/` directory:

### panel.json
Main panel configuration
- Port and host settings
- SSL configuration
- Session timeout
- Security policies

### database.json
Database connection management
- MySQL connections
- PostgreSQL connections
- MongoDB connections
- Redis instances

### waf.json
WAF engine configuration
- Enabled modules
- Rate limiting settings
- Logging configuration
- IP whitelist/blacklist

## Directory Structure

```
apkaya-Panel-WAF/
├── config/              # Configuration files
├── data/                # Runtime data
│   ├── vhost/          # Website files
│   └── backup/         # Backups
├── logs/               # Application logs
├── panel/              # Web panel (Python/Flask)
│   ├── class/         # Business logic
│   ├── templates/     # HTML templates
│   ├── static/        # Assets
│   ├── routes/        # API routes
│   └── app.py         # Flask application
├── waf/               # WAF engine (Go)
├── run.py             # Main launcher
├── setup.py           # Setup script
└── requirements.txt   # Python dependencies
```

## Environment Variables

```bash
PANEL_PORT=8888        # Panel port (default: 8888)
PANEL_HOST=0.0.0.0     # Bind address (default: 0.0.0.0)
WAF_PORT=8379          # WAF port (default: 8379)
DEBUG=false            # Debug mode (default: false)
```

## Database Configuration

### Add MySQL Database

Edit `config/database.json`:
```json
{
  "mysql": [
    {
      "name": "production",
      "host": "localhost",
      "user": "root",
      "password": "password",
      "port": 3306
    }
  ]
}
```

### Add Redis Instance

```json
{
  "redis": [
    {
      "name": "cache",
      "host": "localhost",
      "port": 6379,
      "password": ""
    }
  ]
}
```

## WAF Module Configuration

All WAF modules are enabled by default. To disable a module, edit `config/waf.json`:

```json
{
  "modules": {
    "sql_injection": false,     // Disable SQL injection detection
    "xss": true,
    "ssrf": true,
    "command_injection": true,
    "file_upload": true,
    "file_inclusion": true,
    "php_injection": true,
    "java_injection": true,
    "template_injection": true,
    "xxe": true
  }
}
```

## Security Configuration

### Enable SSL

1. Obtain SSL certificate (Let's Encrypt, etc.)
2. Update `config/panel.json`:

```json
{
  "panel": {
    "ssl": true,
    "ssl_cert": "/path/to/cert.pem",
    "ssl_key": "/path/to/key.pem"
  }
}
```

3. Restart the panel

### Password Policy

Configure in `config/panel.json`:

```json
{
  "security": {
    "password_min_length": 12,
    "require_uppercase": true,
    "require_numbers": true,
    "require_special": true
  }
}
```

## Logging

Logs are stored in the `logs/` directory:
- `panel.log` - Panel application logs
- `waf.log` - WAF engine logs
- `access.log` - HTTP access logs
- `error.log` - Error logs

## API Documentation

### Panel API

See `API.md` for complete endpoint reference.

Base URL: `http://localhost:8888/api`

### WAF API

WAF runs on separate port (default: 8379)

Base URL: `http://localhost:8379/api`

## Backup & Recovery

### Create Backup

```bash
python run.py --backup
```

Backups are stored in `data/backup/`

### Restore Backup

```bash
python run.py --restore /path/to/backup.tar.gz
```

## Performance Tuning

### Database Connection Pool

```json
{
  "database": {
    "pool_size": 10,
    "max_overflow": 20,
    "pool_timeout": 30
  }
}
```

### Cache Configuration

```json
{
  "cache": {
    "type": "redis",
    "ttl": 3600
  }
}
```

## Troubleshooting

### Port Already in Use

```bash
# Change port in command line
python run.py --port 9999

# Or in config/panel.json
```

### Database Connection Failed

1. Check database credentials in `config/database.json`
2. Verify database server is running
3. Test connection: `python run.py --test-db`

### WAF Service Not Starting

1. Ensure Go WAF binary is built
2. Check port 8379 is available
3. Review `logs/waf.log` for errors

## Support

- Documentation: https://github.com/apkaya/panel-waf/wiki
- Issues: https://github.com/apkaya/panel-waf/issues
- Discussions: https://github.com/apkaya/panel-waf/discussions

## License

MIT License - Free and Open Source Forever
