# 🚀 ApkayA Enterprise Control Panel - Deployment Guide

> **Developed by Albert Camings** | Full Stack Developer

Complete guide for deploying ApkayA Enterprise Control Panel in production environments.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Initial Configuration](#initial-configuration)
4. [Production Deployment](#production-deployment)
5. [Security Hardening](#security-hardening)
6. [Monitoring & Maintenance](#monitoring--maintenance)
7. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Specifications

- **OS:** Windows Server 2016+, Ubuntu 20.04+, CentOS 8+, Debian 10+
- **CPU:** 2 cores minimum (4+ recommended)
- **RAM:** 2GB minimum (4GB+ recommended)
- **Disk Space:** 10GB minimum
- **Python:** 3.9+ (3.12+ recommended)
- **Network:** Static IP address, ports 72323 (HTTP), 443 (HTTPS)

### Recommended Specifications (Production)

- **CPU:** 4+ cores
- **RAM:** 8GB+
- **Disk:** 50GB+ SSD (for websites and backups)
- **Bandwidth:** Dedicated/unmetered
- **Firewall:** Hardware or cloud firewall recommended

### Required Services

- Nginx or Apache (auto-installed)
- MySQL 5.7+ or MariaDB 10.3+
- PHP 8.1+ (optional, if hosting PHP sites)
- FTP daemon (vsftpd for Linux, or native Windows FTP)
- OpenSSL for SSL/TLS

---

## Installation

### Step 1: Clone Repository

```bash
# Linux
git clone https://github.com/apkaya/apkaya-panel-waf.git
cd apkaya-panel-waf

# Windows (PowerShell)
git clone https://github.com/apkaya/apkaya-panel-waf.git
cd apkaya-panel-waf
```

### Step 2: Install Python Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows (PowerShell):
.\venv\Scripts\Activate

# Install requirements
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Create Required Directories

```bash
# Linux/macOS
mkdir -p config data logs backup ssl {webserver,rewrite,redirect,proxy}/launcher.shaiyastarlight.com

# Windows (PowerShell)
mkdir -force config, data, logs, backup, ssl, webserver, rewrite, redirect, proxy | out-null
mkdir -force webserver/launcher.shaiyastarlight.com, rewrite/launcher.shaiyastarlight.com, redirect/launcher.shaiyastarlight.com, proxy/launcher.shaiyastarlight.com | out-null
```

### Step 4: Initialize Application

```bash
# Create initial config
python run.py --init

# Or simply run (will auto-create necessary files)
python run.py
```

---

## Initial Configuration

### 1. Default Credentials

**Important:** Change these immediately after installation!

```
Username: admin
Password: (generated and saved in config/app.config)
Email: admin@localhost
```

Retrieve initial password from logs:
```bash
grep -i "initial password\|default password" logs/*.log
```

### 2. Access Control Panel

Open in browser:
```
http://your-server-ip:72323
```

### 3. First Login

1. Click **Login** button
2. Use credentials from step 1
3. Change password immediately (**Settings → Profile → Change Password**)
4. Enable 2FA (**Settings → Security → Two-Factor Authentication**)

### 4. Configure Server Settings

**Navigate to: Settings → Server Configuration**

- [ ] Set server hostname
- [ ] Configure NTP for time sync
- [ ] Setup system backup schedule
- [ ] Enable firewall rules
- [ ] Configure logging

---

## Production Deployment

### Method 1: Systemd Service (Linux) - Recommended

Create `/etc/systemd/system/apkaya-panel.service`:

```ini
[Unit]
Description=Apkaya Panel WAF Control Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/apkaya-panel-waf
Environment="PATH=/root/apkaya-panel-waf/venv/bin"
Environment="FLASK_DEBUG=false"
Environment="FLASK_ENV=production"
ExecStart=/root/apkaya-panel-waf/venv/bin/python run.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=apkaya-panel

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable apkaya-panel
sudo systemctl start apkaya-panel
sudo systemctl status apkaya-panel
```

Check logs:
```bash
sudo journalctl -u apkaya-panel -f
```

### Method 2: Supervisor (Universal)

Install supervisor:
```bash
# Linux
sudo apt-get install supervisor

# Or
pip install supervisor
```

Create `/etc/supervisor/conf.d/apkaya-panel.conf`:

```ini
[program:apkaya-panel]
command=/root/apkaya-panel-waf/venv/bin/python /root/apkaya-panel-waf/run.py
directory=/root/apkaya-panel-waf
user=root
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/root/apkaya-panel-waf/logs/supervisor.log
environment=PATH="/root/apkaya-panel-waf/venv/bin",FLASK_DEBUG="false",FLASK_ENV="production"
```

Start:
```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start apkaya-panel
```

### Method 3: Docker (Containerized)

Build Docker image:

```bash
docker build -t apkaya-panel:latest .
```

Run container:

```bash
docker run -d \
  --name apkaya-panel \
  -p 72323:72323 \
  -v /root/apkaya-panel-data:/app/data \
  -v /root/apkaya-panel-config:/app/config \
  -v /root/apkaya-panel-logs:/app/logs \
  -e FLASK_DEBUG=false \
  -e FLASK_ENV=production \
  apkaya-panel:latest
```

### Method 4: Nginx Reverse Proxy (Recommended for Production)

Set up Nginx reverse proxy for SSL termination and better performance:

```nginx
upstream apkaya_backend {
    server 127.0.0.1:72323;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name panel.example.com;
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
    
    # ACME challenge for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name panel.example.com;
    
    # SSL Certificate (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        proxy_pass http://apkaya_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_buffering off;
    }
    
    # WebSocket support
    location /socket.io {
        proxy_pass http://apkaya_backend/socket.io;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    # Logging
    access_log /var/log/nginx/panel.example.com.access.log combined;
    error_log /var/log/nginx/panel.example.com.error.log;
}
```

---

## Security Hardening

### 1. Enable HTTPS Only

```bash
# Generate Let's Encrypt certificate
sudo certbot certonly --standalone -d panel.example.com

# Auto-renewal
sudo certbot renew --dry-run
sudo systemctl enable certbot.timer
```

### 2. Firewall Configuration

```bash
# Linux (UFW)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 72323/tcp # Local panel (restrict to admin IPs)
sudo ufw enable

# Or restrict panel access to specific IPs
sudo ufw allow from 192.168.1.0/24 to any port 72323
```

### 3. Configure Panel Firewall

1. Navigate to **Firewall** in control panel
2. Add whitelist rules for trusted IPs
3. Enable DDoS protection (if available)
4. Configure WAF rules for web applications

### 4. Database Security

```sql
-- Change MySQL root password
ALTER USER 'root'@'localhost' IDENTIFIED BY 'NEW_SECURE_PASSWORD';

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root access
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Apply changes
FLUSH PRIVILEGES;
```

### 5. FTP Security

```bash
# Disable anonymous FTP
# Edit vsftpd.conf
sudo nano /etc/vsftpd.conf

# Set:
# anonymous_enable=NO
# local_enable=YES
# write_enable=YES
# chroot_local_user=YES

sudo systemctl restart vsftpd
```

### 6. API Security

In **Settings → API Security**:

- [ ] Enable API key authentication
- [ ] Set API rate limits (default: 100 req/min)
- [ ] Whitelist API IPs (if applicable)
- [ ] Enable request logging

### 7. Backup Security

```bash
# Ensure backups are encrypted
# In Settings → Backup → Encryption: Enable

# Secure backup storage
# Recommend: Offsite storage (AWS S3, Azure Blob, Google Drive)
```

---

## Monitoring & Maintenance

### Daily Checks

```bash
# Check service status
sudo systemctl status apkaya-panel

# Check disk space
df -h

# Monitor logs
tail -f /root/apkaya-panel-waf/logs/access.log
tail -f /root/apkaya-panel-waf/logs/error.log

# Check system metrics
# Open panel at http://your-ip:72323 → Dashboard
```

### Weekly Maintenance

- Review firewall logs
- Check failed login attempts
- Verify SSL certificate expiry
- Review backup completeness
- Check disk space trends

### Monthly Tasks

- Update system packages
- Review user access logs
- Verify disaster recovery procedures
- Test backup restoration

### Monitoring Stack

**Recommended monitoring tools:**
- Prometheus + Grafana (metrics)
- ELK Stack (log aggregation)
- Uptime Kuma (uptime monitoring)
- Zabbix (system monitoring)

---

## Troubleshooting

### Issue 1: Panel Won't Start

**Error:** `Address already in use`

**Solution:**
```bash
# Find process using port 72323
lsof -i :72323  # Linux/macOS
netstat -ano | findstr :72323  # Windows

# Kill the process
kill -9 <PID>  # Linux
taskkill /PID <PID> /F  # Windows

# Start panel again
python run.py
```

### Issue 2: High Memory Usage

**Cause:** Long-running processes, memory leaks

**Solution:**
```bash
# Restart application
sudo systemctl restart apkaya-panel

# Check processes
ps aux | grep python

# Enable memory monitoring
# Panel → Dashboard → System → Monitor RAM
```

### Issue 3: WebSocket Connection Fails

**Cause:** Reverse proxy not configured for WebSocket

**Solution:**
```nginx
# Add to Nginx config:
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

### Issue 4: SSL Certificate Errors

**Error:** `SSL: CERTIFICATE_VERIFY_FAILED`

**Solution:**
```bash
# Renew certificate
sudo certbot renew --force-renewal

# Check expiry
openssl x509 -enddate -noout -in /etc/letsencrypt/live/domain.com/cert.pem

# Auto-renewal check
sudo systemctl list-timers certbot.timer
```

### Issue 5: Database Connection Failed

**Error:** `Can't connect to MySQL server`

**Solution:**
```bash
# Check MySQL status
sudo systemctl status mysql  # or mariadb

# Start if stopped
sudo systemctl start mysql

# Test connection
mysql -u root -p

# Check credentials in config
cat config/database.json
```

### Issue 6: Files Permission Denied

**Error:** `Permission denied` when creating websites/backups

**Solution:**
```bash
# Fix directory permissions
sudo chown -R $USER:$USER /root/apkaya-panel-waf
sudo chmod -R 755 /root/apkaya-panel-waf

# Specific directory permissions
sudo chmod 777 /root/apkaya-panel-waf/data
sudo chmod 777 /root/apkaya-panel-waf/backup
sudo chmod 777 /root/apkaya-panel-waf/logs
```

---

## Performance Tuning

### Nginx Optimization

```nginx
# In main nginx.conf:
worker_processes auto;
worker_connections 2048;
keepalive_timeout 65;
gzip on;
gzip_types text/plain text/css application/json application/javascript;
gzip_min_length 1000;
```

### Database Optimization

```sql
-- Check slow queries
SHOW VARIABLES LIKE 'long_query_time';
SET GLOBAL long_query_time = 2;

-- Enable query logging
SET GLOBAL slow_query_log = 'ON';

-- Monitor
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Questions';
```

### Python Application Tuning

```bash
# In run.py environment variables:
export FLASK_ENV=production
export FLASK_DEBUG=false
export PYTHONOPTIMIZE=2  # Enable Python optimizations
```

---

## Backup & Recovery

### Create Backup

**Via UI:** Control Panel → Backup → Create Backup

**Via CLI:**
```bash
python -c "from panel.modules.backup import backup_manager; print(backup_manager.create_backup())"
```

### Restore Backup

1. Copy backup file to `backup/` directory
2. Go to **Backup** → **Restore**
3. Select backup file
4. Confirm restoration

---

## Uninstallation

### Completely Remove

```bash
# Stop service
sudo systemctl stop apkaya-panel
sudo systemctl disable apkaya-panel

# Remove files
rm -rf /root/apkaya-panel-waf

# Remove database (CAREFUL!)
mysql -u root -p -e "DROP DATABASE apkaya_panel;"

# Remove firewall rules
sudo ufw delete allow 72323/tcp
```

---

## Support & Contribution

- **Documentation:** https://docs.apkaya.com
- **GitHub Issues:** https://github.com/apkaya/apkaya-panel-waf/issues
- **Community Forum:** https://forum.apkaya.com
- **Email Support:** support@apkaya.com

---

**Last Updated:** January 2026  
**Version:** 1.0  
**Status:** Production Ready
