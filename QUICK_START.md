# 🚀 Quick Start Guide

> **Developed by Albert Camings** | Full Stack Developer

Get ApkayA Enterprise Control Panel running in minutes!

## Prerequisites

- **Linux/Windows Server 2016+**
- **Python 3.9+** (3.12 recommended)
- **2GB RAM** minimum, 4GB+ recommended
- **10GB disk space** minimum
- **Static IP address**
- **Root/Administrator access**

## 📦 Installation

### Option 1: Automated Script (Linux) - Recommended

```bash
# Download and run installation script
curl -O https://raw.githubusercontent.com/apkaya/apkaya-panel-waf/main/install.sh
bash install.sh
```

**Installation takes ~5 minutes**

After completion:
- ✅ All dependencies installed
- ✅ Python virtual environment created
- ✅ MySQL database configured
- ✅ SSL certificate configured
- ✅ Systemd service running
- ✅ Firewall rules applied

### Option 2: Docker (Easiest)

```bash
# Clone repository
git clone https://github.com/apkaya/apkaya-panel-waf.git
cd apkaya-panel-waf

# Start with Docker Compose
docker-compose up -d

# Verify running
docker-compose ps
```

Access at: `http://localhost:72323`

### Option 3: Manual Installation

```bash
# 1. Clone repository
git clone https://github.com/apkaya/apkaya-panel-waf.git
cd apkaya-panel-waf

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or .\venv\Scripts\Activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run application
python run.py
```

Access at: `http://localhost:72323`

---

## 🔐 First Login

**Default Credentials:**
- **Username:** `admin`
- **Password:** Check `config/app.config` or logs

⚠️ **IMPORTANT:** Change password immediately after login!

1. Click **Settings** → **Profile**
2. Change password to something strong
3. Enable **Two-Factor Authentication** for security

---

## 📋 Configuration

### Change Default Port

Edit `run.py` or set environment variable:

```bash
export APKAYA_PORT=8080
python run.py
```

### Configure Database

Edit `config/database.json`:

```json
{
  "db_type": "mysql",
  "db_host": "localhost",
  "db_user": "apkaya_user",
  "db_password": "your_password",
  "db_name": "apkaya_panel"
}
```

### Enable HTTPS

```bash
# Using Let's Encrypt (automated)
sudo certbot certonly --standalone -d your-domain.com

# Update config/ssl.json with certificate paths
```

---

## 🏢 Add Your First Website

1. **Login** to control panel at `http://your-ip:72323`
2. Click **Websites** → **Add Website**
3. Fill in:
   - **Domain:** example.com
   - **Document Root:** /home/www/example.com
   - **PHP Version:** 8.3 (optional)
4. Click **Create**

Your website is now hosted! 🎉

---

## 🛡️ WAF Configuration

Enable protection for your site:

1. Go to **WAF** → **Protected Sites**
2. Add your domain
3. Select protection level:
   - **Basic:** XSS + SQL Injection protection
   - **Moderate:** + Rate limiting + Bot detection
   - **Strict:** Full protection + Custom rules

---

## 📊 Monitoring

**Dashboard** automatically shows:
- ✅ System health (CPU, Memory, Disk)
- ✅ Service status (Nginx, MySQL, PHP, WAF)
- ✅ Security alerts
- ✅ Recent activity

Real-time updates every 5 seconds.

---

## 🔧 Common Tasks

### Create MySQL Database

1. **Databases** → **Add Database**
2. Set name and username
3. Set password
4. Click **Create**

### Enable SSL for Website

1. **Websites** → Select domain
2. **SSL** → **Get Certificate**
3. Select certificate source (Let's Encrypt recommended)
4. Click **Issue**

Auto-renewal happens automatically!

### Create FTP Account

1. **Websites** → Select domain
2. **FTP** → **Add FTP Account**
3. Set username and password
4. Click **Create**

### Backup Website

1. **Websites** → Select domain
2. **Backup** → **Create Backup**
3. Choose backup type (Files + Database)
4. Click **Start**

---

## 📡 API Usage

Access 174+ REST API endpoints:

```bash
# Get system info
curl http://localhost:72323/api/system/info

# List websites
curl http://localhost:72323/api/sites/list

# Create API key (in Settings → API)
# Then use with Authorization header:
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:72323/api/sites/list
```

Full API documentation: [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

---

## 📚 Documentation

- **[Installation Guide](DEPLOYMENT_GUIDE.md)** - Detailed setup for production
- **[API Reference](API_DOCUMENTATION.md)** - All 174+ endpoints
- **[Security Guide](SECURITY.md)** - Security best practices
- **[Nginx Configuration](NGINX_CONFIGURATION_GUIDE.md)** - Complex setups
- **[WAF Rules](WAF_RULES.md)** - Custom security rules

---

## 🐛 Troubleshooting

### Panel Won't Start

```bash
# Check if port 72323 is in use
lsof -i :72323
kill -9 <PID>

# Try running again
python run.py
```

### Database Connection Failed

```bash
# Verify MySQL is running
systemctl status mysql

# Check credentials
cat config/database.json

# Test connection
mysql -u apkaya_user -p apkaya_panel
```

### High Memory Usage

```bash
# Restart application
systemctl restart apkaya-panel

# Check for background processes
ps aux | grep python
```

### WebSocket Errors

Ensure Nginx reverse proxy includes:

```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

---

## 🆘 Support

- **Issues:** [GitHub Issues](https://github.com/apkaya/apkaya-panel-waf/issues)
- **Discussions:** [GitHub Discussions](https://github.com/apkaya/apkaya-panel-waf/discussions)
- **Email:** support@apkaya.com
- **Documentation:** https://docs.apkaya.com

---

## 📄 License

MIT License - No restrictions. See [LICENSE](LICENSE)

---

## 🙏 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 🎯 Roadmap

- ✅ Website management
- ✅ SSL/TLS certificates
- ✅ WAF protection
- ✅ Database management
- ✅ File manager
- ✅ Firewall control
- ✅ Backup/restore
- ⏳ Kubernetes support
- ⏳ Clustering
- ⏳ Multi-region deployment

---

**Enjoy using ApkayA Enterprise Control Panel! 🚀**

*Last Updated: January 2026*
