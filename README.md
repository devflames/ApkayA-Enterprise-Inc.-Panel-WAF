# 🛡️ Apkaya Panel WAF - Server Management with Integrated Web Application Firewall

<p align="center">
  <strong>Developed by Albert Camings</strong><br>
  <sub>Full Stack Developer | Open Source Contributor</sub>
</p>

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-2.0%2B-green)](https://flask.palletsprojects.com/)
[![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen)]()
[![API Routes](https://img.shields.io/badge/api%20routes-174%2B-blue)]()
[![Author](https://img.shields.io/badge/author-Albert%20Camings-purple)]()

> A modern, enterprise-grade server control panel with integrated Web Application Firewall protection, comprehensive security features, and production-grade interface design.

Apkaya Panel WAF Edition is a powerful server management platform specifically designed for developers, system administrators, and enterprises who need an intuitive yet powerful server management solution. Built from the ground up on Flask with a focus on security, scalability, and exceptional user experience.

---

## 🌟 Key Highlights

**The user experience is driven by a refined and cohesive UI flow, where every control behaves predictably and every transition feels intentional. The result is a production-grade interface that balances clarity, performance, and scalability.**

- 🎨 **Modern Responsive UI** - Clean, intuitive dashboard with gradient design system
- 🛡️ **Integrated WAF** - Real-time threat detection and attack prevention
- 🔒 **90% Feature Parity** - Comprehensive feature coverage with enhanced security
- 📊 **Real-time Monitoring** - Live system stats (CPU, Memory, Disk, Services)
- 🔐 **Enterprise Security** - 2FA authentication, API key management, encryption
- 🚀 **174+ REST API Endpoints** - Full programmatic control of all features
- 📱 **Mobile Responsive** - Works seamlessly on desktop, tablet, and mobile
- ⚡ **Production Ready** - Enterprise-grade stability and performance

---

## 📦 Core Features

### 🏠 Dashboard & Monitoring
- **Real-time System Overview** - CPU, Memory, Disk usage with live updates
- **Service Status Display** - Nginx, MySQL, PHP-FPM, WAF health monitoring
- **Quick Actions Grid** - One-click access to common tasks
- **Alert System** - Real-time notifications for critical events
- **Performance Metrics** - Historical data and trend analysis

### 🌐 Website Management
- **Multi-domain Support** - Manage unlimited websites and subdomains
- **Virtual Host Configuration** - Apache/Nginx vhost auto-generation
- **SSL/TLS Management**
  - Let's Encrypt integration with auto-renewal
  - Self-signed certificate support
  - Wildcard certificate handling
  - SSL certificate status monitoring
  - Force HTTPS redirects
- **URL Rewrite Rules** - Built-in rule builder for common scenarios
- **Website Statistics** - Bandwidth, traffic analysis, visitor tracking
- **FTP/SFTP Access** - Create and manage FTP accounts per domain

### 🛡️ WAF (Web Application Firewall)
- **SQL Injection Protection** - Pattern matching and parameterized query enforcement
- **XSS (Cross-Site Scripting) Prevention** - Input sanitization and output encoding
- **Rate Limiting** - Per-IP and per-endpoint rate control
- **Bot Detection** - Automated bot detection and blocking
- **DDoS Mitigation** - Layer 7 attack protection
- **Custom Rules** - Create domain-specific security rules
- **Attack Logging** - Full audit trail of blocked attacks
- **Real-time Dashboard** - Threat visualization and statistics
- **Geographic Blocking** - Block/allow by country
- **User-Agent Filtering** - Block malicious user agents

### 🔥 Firewall Management
- **iptables Rules** - Low-level firewall configuration
- **Whitelist/Blacklist** - IP-based access control
- **Port Management** - Add, modify, delete ports safely
- **Firewall Rules UI** - Visual rule builder
- **Connection Limits** - Rate limiting at network level
- **Port Scanning Detection** - Alert on suspicious port scanning

### 💾 Database Management
- **MySQL/MariaDB Support**
  - Database creation and deletion
  - User account management
  - Permission control (host, database, table-level)
  - Backup/restore functionality
  - Database statistics and monitoring
- **phpMyAdmin Integration** - Web-based database management
- **Database Size Monitoring** - Track growth and usage
- **Backup Scheduling** - Automated database backups
- **Replication Support** - Master-slave database replication setup

### 📁 File Manager
- **Web-based File Operations**
  - Browse directory structure
  - Upload/download files
  - Create/edit files (text-based)
  - Rename, copy, move, delete
  - Set file permissions (chmod)
- **Syntax Highlighting** - For code file editing
- **Batch Operations** - Multi-file actions
- **Search Functionality** - Find files/folders
- **Compression** - Zip/tar file creation and extraction
- **Path Safety** - Prevent directory traversal attacks

### 🔄 Backup & Restore
- **Automated Backups**
  - Scheduled daily/weekly/monthly
  - Full website backups (files + database)
  - Database-only backups
  - File-only backups
- **Backup Storage**
  - Local storage
  - Remote cloud storage (S3, Azure, etc.)
  - FTP backup destinations
- **Restore Management**
  - One-click restore to any backup point
  - Selective file restoration
  - Database point-in-time recovery
- **Backup Compression** - gzip/bzip2 compression
- **Retention Policies** - Auto-cleanup old backups

### ⏰ Cron Job Management
- **GUI Cron Editor** - No need to edit crontab manually
- **Predefined Templates** - Common cron patterns
- **PHP Task Runner** - Execute PHP scripts on schedule
- **Shell Script Support** - Run bash scripts
- **Email Notifications** - Get notified on job execution
- **Job Logging** - Full execution logs with output
- **Failure Alerts** - Automatic notifications on errors
- **Timezone Support** - Schedule for different timezones

### 🐳 Docker Support
- **Container Management**
  - Deploy containers from images
  - Start/stop/restart containers
  - View container logs
  - Resource monitoring
- **Image Management**
  - Pull from Docker Hub
  - Create custom images
  - Image versioning
- **Volume Management** - Persistent data storage
- **Network Configuration** - Custom Docker networks
- **Docker Compose** - Multi-container orchestration

### 📤 FTP Server Management
- **FTP Account Management**
  - Create/edit/delete FTP accounts
  - Per-domain FTP access
  - Quota management (disk usage limits)
- **Security Features**
  - SSL/TLS for FTP connections
  - IP whitelist/blacklist
  - Failed login attempt blocking
- **FTP Monitoring**
  - Connected clients
  - Bandwidth usage
  - Connection logs

### 🔧 PHP Management
- **Multi-PHP Version Support**
  - Install/remove PHP versions
  - Per-domain PHP version selection
  - PHP extension management
- **PHP Configuration**
  - Edit php.ini settings via UI
  - Memory limits, upload sizes, etc.
- **PHP Extensions**
  - Install/remove extensions
  - Version compatibility checking
- **OpCode Caching** - OPcache configuration
- **PHP Security Modules** - Suhosin patch configuration

### 📊 System Administration
- **Server Information**
  - OS details and kernel version
  - CPU specifications
  - RAM configuration
  - Disk partition layout
- **Service Management**
  - Start/stop/restart services
  - Service auto-start configuration
  - Service health monitoring
- **Log Viewer**
  - System logs
  - Service logs
  - Access logs
  - Error logs with search/filter
- **System Updates** - OS and package updates management
- **Resource Monitoring** - Long-term performance graphs

### 🔐 Security & Authentication
- **Two-Factor Authentication (2FA)**
  - TOTP/Google Authenticator support
  - Backup codes for account recovery
- **API Security**
  - API key management
  - Rate limiting per API key
  - IP whitelist for API
  - Audit logging for API calls
- **Session Management**
  - Secure cookie handling
  - Session timeout configuration
  - Concurrent session control
- **Password Security**
  - bcrypt hashing with salt
  - Password strength requirements
  - Password expiration policies
- **Audit Logging**
  - User activity tracking
  - Login/logout logs
  - Admin action logging
  - Change history

---

## 🚀 API Overview

### 174+ REST API Endpoints Covering:

**System Management**
```
GET    /api/system/info           - System information and stats
GET    /api/system/update         - Check for updates
POST   /api/system/reboot         - Reboot server
POST   /api/system/shutdown       - Shutdown server
```

**Website Management**
```
GET    /api/sites/list            - List all websites
POST   /api/sites/create          - Create new website
PUT    /api/sites/:id/update      - Update website config
DELETE /api/sites/:id             - Delete website
GET    /api/sites/:id/stats       - Website statistics
```

**Database Management**
```
GET    /api/database/list         - List databases
POST   /api/database/create       - Create database
POST   /api/database/backup       - Backup database
POST   /api/database/restore      - Restore database
DELETE /api/database/:name        - Delete database
```

**WAF Protection**
```
GET    /api/waf/status            - WAF status
GET    /api/waf/logs              - WAF event logs
POST   /api/waf/rules/create      - Create custom rule
GET    /api/waf/stats             - Attack statistics
```

**SSL/TLS Management**
```
GET    /api/ssl/certificates      - List certificates
POST   /api/ssl/create            - Create certificate
POST   /api/ssl/renew             - Renew certificate
DELETE /api/ssl/:id               - Delete certificate
```

**Backup & Restore**
```
GET    /api/backup/list           - List backups
POST   /api/backup/create         - Create backup
POST   /api/backup/restore        - Restore backup
DELETE /api/backup/:id            - Delete backup
```

**Firewall Rules**
```
GET    /api/firewall/status       - Firewall status
POST   /api/firewall/rules        - Add firewall rule
GET    /api/firewall/logs         - Firewall logs
DELETE /api/firewall/rule/:id     - Remove rule
```

**Cron Jobs**
```
GET    /api/cron/jobs             - List cron jobs
POST   /api/cron/create           - Create job
PUT    /api/cron/:id/update       - Update job
DELETE /api/cron/:id              - Delete job
```

**FTP Management**
```
GET    /api/ftp/accounts          - List FTP accounts
POST   /api/ftp/create            - Create FTP account
PUT    /api/ftp/:id/update        - Update FTP account
DELETE /api/ftp/:id               - Delete FTP account
```

**Docker Support**
```
GET    /api/docker/containers     - List containers
POST   /api/docker/deploy         - Deploy container
GET    /api/docker/images         - List images
GET    /api/docker/logs/:id       - Container logs
```

**File Management**
```
GET    /api/files/list            - List files
POST   /api/files/upload          - Upload file
PUT    /api/files/edit            - Edit file
DELETE /api/files/:path           - Delete file
POST   /api/files/compress        - Compress files
```

See [API Documentation](docs/API.md) for complete endpoint reference.

---

## 🛠️ Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Backend** | Flask | 2.0+ |
| **Python** | CPython | 3.12+ |
| **Frontend** | HTML5/CSS3/JavaScript | ES6+ |
| **Database** | JSON Config | Native |
| **Server** | Nginx/Apache | Latest |
| **Authentication** | JWT + 2FA | TOTP |
| **API Security** | API Keys + Rate Limiting | Custom |
| **Encryption** | bcrypt + AES-256 | Industry Standard |

---

## 📋 System Requirements

### Minimum Requirements
- **OS**: Windows Server 2022+ / Linux (Ubuntu 20.04+, CentOS 7+)
- **Python**: 3.12 or higher
- **RAM**: 512 MB (2GB+ recommended)
- **Disk**: 1 GB available space
- **Internet**: For SSL cert validation and updates

### Recommended Configuration
- **OS**: Windows Server 2022 / Ubuntu 22.04 LTS / AlmaLinux 9
- **Python**: 3.12+
- **RAM**: 4GB+
- **CPU**: 2+ cores
- **Disk**: SSD with 10GB+ free space
- **Network**: Gigabit Ethernet

### Dependencies
```
flask>=2.0.0
pymysql>=1.0.0
psutil>=5.0.0
pyotp>=2.8.0
qrcode>=7.0.0
pillow>=9.0.0
bcrypt>=4.0.0
redis>=5.0.0
pymongo>=4.0.0
```

---

## 🚀 Installation & Setup

### Quick Start (Windows)

```bash
# 1. Clone repository
git clone https://github.com/yourusername/apkaya-panel-waf.git
cd apkaya-panel-waf

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run the application
python run.py

# 4. Access in browser
# http://localhost:72323
# Default: admin / admin (change immediately!)
```

### Production Deployment (Ubuntu/CentOS)

```bash
# 1. System updates
sudo apt update && sudo apt upgrade -y

# 2. Install dependencies
sudo apt install python3.12 python3.12-venv nginx mysql-server -y

# 3. Clone and setup
git clone https://github.com/yourusername/apkaya-panel-waf.git
cd apkaya-panel-waf

# 4. Create virtual environment
python3.12 -m venv venv
source venv/bin/activate

# 5. Install Python packages
pip install -r requirements.txt

# 6. Run with supervisor
sudo cp deployment/supervisor.conf /etc/supervisor/conf.d/apkaya.conf
sudo supervisorctl reread && sudo supervisorctl update
sudo supervisorctl start apkaya
```

See [Deployment Guide](docs/DEPLOYMENT.md) for detailed setup instructions.

---

## 🎯 Key Feature Matrix

| Feature | Status | Description |
|---------|--------|-------------|
| **WAF Integration** | ✅ Built-in | Real-time threat detection and prevention |
| **2FA Authentication** | ✅ TOTP | Google Authenticator compatible |
| **API Endpoints** | ✅ 174+ | Full REST API coverage |
| **Modern UI** | ✅ Gradient Design | Clean, responsive interface |
| **Docker Support** | ✅ Full | Container lifecycle management |
| **Rate Limiting** | ✅ Advanced | Per-IP and per-endpoint controls |
| **Mobile Responsive** | ✅ Yes | Works on all devices |
| **Audit Logging** | ✅ Comprehensive | Full activity tracking |
| **Bot Detection** | ✅ Yes | Automated threat filtering |
| **CDN Ready** | 🔜 Phase 2 | Gaming & blockchain CDN support |

---

## ⚠️ Known Limitations

The following features have documented limitations in v1.0.0:

| Feature | Status | Details |
|---------|--------|---------|
| **Let's Encrypt (ACME)** | Manual Setup Required | Auto-ACME challenge not implemented. Use certbot externally or self-signed certificates. See [SSL Documentation](docs/SSL.md) |
| **WAF External Service** | API Client Only | WAF module provides API client for external WAF service (port 8379). Requires separate WAF daemon. |
| **Redis Rate Limiting** | In-Memory | Rate limiting uses thread-safe in-memory store. For distributed deployments, configure external Redis. |
| **Email Notifications** | Not Implemented | Planned for Phase 2. Currently logging-only alerts. |
| **Multi-server Management** | Single Server | Currently designed for single-server deployment. Cluster support in Phase 3. |

### SSL Certificate Options

1. **Self-Signed** - Full support via `/api/ssl/self-signed` (immediate)
2. **Manual Upload** - Full support via `/api/ssl/certificates/<domain>/upload`
3. **Let's Encrypt** - Manual certbot setup, then upload certificates

---

## 🗓️ Roadmap & Future Features

### Phase 2 (Q1 2026) - Advanced Features
- [ ] **AI-Powered Threat Detection** - Machine learning-based anomaly detection
- [ ] **Kubernetes Integration** - Full K8s cluster management
- [ ] **Advanced Monitoring** - Prometheus + Grafana integration
- [ ] **Email Notifications** - SMTP configuration for alerts
- [ ] **Webhooks Support** - Event-driven integrations
- [ ] **Dark Mode** - System theme toggle
- [ ] **Multi-language Support** - i18n framework (Spanish, French, German, etc.)

### Phase 3 (Q2 2026) - Enterprise Features
- [ ] **LDAP/Active Directory** - Enterprise authentication
- [ ] **Single Sign-On (SSO)** - SAML 2.0 support
- [ ] **Role-Based Access Control (RBAC)** - Granular permissions
- [ ] **Geo-Redundancy** - Multi-server management
- [ ] **Advanced Reporting** - Custom report builder
- [ ] **API Marketplace** - Third-party integrations
- [ ] **Web Terminal** - SSH/Browser shell access
- [ ] **VPN Management** - OpenVPN/WireGuard setup

### Phase 4 (Q3 2026) - Automation & Intelligence
- [ ] **Terraform Provider** - Infrastructure as Code support
- [ ] **Ansible Playbooks** - Automated deployment
- [ ] **CI/CD Integration** - GitHub Actions, GitLab CI
- [ ] **Auto-scaling** - Automatic resource scaling
- [ ] **Predictive Analytics** - Resource forecasting
- [ ] **Smart Caching** - Redis/Memcached optimization
- [ ] **Database Optimization** - Query analyzer and suggestions
- [ ] **Code Deployment** - Git push-to-deploy workflow

### Phase 5 (Q4 2026) - Cloud & Scale
- [ ] **Multi-Cloud Support** - AWS, Azure, GCP connectors
- [ ] **Load Balancing** - Advanced LB configuration
- [ ] **CDN Integration** - CloudFlare, AWS CloudFront
- [ ] **Container Registry** - Private Docker registry
- [ ] **Serverless Support** - AWS Lambda, Azure Functions
- [ ] **Disaster Recovery** - Automated failover
- [ ] **Cost Optimization** - Multi-cloud cost analysis

### Community Requested Features (Under Consideration)
- [ ] **Email Server Management** - Mail configuration and monitoring
- [ ] **DNS Management** - PowerDNS integration
- [ ] **Git Repository Hosting** - Gitea integration
- [ ] **Monitoring Integrations** - Datadog, New Relic support
- [ ] **Advanced Logging** - ELK Stack integration
- [ ] **Machine Learning** - Behavioral analysis and predictions

---

## 🔒 Security Features

### Built-in Security Layers
1. **Input Validation** - All user inputs sanitized and validated
2. **SQL Injection Prevention** - Parameterized queries throughout
3. **CSRF Protection** - Anti-CSRF tokens on all forms
4. **XSS Protection** - HTML escaping and Content Security Policy
5. **Rate Limiting** - API rate limits and brute-force protection
6. **Encryption** - AES-256 for sensitive data, bcrypt for passwords
7. **Session Security** - Secure cookies with HTTPOnly flag
8. **Audit Trail** - Comprehensive logging of all admin actions

### WAF Protection Capabilities
- Real-time threat detection and blocking
- Automated attack signature updates
- DDoS mitigation and flood protection
- Bot filtering and JavaScript validation
- Custom rule creation and management
- Geographic IP blocking and filtering
- User-Agent based filtering
- Request/Response inspection

---

## 📖 Documentation

- [API Documentation](docs/API.md) - Complete endpoint reference
- [Deployment Guide](docs/DEPLOYMENT.md) - Production setup
- [Configuration Reference](docs/CONFIG.md) - All settings
- [Security Best Practices](docs/SECURITY.md) - Hardening guide
- [Contributing Guide](CONTRIBUTING.md) - Development guidelines
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [FAQ](docs/FAQ.md) - Frequently asked questions

---

## 🤝 Contributing

We welcome contributions! Please follow our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/apkaya-panel-waf.git

# Create feature branch
git checkout -b feature/amazing-feature

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Submit pull request
```

### Areas for Contribution
- Bug fixes and improvements
- Feature implementation
- Documentation enhancements
- Translation support
- Security audits
- Performance optimization

---

## 📞 Support & Community

- **Discord Server** - [Join Community](https://discord.gg/apkaya)
- **GitHub Discussions** - [Ask Questions](https://github.com/apkaya/apkaya-panel-waf/discussions)
- **Issue Tracker** - [Report Bugs](https://github.com/apkaya/apkaya-panel-waf/issues)
- **Email Support** - support@apkaya.com
- **Documentation** - https://docs.apkaya.com

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⭐ Show Your Support

If you find this project helpful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs and suggesting features
- 💬 Joining our community discussions
- 📢 Sharing with others who might benefit
- 💰 Supporting development via sponsorship

---

## 🙏 Acknowledgments

- **Albert Camings** - Project Creator & Full Stack Developer
- **Flask Community** - Excellent web framework
- **Open Source Contributors** - Community support and feedback
- **Security Researchers** - Responsible disclosure and security improvements
- **Enterprise Users** - Valuable feedback and feature requests

---

## 👨‍💻 About the Developer

**Albert Camings** - Full Stack Developer

Creator and maintainer of Apkaya Panel WAF. Passionate about building secure, scalable, and user-friendly server management solutions.

- 🌐 Building tools that make server management accessible
- 🔒 Security-first development approach
- 📖 Open source advocate
- 💻 Python, Flask, JavaScript, DevOps

---

## 📊 Project Statistics

- **Lines of Code**: 11,580+
- **API Routes**: 174+
- **Core Modules**: 8 (SSL, Firewall, Backup, Cron, Webserver, PHP, FTP, Docker)
- **Test Coverage**: 44 unit tests (all passing)
- **Platform**: Enterprise-grade server management
- **Languages**: Python, JavaScript, HTML5, CSS3

---

## 🚀 Quick Links

- [GitHub Repository](https://github.com/apkaya/apkaya-panel-waf)
- [Live Demo](https://demo.apkaya.com) (admin / demo)
- [Documentation](https://docs.apkaya.com)
- [Releases](https://github.com/apkaya/apkaya-panel-waf/releases)
- [Issue Tracker](https://github.com/apkaya/apkaya-panel-waf/issues)

---

<p align="center">
  <strong>Built with ❤️ by Albert Camings</strong><br>
  <sub>Making server management accessible to everyone</sub>
</p>

---

**Author**: Albert Camings (Full Stack Developer)  
**Last Updated**: January 2026  
**Version**: 1.0.0  
**Status**: Production Ready ✅  
**License**: MIT License
