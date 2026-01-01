# Changelog

All notable changes to ApkayA Enterprise Control Panel + WAF will be documented in this file.

**Author:** Albert Camings (Full Stack Developer)  
**Project:** ApkayA Enterprise Control Panel + WAF  
**License:** MIT

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-01-01

### Added
- **Authentication System**
  - User registration and login with bcrypt password hashing
  - Two-Factor Authentication (TOTP) with backup codes
  - Session management with secure cookies
  - Role-Based Access Control (RBAC)

- **API Security**
  - 177 REST API endpoints
  - Rate limiting with in-memory enforcement
  - API key management with HMAC signing
  - IP whitelist/blacklist

- **Website Management**
  - Multi-domain support
  - Virtual host configuration
  - PHP version selection per site

- **SSL/TLS Management**
  - Self-signed certificate generation
  - Manual certificate upload
  - Certificate renewal tracking
  - Let's Encrypt support (manual certbot)

- **Firewall Management**
  - Port management (open/close)
  - IP whitelist/blacklist
  - Custom firewall rules

- **WAF Integration**
  - SQL injection protection
  - XSS protection
  - Rate limiting
  - Bot detection
  - Custom rules

- **Backup & Restore**
  - Site backups
  - Database backups
  - Directory backups
  - Scheduled backups
  - Retention policies

- **Cron Job Management**
  - GUI cron editor
  - Job templates
  - Execution history
  - Manual job triggering

- **Docker Support**
  - Container management
  - Image management
  - Volume management
  - Network management
  - Docker Compose support

- **File Manager**
  - Web-based file browser
  - File editing with syntax highlighting
  - Compression/extraction
  - Path traversal protection

- **PHP Management**
  - Multi-version support
  - Extension management
  - php.ini configuration
  - PHP-FPM control

- **FTP Management**
  - User account management
  - Quota management
  - Connection logging

- **System Monitoring**
  - Real-time CPU/Memory/Disk stats
  - Process monitoring
  - Network interface details
  - Service status

- **Logging & Audit**
  - Access logs
  - Audit trail
  - Error logging
  - Security event logging

### Security
- Secure session cookies (HttpOnly, Secure, SameSite)
- CSRF protection
- Security headers (CSP, HSTS, X-Frame-Options)
- Input validation and sanitization
- bcrypt password hashing

### Known Limitations
- Let's Encrypt requires manual certbot setup
- WAF features require external daemon on port 8379
- Rate limiting uses in-memory store (Redis optional)
- Single server deployment only

---

## [Unreleased]

### Planned for 1.1.0
- Email notifications
- Dark mode theme
- Multi-language support

### Planned for 2.0.0
- Kubernetes integration
- Multi-server management
- AI threat detection
