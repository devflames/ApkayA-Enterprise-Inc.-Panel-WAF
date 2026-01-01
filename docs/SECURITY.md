# Security Best Practices

> **Developed by Albert Camings** | Full Stack Developer

## Overview

ApkayA Enterprise Control Panel implements multiple layers of security to protect your server management interface.

---

## Authentication Security

### Password Requirements
- Minimum 8 characters
- Must contain uppercase, lowercase, numbers, and special characters
- Passwords hashed with bcrypt (work factor 12)
- Account lockout after 5 failed attempts (15-minute lockout)

### Two-Factor Authentication (2FA)
- TOTP-based (Google Authenticator compatible)
- 8 backup codes generated on setup
- Recommended for all admin accounts

### Session Security
- 24-hour session timeout
- Secure cookies with `HttpOnly`, `Secure`, `SameSite=Strict`
- Session tokens regenerated on privilege changes

---

## API Security

### Rate Limiting
Default limits per role:
| Role | Requests/Minute | Requests/Hour |
|------|-----------------|---------------|
| Admin | 1000 | 100,000 |
| Operator | 500 | 50,000 |
| User | 100 | 10,000 |
| Guest | 10 | 1,000 |

### API Key Management
- Keys expire after 90 days by default
- HMAC-SHA256 request signing supported
- IP whitelist/blacklist per key

---

## HTTP Security Headers

All responses include:
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com
Referrer-Policy: strict-origin-when-cross-origin
```

---

## Input Validation

All inputs are validated and sanitized:
- Path traversal prevention (`..` blocked)
- SQL injection protection (parameterized queries)
- XSS prevention (HTML escaping)
- File upload restrictions (type/size limits)

---

## Production Hardening Checklist

### Required
- [ ] Change default port from 2323
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Set strong admin password
- [ ] Enable 2FA for all admin accounts
- [ ] Configure firewall to restrict panel access

### Recommended
- [ ] Use reverse proxy (nginx) in front of panel
- [ ] Enable fail2ban for brute-force protection
- [ ] Set up log monitoring and alerts
- [ ] Regular security updates
- [ ] Backup encryption keys securely

---

## Reporting Security Issues

If you discover a security vulnerability, please:

1. **Do NOT** open a public GitHub issue
2. Email: security@apkaya.com
3. Include detailed reproduction steps
4. Allow 90 days for patch before disclosure

We appreciate responsible disclosure.
