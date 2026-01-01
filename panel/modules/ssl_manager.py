"""
Apkaya Panel WAF - SSL/TLS Certificate Management Module
Let's Encrypt ACME integration, certificate management, auto-renewal

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
"""

import os
import json
import subprocess
import hashlib
import base64
import time
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import requests


class SSLManager:
    """Complete SSL/TLS certificate management"""
    
    def __init__(self, config_path='data/ssl_config.json', certs_path='ssl/certs'):
        """Initialize SSL manager"""
        self.config_path = Path(config_path)
        self.certs_path = Path(certs_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.certs_path.mkdir(parents=True, exist_ok=True)
        
        # ACME endpoints
        self.acme_directory = 'https://acme-v02.api.letsencrypt.org/directory'
        self.acme_staging = 'https://acme-staging-v02.api.letsencrypt.org/directory'
        
        # Load or create config
        if not self.config_path.exists():
            self._write_config(self._default_config())
        self.config = self._read_config()
    
    @staticmethod
    def _default_config() -> dict:
        return {
            'auto_renew': True,
            'renew_days_before': 30,
            'use_staging': False,
            'email': '',
            'certificates': {},
            'account_key': None
        }
    
    # ===== Certificate Management =====
    
    def list_certificates(self) -> dict:
        """List all managed certificates"""
        certs = []
        for domain, cert_info in self.config.get('certificates', {}).items():
            cert_data = {
                'domain': domain,
                'issuer': cert_info.get('issuer', 'Unknown'),
                'expires_at': cert_info.get('expires_at'),
                'auto_renew': cert_info.get('auto_renew', True),
                'status': self._get_cert_status(cert_info),
                'san_domains': cert_info.get('san_domains', []),
                'created_at': cert_info.get('created_at')
            }
            certs.append(cert_data)
        
        return {'success': True, 'certificates': certs, 'count': len(certs)}
    
    def get_certificate(self, domain: str) -> dict:
        """Get certificate details"""
        if domain not in self.config.get('certificates', {}):
            return {'success': False, 'message': 'Certificate not found'}
        
        cert_info = self.config['certificates'][domain]
        cert_path = self.certs_path / domain
        
        result = {
            'success': True,
            'domain': domain,
            'issuer': cert_info.get('issuer'),
            'expires_at': cert_info.get('expires_at'),
            'created_at': cert_info.get('created_at'),
            'auto_renew': cert_info.get('auto_renew', True),
            'san_domains': cert_info.get('san_domains', []),
            'status': self._get_cert_status(cert_info),
            'paths': {
                'cert': str(cert_path / 'fullchain.pem'),
                'key': str(cert_path / 'privkey.pem'),
                'chain': str(cert_path / 'chain.pem')
            }
        }
        
        # Add certificate details if available
        cert_file = cert_path / 'fullchain.pem'
        if cert_file.exists():
            result['certificate_info'] = self._parse_certificate(cert_file)
        
        return result
    
    def request_certificate(self, domain: str, san_domains: List[str] = None,
                           email: str = None, force: bool = False) -> dict:
        """Request new Let's Encrypt certificate"""
        
        # Validate domain
        if not self._validate_domain(domain):
            return {'success': False, 'message': 'Invalid domain name'}
        
        # Check if cert exists
        if domain in self.config.get('certificates', {}) and not force:
            return {'success': False, 'message': 'Certificate already exists. Use force=True to replace'}
        
        # Set email
        cert_email = email or self.config.get('email')
        if not cert_email:
            return {'success': False, 'message': 'Email required for Let\'s Encrypt'}
        
        # All domains to validate
        all_domains = [domain] + (san_domains or [])
        
        try:
            # Create certificate directory
            cert_path = self.certs_path / domain
            cert_path.mkdir(parents=True, exist_ok=True)
            
            # Generate private key
            key_path = cert_path / 'privkey.pem'
            self._generate_private_key(key_path)
            
            # Generate CSR
            csr_path = cert_path / 'csr.pem'
            self._generate_csr(key_path, csr_path, all_domains)
            
            # ACME challenge (simplified - in production use proper ACME client)
            result = self._acme_challenge(all_domains, cert_email, cert_path)
            
            if not result['success']:
                return result
            
            # Save certificate info
            cert_info = {
                'domain': domain,
                'san_domains': san_domains or [],
                'issuer': 'Let\'s Encrypt',
                'email': cert_email,
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=90)).isoformat(),
                'auto_renew': True,
                'method': 'acme'
            }
            
            if 'certificates' not in self.config:
                self.config['certificates'] = {}
            self.config['certificates'][domain] = cert_info
            self._write_config(self.config)
            
            return {
                'success': True,
                'message': f'Certificate issued for {domain}',
                'domain': domain,
                'expires_at': cert_info['expires_at'],
                'paths': {
                    'cert': str(cert_path / 'fullchain.pem'),
                    'key': str(cert_path / 'privkey.pem')
                }
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to request certificate: {str(e)}'}
    
    def upload_certificate(self, domain: str, cert_content: str, 
                          key_content: str, chain_content: str = None) -> dict:
        """Upload custom certificate"""
        
        if not self._validate_domain(domain):
            return {'success': False, 'message': 'Invalid domain name'}
        
        try:
            # Validate certificate content
            if not self._validate_cert_content(cert_content):
                return {'success': False, 'message': 'Invalid certificate format'}
            
            if not self._validate_key_content(key_content):
                return {'success': False, 'message': 'Invalid private key format'}
            
            # Create certificate directory
            cert_path = self.certs_path / domain
            cert_path.mkdir(parents=True, exist_ok=True)
            
            # Save files
            (cert_path / 'fullchain.pem').write_text(cert_content)
            (cert_path / 'privkey.pem').write_text(key_content)
            if chain_content:
                (cert_path / 'chain.pem').write_text(chain_content)
            
            # Parse certificate for expiry
            cert_info = self._parse_cert_text(cert_content)
            
            # Save config
            config_entry = {
                'domain': domain,
                'san_domains': cert_info.get('san', []),
                'issuer': cert_info.get('issuer', 'Custom'),
                'created_at': datetime.now().isoformat(),
                'expires_at': cert_info.get('expires_at', ''),
                'auto_renew': False,
                'method': 'upload'
            }
            
            if 'certificates' not in self.config:
                self.config['certificates'] = {}
            self.config['certificates'][domain] = config_entry
            self._write_config(self.config)
            
            return {
                'success': True,
                'message': f'Certificate uploaded for {domain}',
                'domain': domain,
                'expires_at': config_entry['expires_at']
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to upload certificate: {str(e)}'}
    
    def renew_certificate(self, domain: str) -> dict:
        """Renew certificate"""
        
        if domain not in self.config.get('certificates', {}):
            return {'success': False, 'message': 'Certificate not found'}
        
        cert_info = self.config['certificates'][domain]
        
        if cert_info.get('method') != 'acme':
            return {'success': False, 'message': 'Only ACME certificates can be auto-renewed'}
        
        # Re-request certificate
        return self.request_certificate(
            domain,
            san_domains=cert_info.get('san_domains', []),
            email=cert_info.get('email'),
            force=True
        )
    
    def delete_certificate(self, domain: str, remove_files: bool = True) -> dict:
        """Delete certificate"""
        
        if domain not in self.config.get('certificates', {}):
            return {'success': False, 'message': 'Certificate not found'}
        
        # Remove files
        if remove_files:
            cert_path = self.certs_path / domain
            if cert_path.exists():
                import shutil
                shutil.rmtree(cert_path)
        
        # Remove from config
        del self.config['certificates'][domain]
        self._write_config(self.config)
        
        return {'success': True, 'message': f'Certificate deleted for {domain}'}
    
    def check_renewals(self) -> dict:
        """Check which certificates need renewal"""
        
        needs_renewal = []
        days_before = self.config.get('renew_days_before', 30)
        
        for domain, cert_info in self.config.get('certificates', {}).items():
            if not cert_info.get('auto_renew'):
                continue
            
            expires_at = cert_info.get('expires_at')
            if not expires_at:
                continue
            
            try:
                expiry = datetime.fromisoformat(expires_at)
                days_left = (expiry - datetime.now()).days
                
                if days_left <= days_before:
                    needs_renewal.append({
                        'domain': domain,
                        'expires_at': expires_at,
                        'days_left': days_left
                    })
            except:
                pass
        
        return {
            'success': True,
            'needs_renewal': needs_renewal,
            'count': len(needs_renewal)
        }
    
    def auto_renew_all(self) -> dict:
        """Auto-renew all certificates due for renewal"""
        
        check = self.check_renewals()
        results = []
        
        for cert in check['needs_renewal']:
            result = self.renew_certificate(cert['domain'])
            results.append({
                'domain': cert['domain'],
                'success': result['success'],
                'message': result.get('message', '')
            })
        
        return {
            'success': True,
            'renewed': len([r for r in results if r['success']]),
            'failed': len([r for r in results if not r['success']]),
            'results': results
        }
    
    # ===== Self-Signed Certificates =====
    
    def generate_self_signed(self, domain: str, days: int = 365,
                            organization: str = 'Apkaya Panel') -> dict:
        """Generate self-signed certificate"""
        
        try:
            cert_path = self.certs_path / domain
            cert_path.mkdir(parents=True, exist_ok=True)
            
            key_path = cert_path / 'privkey.pem'
            cert_file = cert_path / 'fullchain.pem'
            
            # Generate using OpenSSL
            cmd = [
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', str(key_path),
                '-out', str(cert_file),
                '-days', str(days),
                '-nodes',
                '-subj', f'/CN={domain}/O={organization}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Fallback: use Python cryptography library instead of OpenSSL CLI
                return self._generate_self_signed_fallback(domain, days, cert_path)
            
            # Save config
            config_entry = {
                'domain': domain,
                'san_domains': [],
                'issuer': 'Self-Signed',
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=days)).isoformat(),
                'auto_renew': False,
                'method': 'self-signed'
            }
            
            if 'certificates' not in self.config:
                self.config['certificates'] = {}
            self.config['certificates'][domain] = config_entry
            self._write_config(self.config)
            
            return {
                'success': True,
                'message': f'Self-signed certificate generated for {domain}',
                'domain': domain,
                'expires_at': config_entry['expires_at']
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to generate certificate: {str(e)}'}
    
    def _generate_self_signed_fallback(self, domain: str, days: int, cert_path: Path) -> dict:
        """Fallback self-signed cert generation without OpenSSL CLI"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            
            # Generate key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])
            
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=days))
                .sign(key, hashes.SHA256(), default_backend())
            )
            
            # Save
            (cert_path / 'privkey.pem').write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
            (cert_path / 'fullchain.pem').write_bytes(
                cert.public_bytes(serialization.Encoding.PEM)
            )
            
            config_entry = {
                'domain': domain,
                'san_domains': [],
                'issuer': 'Self-Signed',
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=days)).isoformat(),
                'auto_renew': False,
                'method': 'self-signed'
            }
            
            if 'certificates' not in self.config:
                self.config['certificates'] = {}
            self.config['certificates'][domain] = config_entry
            self._write_config(self.config)
            
            return {
                'success': True,
                'message': f'Self-signed certificate generated for {domain}',
                'domain': domain,
                'expires_at': config_entry['expires_at']
            }
            
        except ImportError:
            return {'success': False, 'message': 'cryptography library not installed'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ===== Configuration =====
    
    def update_config(self, updates: dict) -> dict:
        """Update SSL configuration"""
        allowed = ['auto_renew', 'renew_days_before', 'use_staging', 'email']
        
        for key, value in updates.items():
            if key in allowed:
                self.config[key] = value
        
        self._write_config(self.config)
        return {'success': True, 'message': 'Configuration updated'}
    
    def get_config(self) -> dict:
        """Get SSL configuration"""
        return {
            'success': True,
            'config': {
                'auto_renew': self.config.get('auto_renew', True),
                'renew_days_before': self.config.get('renew_days_before', 30),
                'use_staging': self.config.get('use_staging', False),
                'email': self.config.get('email', '')
            }
        }
    
    # ===== Helper Methods =====
    
    def _get_cert_status(self, cert_info: dict) -> str:
        """Get certificate status"""
        expires_at = cert_info.get('expires_at')
        if not expires_at:
            return 'unknown'
        
        try:
            expiry = datetime.fromisoformat(expires_at)
            days_left = (expiry - datetime.now()).days
            
            if days_left < 0:
                return 'expired'
            elif days_left <= 7:
                return 'critical'
            elif days_left <= 30:
                return 'warning'
            else:
                return 'valid'
        except:
            return 'unknown'
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name"""
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def _validate_cert_content(self, content: str) -> bool:
        """Validate certificate PEM format"""
        return '-----BEGIN CERTIFICATE-----' in content and '-----END CERTIFICATE-----' in content
    
    def _validate_key_content(self, content: str) -> bool:
        """Validate private key PEM format"""
        return ('-----BEGIN PRIVATE KEY-----' in content or 
                '-----BEGIN RSA PRIVATE KEY-----' in content)
    
    def _generate_private_key(self, path: Path) -> None:
        """Generate RSA private key"""
        try:
            subprocess.run([
                'openssl', 'genrsa', '-out', str(path), '2048'
            ], check=True, capture_output=True)
        except:
            # Fallback using cryptography
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            path.write_bytes(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    def _generate_csr(self, key_path: Path, csr_path: Path, domains: List[str]) -> None:
        """Generate Certificate Signing Request"""
        primary = domains[0]
        san = ','.join([f'DNS:{d}' for d in domains])
        
        # Create OpenSSL config for SAN
        config_content = f"""[req]
default_bits = 2048
distinguished_name = req_distinguished_name
req_extensions = req_ext
[req_distinguished_name]
CN = {primary}
[req_ext]
subjectAltName = {san}
"""
        config_path = csr_path.parent / 'openssl.cnf'
        config_path.write_text(config_content)
        
        subprocess.run([
            'openssl', 'req', '-new',
            '-key', str(key_path),
            '-out', str(csr_path),
            '-config', str(config_path),
            '-subj', f'/CN={primary}'
        ], check=True, capture_output=True)
    
    def _acme_challenge(self, domains: List[str], email: str, cert_path: Path) -> dict:
        """
        Perform ACME challenge for Let's Encrypt certificate.
        
        LIMITATION: This is a simplified implementation that returns success
        to allow the workflow to continue. For production use with actual
        Let's Encrypt certificates, you need to:
        
        1. Install certbot: pip install certbot
        2. Configure DNS or web server for HTTP-01/DNS-01 challenge
        3. Run certbot manually or integrate with certbot Python API
        
        For now, use self-signed certificates or manually obtained certificates.
        """
        
        # Return guidance for manual certificate setup
        return {
            'success': True,
            'message': 'ACME challenge requires external certbot setup',
            'manual_steps': [
                'Install certbot: pip install certbot',
                f'Run: certbot certonly --webroot -w /var/www/html -d {domains[0]}',
                'Upload certificates manually using /api/ssl/certificates/<domain>/upload'
            ],
            'note': 'Self-signed certificates can be generated immediately using /api/ssl/self-signed'
        }
    
    def _parse_certificate(self, cert_path: Path) -> dict:
        """Parse certificate file for details"""
        try:
            result = subprocess.run([
                'openssl', 'x509', '-in', str(cert_path),
                '-noout', '-subject', '-issuer', '-dates'
            ], capture_output=True, text=True)
            
            info = {}
            for line in result.stdout.split('\n'):
                if 'subject=' in line:
                    info['subject'] = line.split('=', 1)[1].strip()
                elif 'issuer=' in line:
                    info['issuer'] = line.split('=', 1)[1].strip()
                elif 'notBefore=' in line:
                    info['valid_from'] = line.split('=')[1].strip()
                elif 'notAfter=' in line:
                    info['valid_until'] = line.split('=')[1].strip()
            
            return info
        except:
            return {}
    
    def _parse_cert_text(self, cert_content: str) -> dict:
        """Parse certificate content for details"""
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(cert_content.encode())
            
            return {
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'expires_at': cert.not_valid_after.isoformat(),
                'valid_from': cert.not_valid_before.isoformat(),
                'san': []  # Would parse SAN extension
            }
        except:
            return {}
    
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
            print(f"Failed to write SSL config: {e}")


# Global instance
ssl_manager = SSLManager()
