"""
ApkayA Enterprise Control Panel - Two-Factor Authentication Module
TOTP (Time-based One-Time Password) and backup codes implementation

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import pyotp
import qrcode
import json
import secrets
import io
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple


class TwoFactorAuth:
    """Two-factor authentication system with TOTP support"""
    
    def __init__(self, db_file='data/2fa.json'):
        """Initialize 2FA manager"""
        self.db_file = Path(db_file)
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        
        if not self.db_file.exists():
            self._write_2fa({})
        
        # Configuration
        self.backup_codes_count = 10
        self.totp_window = 1  # Allow 1 step before/after for clock drift
    
    # ===== Setup 2FA =====
    
    def generate_secret(self, user_id: str, name: str = None) -> dict:
        """Generate TOTP secret for user"""
        # Generate new secret
        secret = pyotp.random_base32()
        
        # User name for QR code
        user_name = f"ApkayaPanel-{user_id}"
        
        # Create TOTP object
        totp = pyotp.TOTP(secret)
        
        # Generate provisioning URI for QR code
        provisioning_uri = totp.provisioning_uri(
            name=user_name,
            issuer_name='ApkayA Enterprise'
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        qr_code_base64 = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
        
        # Generate backup codes
        backup_codes = self._generate_backup_codes(self.backup_codes_count)
        
        return {
            'success': True,
            'secret': secret,
            'provisioning_uri': provisioning_uri,
            'qr_code': f'data:image/png;base64,{qr_code_base64}',
            'backup_codes': backup_codes,
            'message': 'Scan QR code with authenticator app'
        }
    
    def enable_2fa(self, user_id: str, secret: str, verification_code: str, backup_codes: list) -> dict:
        """Enable 2FA for user"""
        # Verify code
        if not self._verify_code(secret, verification_code):
            return {'success': False, 'message': 'Invalid verification code'}
        
        twofa = self._read_2fa()
        
        if user_id in twofa:
            return {'success': False, 'message': 'User already has 2FA enabled'}
        
        # Save 2FA data
        twofa[user_id] = {
            'enabled': True,
            'secret': secret,
            'backup_codes': self._hash_backup_codes(backup_codes),
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'recovery_codes_used': []
        }
        
        self._write_2fa(twofa)
        
        return {
            'success': True,
            'message': '2FA enabled successfully',
            'backup_codes': backup_codes
        }
    
    def disable_2fa(self, user_id: str, password_verification: bool = True) -> dict:
        """Disable 2FA for user"""
        twofa = self._read_2fa()
        
        if user_id not in twofa:
            return {'success': False, 'message': 'User does not have 2FA enabled'}
        
        del twofa[user_id]
        self._write_2fa(twofa)
        
        return {'success': True, 'message': '2FA disabled successfully'}
    
    def is_2fa_enabled(self, user_id: str) -> bool:
        """Check if user has 2FA enabled"""
        twofa = self._read_2fa()
        return user_id in twofa and twofa[user_id].get('enabled', False)
    
    # ===== Verification =====
    
    def verify_code(self, user_id: str, code: str) -> Tuple[bool, str]:
        """Verify TOTP code"""
        twofa = self._read_2fa()
        
        if user_id not in twofa:
            return False, 'User does not have 2FA enabled'
        
        user_2fa = twofa[user_id]
        secret = user_2fa['secret']
        
        # Verify code with time window
        if self._verify_code(secret, code, window=self.totp_window):
            return True, 'Code verified successfully'
        
        return False, 'Invalid code'
    
    def verify_backup_code(self, user_id: str, code: str) -> Tuple[bool, str]:
        """Verify backup code"""
        twofa = self._read_2fa()
        
        if user_id not in twofa:
            return False, 'User does not have 2FA enabled'
        
        user_2fa = twofa[user_id]
        backup_codes = user_2fa.get('backup_codes', [])
        used_codes = user_2fa.get('recovery_codes_used', [])
        
        # Check if code exists and hasn't been used
        for stored_hash in backup_codes:
            if self._verify_backup_code(code, stored_hash) and code not in used_codes:
                # Mark code as used
                user_2fa['recovery_codes_used'].append(code)
                user_2fa['updated_at'] = datetime.now().isoformat()
                twofa[user_id] = user_2fa
                self._write_2fa(twofa)
                
                return True, 'Backup code verified'
        
        return False, 'Invalid or already used backup code'
    
    def get_remaining_backup_codes(self, user_id: str) -> int:
        """Get number of remaining backup codes"""
        twofa = self._read_2fa()
        
        if user_id not in twofa:
            return 0
        
        user_2fa = twofa[user_id]
        total_codes = len(user_2fa.get('backup_codes', []))
        used_codes = len(user_2fa.get('recovery_codes_used', []))
        
        return total_codes - used_codes
    
    # ===== Backup Codes Management =====
    
    def regenerate_backup_codes(self, user_id: str) -> dict:
        """Regenerate backup codes"""
        twofa = self._read_2fa()
        
        if user_id not in twofa:
            return {'success': False, 'message': 'User does not have 2FA enabled'}
        
        # Generate new codes
        new_codes = self._generate_backup_codes(self.backup_codes_count)
        
        # Update user's 2FA
        user_2fa = twofa[user_id]
        user_2fa['backup_codes'] = self._hash_backup_codes(new_codes)
        user_2fa['recovery_codes_used'] = []
        user_2fa['updated_at'] = datetime.now().isoformat()
        twofa[user_id] = user_2fa
        self._write_2fa(twofa)
        
        return {
            'success': True,
            'message': 'Backup codes regenerated',
            'backup_codes': new_codes
        }
    
    def get_backup_codes_status(self, user_id: str) -> dict:
        """Get backup codes status"""
        twofa = self._read_2fa()
        
        if user_id not in twofa:
            return {'success': False, 'message': 'User does not have 2FA enabled'}
        
        user_2fa = twofa[user_id]
        total = len(user_2fa.get('backup_codes', []))
        used = len(user_2fa.get('recovery_codes_used', []))
        remaining = total - used
        
        return {
            'success': True,
            'total_codes': total,
            'used_codes': used,
            'remaining_codes': remaining,
            'percentage_used': round((used / total * 100) if total > 0 else 0, 1)
        }
    
    # ===== Account Recovery =====
    
    def generate_recovery_email(self, user_id: str) -> dict:
        """Generate recovery codes for email"""
        twofa = self._read_2fa()
        
        if user_id not in twofa:
            return {'success': False, 'message': 'User does not have 2FA enabled'}
        
        # Generate new recovery codes
        recovery_codes = self._generate_backup_codes(5)  # Fewer codes for email
        
        return {
            'success': True,
            'message': 'Recovery codes generated',
            'codes': recovery_codes,
            'note': 'Send these codes to user email'
        }
    
    # ===== Helper Methods =====
    
    @staticmethod
    def _verify_code(secret: str, code: str, window: int = 1) -> bool:
        """Verify TOTP code with time window"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=window)
        except Exception:
            return False
    
    @staticmethod
    def _generate_backup_codes(count: int = 10) -> list:
        """Generate backup codes"""
        codes = []
        for _ in range(count):
            # Generate 8-character codes: XXXX-XXXX
            code = secrets.token_hex(4)  # 8 hex chars
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        return codes
    
    @staticmethod
    def _hash_backup_codes(codes: list) -> list:
        """Hash backup codes for storage"""
        import hashlib
        hashed = []
        for code in codes:
            # Remove hyphens for hashing
            clean_code = code.replace('-', '')
            hash_val = hashlib.sha256(clean_code.encode()).hexdigest()
            hashed.append(hash_val)
        return hashed
    
    @staticmethod
    def _verify_backup_code(code: str, hash_val: str) -> bool:
        """Verify backup code against hash"""
        import hashlib
        clean_code = code.replace('-', '')
        computed_hash = hashlib.sha256(clean_code.encode()).hexdigest()
        return computed_hash == hash_val
    
    # ===== File Operations =====
    
    def _read_2fa(self) -> dict:
        """Read 2FA database"""
        try:
            if self.db_file.exists():
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _write_2fa(self, data: dict) -> None:
        """Write 2FA database"""
        try:
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to write 2FA: {e}")
    
    # ===== Admin Functions =====
    
    def force_disable_2fa(self, user_id: str) -> dict:
        """Admin function: Force disable 2FA"""
        twofa = self._read_2fa()
        
        if user_id not in twofa:
            return {'success': False, 'message': 'User does not have 2FA enabled'}
        
        del twofa[user_id]
        self._write_2fa(twofa)
        
        return {'success': True, 'message': f'2FA disabled for user {user_id}'}
    
    def get_2fa_stats(self) -> dict:
        """Get 2FA statistics"""
        twofa = self._read_2fa()
        
        total_users_with_2fa = len(twofa)
        users_with_low_backup_codes = 0
        
        for user_data in twofa.values():
            total_codes = len(user_data.get('backup_codes', []))
            used_codes = len(user_data.get('recovery_codes_used', []))
            remaining = total_codes - used_codes
            
            if remaining < 3:  # Warning threshold
                users_with_low_backup_codes += 1
        
        return {
            'total_users_with_2fa': total_users_with_2fa,
            'users_with_low_backup_codes': users_with_low_backup_codes,
            'warning_message': f'{users_with_low_backup_codes} users need to regenerate backup codes'
        }


# Global 2FA manager instance
twofa_manager = TwoFactorAuth()
