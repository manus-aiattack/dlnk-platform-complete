"""
Security Hardening Module
Implements essential security measures for the Manus AI platform
"""

import os
import jwt
import bcrypt
import secrets
import hashlib
import logging
import time
import html
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Any
from dataclasses import dataclass
from core.logger import log


@dataclass
class SecurityConfig:
    """Security configuration data structure"""
    jwt_secret: str
    jwt_expires_in: str = '15m'
    bcrypt_rounds: int = 12
    rate_limit_window_ms: int = 900000  # 15 minutes
    rate_limit_max_requests: int = 100
    session_timeout_minutes: int = 30
    max_login_attempts: int = 5
    account_lockout_minutes: int = 15


class SecurityError(Exception):
    """Custom security exception"""
    pass


class SecurityManager:
    """Security management system"""

    def __init__(self, config: SecurityConfig = None):
        """Initialize SecurityManager with configuration"""

        # Validate JWT secret is not hardcoded and comes from environment
        jwt_secret = config.jwt_secret if config else os.getenv('JWT_SECRET_KEY')
        if not jwt_secret or jwt_secret == 'hardcoded_secret':
            raise SecurityError('JWT_SECRET_KEY environment variable is required and must not be hardcoded')

        self.config = config or SecurityConfig(jwt_secret=jwt_secret)
        self.active_sessions: Dict[str, 'UserSession'] = {}
        self.failed_login_attempts: Dict[str, int] = {}
        self.blocked_ips: set = set()

        log.info("SecurityManager initialized successfully")
        self._start_session_cleanup()

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt with salt"""
        if not password:
            raise ValueError("Password cannot be empty")

        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=self.config.bcrypt_rounds)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

        return hashed.decode('utf-8')

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hashed value"""
        if not password or not hashed:
            return False

        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:
            log.error(f"Password verification error: {e}")
            return False

    def generate_token(self, payload: Dict[str, Any]) -> str:
        """Generate JWT token with expiration"""
        if not payload:
            raise ValueError("Payload cannot be empty")

        # Add expiration time
        now = datetime.utcnow()
        expires_at = now + self._parse_jwt_expires_in()

        token_payload = {
            **payload,
            'iat': now,
            'exp': expires_at
        }

        try:
            token = jwt.encode(token_payload, self.config.jwt_secret, algorithm='HS256')
            return token
        except Exception as e:
            log.error(f"Token generation error: {e}")
            raise SecurityError(f"Failed to generate token: {e}")

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        if not token:
            raise ValueError("Token cannot be empty")

        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=['HS256']
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise SecurityError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise SecurityError(f"Invalid token: {e}")

    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> str:
        """Create user session"""
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=self.config.session_timeout_minutes)

        session = UserSession(
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=now,
            last_activity=now,
            expires_at=expires_at,
            is_active=True
        )

        self.active_sessions[session_id] = session
        log.info(f"Session created for user {user_id}")

        return session_id

    def validate_session(self, session_id: str, ip_address: str) -> bool:
        """Validate session with IP address checking"""
        session = self.active_sessions.get(session_id)

        if not session:
            return False

        # Check if session is expired
        if session.expires_at < datetime.utcnow() or not session.is_active:
            self.active_sessions.pop(session_id, None)
            return False

        # Check IP address (basic session hijacking protection)
        if session.ip_address != ip_address:
            self.active_sessions.pop(session_id, None)
            log.warning(f"Session hijacking attempt detected for session {session_id}")
            return False

        # Update last activity
        session.last_activity = datetime.utcnow()
        return True

    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate user session"""
        session = self.active_sessions.pop(session_id, None)

        if session:
            session.is_active = False
            log.info(f"Session {session_id} invalidated")
            return True

        return False

    def record_failed_login(self, ip_address: str) -> int:
        """Record failed login attempt and check for IP blocking"""
        attempts = self.failed_login_attempts.get(ip_address, 0) + 1
        self.failed_login_attempts[ip_address] = attempts

        # Block IP after max attempts
        if attempts >= self.config.max_login_attempts:
            self.blocked_ips.add(ip_address)
            log.warning(f"IP {ip_address} blocked due to {attempts} failed login attempts")

            # Schedule unblock after lockout period
            def unblock_ip():
                import threading
                def unblock():
                    self.blocked_ips.discard(ip_address)
                    self.failed_login_attempts.pop(ip_address, None)
                timer = threading.Timer(self.config.account_lockout_minutes * 60, unblock)
                timer.start()

            unblock_ip()

        return attempts

    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP address is blocked"""
        return ip_address in self.blocked_ips

    def reset_failed_attempts(self, ip_address: str):
        """Reset failed login attempts for IP"""
        self.failed_login_attempts.pop(ip_address, None)
        self.blocked_ips.discard(ip_address)

    def sanitize_input(self, input_str: str) -> str:
        """Sanitize user input to prevent XSS and injection"""
        if not input_str:
            return ""

        # Remove dangerous HTML tags and attributes by escaping
        sanitized = html.escape(input_str)

        # Remove javascript: protocol
        sanitized = sanitized.replace('javascript:', '')

        # Trim whitespace
        return sanitized.strip()

    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        if not email or len(email) > 254:  # RFC 5321 limit
            return False

        import re
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    def validate_password(self, password: str) -> Dict[str, Any]:
        """Validate password strength"""
        errors = []

        if len(password) < 8:
            errors.append('Password must be at least 8 characters long')

        if not any(c.isupper() for c in password):
            errors.append('Password must contain at least one uppercase letter')

        if not any(c.islower() for c in password):
            errors.append('Password must contain at least one lowercase letter')

        if not any(c.isdigit() for c in password):
            errors.append('Password must contain at least one number')

        if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            errors.append('Password must contain at least one special character')

        return {
            'is_valid': len(errors) == 0,
            'errors': errors
        }

    def encrypt_data(self, data: str) -> str:
        """Encrypt data using AES-256-GCM"""
        if not data:
            return ""

        try:
            import cryptography.fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            # Derive key from JWT secret
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'manus_security_salt',
                iterations=100000
            )
            key = kdf.derive(self.config.jwt_secret.encode())

            f = cryptography.fernet.Fernet(key)
            encrypted = f.encrypt(data.encode())
            return encrypted.decode()

        except Exception as e:
            log.error(f"Data encryption error: {e}")
            raise SecurityError(f"Failed to encrypt data: {e}")

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt AES-256-GCM encrypted data"""
        if not encrypted_data:
            return ""

        try:
            import cryptography.fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            # Derive key from JWT secret
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'manus_security_salt',
                iterations=100000
            )
            key = kdf.derive(self.config.jwt_secret.encode())

            f = cryptography.fernet.Fernet(key)
            decrypted = f.decrypt(encrypted_data.encode())
            return decrypted.decode()

        except Exception as e:
            log.error(f"Data decryption error: {e}")
            raise SecurityError(f"Failed to decrypt data: {e}")

    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics"""
        return {
            'total_sessions': len(self.active_sessions),
            'blocked_ips': list(self.blocked_ips),
            'failed_login_attempts': list(self.failed_login_attempts.items()),
            'active_sessions': [
                {
                    'user_id': session.user_id,
                    'session_id': session.session_id,
                    'ip_address': session.ip_address,
                    'last_activity': session.last_activity.isoformat(),
                    'is_active': session.is_active
                }
                for session in self.active_sessions.values()
            ]
        }

    def _parse_jwt_expires_in(self) -> timedelta:
        """Parse JWT expiration time string"""
        try:
            import re
            match = re.match(r'(\d+)([mhd])', self.config.jwt_expires_in)
            if not match:
                return timedelta(minutes=15)  # Default

            value, unit = match.groups()
            value = int(value)

            if unit == 'm':
                return timedelta(minutes=value)
            elif unit == 'h':
                return timedelta(hours=value)
            elif unit == 'd':
                return timedelta(days=value)
            else:
                return timedelta(minutes=15)

        except Exception:
            return timedelta(minutes=15)

    def _start_session_cleanup(self):
        """Start session cleanup background task"""
        import threading

        def cleanup_sessions():
            while True:
                try:
                    now = datetime.utcnow()
                    expired_sessions = []

                    for session_id, session in self.active_sessions.items():
                        if session.expires_at < now or not session.is_active:
                            expired_sessions.append(session_id)

                    for session_id in expired_sessions:
                        self.active_sessions.pop(session_id, None)

                    # Sleep for 1 hour
                    time.sleep(3600)
                except Exception as e:
                    log.error(f"Session cleanup error: {e}")
                    time.sleep(300)  # Retry after 5 minutes

        # Start cleanup thread
        cleanup_thread = threading.Thread(target=cleanup_sessions, daemon=True)
        cleanup_thread.start()


@dataclass
class UserSession:
    """User session data structure"""
    user_id: str
    session_id: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool


# Global security manager instance (can be imported by other modules)
_default_config = SecurityConfig(jwt_secret=os.getenv('JWT_SECRET_KEY', 'change_me_in_production'))
try:
    security_manager = SecurityManager(_default_config)
except SecurityError:
    log.warning("SecurityManager not initialized - JWT_SECRET_KEY not set")
    security_manager = None


def get_security_manager() -> Optional[SecurityManager]:
    """Get security manager instance"""
    return security_manager


if __name__ == '__main__':
    # Test security manager functionality
    print("Testing SecurityManager...")

    try:
        # Test password hashing
        hashed = security_manager.hash_password("test_password")
        print(f"Password hashed: {hashed[:20]}...")

        # Test password verification
        is_valid = security_manager.verify_password("test_password", hashed)
        print(f"Password verification: {is_valid}")

        # Test JWT token
        token = security_manager.generate_token({"user_id": "123", "role": "admin"})
        print(f"JWT token generated: {token[:30]}...")

        # Verify token
        payload = security_manager.verify_token(token)
        print(f"Token payload: {payload}")

        print("SecurityManager tests passed!")

    except Exception as e:
        print(f"SecurityManager test failed: {e}")