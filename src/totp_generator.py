"""
Sentra TOTP Generator

Implements Time-based One-Time Password algorithm (RFC 6238) for 2FA codes.
"""

import time
import pyotp
from typing import Optional, Dict, Deque
from urllib.parse import urlparse, parse_qs
from src.crypto_engine import compute_hmac
from collections import deque

class RateLimitError(Exception):
    """Raised when TOTP verification attempts exceed the limit."""
    pass

class TOTPGenerator:
    """
    TOTP generator compliant with RFC 6238
    """

    def __init__(self):
        # Rate Limiting State
        # Dictionary mapping secure_id -> Deque of timestamps
        self._limits: Dict[str, Deque[float]] = {}
        
        # Policy: Max 5 attempts every 30 seconds
        self.RATE_LIMIT_COUNT = 5
        self.RATE_LIMIT_WINDOW = 30.0
        
        # Internal key for tracking (does not need to be persisted)
        self._tracking_salt = b"sentra-totp-tracking"

    def _check_rate_limit(self, secret: str) -> bool:
        """
        Check if attempts for this secret exceed the policy.
        
        Security:
        - Uses crypto_engine.compute_hmac to create a deterministic ID.
        - Prevents storing raw secrets in the rate-limit memory.
        """
        now = time.time()
        
        # FIX: Delegate hashing to crypto_engine
        # We use the secret as 'data' and a static salt as 'key' 
        # to generate a unique tracking ID.
        secret_id = compute_hmac(
            data=secret.encode('utf-8'), 
            key=self._tracking_salt
        ).hex()
        
        if secret_id not in self._limits:
            self._limits[secret_id] = deque()
            
        history = self._limits[secret_id]
        
        # 1. Prune attempts older than the window
        while history and history[0] < (now - self.RATE_LIMIT_WINDOW):
            history.popleft()
            
        # 2. Check if limit reached
        if len(history) >= self.RATE_LIMIT_COUNT:
            return False
            
        # 3. Record this attempt
        history.append(now)
        return True

    def generate_totp(self, secret: str, time_step: int = 30) -> str:
        """
        Generate a 6-digit TOTP code for the current time.

        Args:
            secret: Base32 encoded TOTP secret key.
            time_step: Validity duration of TOTP in seconds (default 30).

        Returns:
            6-digit TOTP string.
        """
        try:
            totp = pyotp.TOTP(secret, interval=time_step)
            return totp.now()
        except Exception:
            return "000000"

    def get_time_remaining(self, time_step: int = 30) -> int:
        """
        Get seconds remaining until the current TOTP code expires.

        Args:
            time_step: TOTP time-step in seconds.

        Returns:
            Seconds remaining (0 - time_step).
        """
        current_time = int(time.time())
        return time_step - (current_time % time_step)

    def is_valid_totp(self, secret: str, code: str, window: int = 1) -> bool:
        """
        Validate a TOTP code against the current time with a tolerance window.

        Args:
            secret: Base32 encoded TOTP secret key.
            code: User provided TOTP code string.
            window: Allowed window size for adjacent codes.

        Returns:
            True if code is valid within tolerance.
        """
        # 1. Enforce Rate Limit
        if not self._check_rate_limit(secret):
            raise RateLimitError(
                f"Too many failed attempts. Please wait {int(self.RATE_LIMIT_WINDOW)}s."
            )

        # 2. Verify Code
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=window)
        except Exception:
            return False

    def parse_totp_uri(self, uri: str) -> Optional[str]:
        """
        Parse an otpauth:// URI and extract the secret key.

        Args:
            uri: otpauth URI string.

        Returns:
            Extracted Base32 TOTP secret if valid, else None.
        """
        try:
            parsed = urlparse(uri)
            if parsed.scheme != "otpauth":
                return None
            params = parse_qs(parsed.query)
            return params.get("secret", [None])[0]
            
        except Exception:
            return None

    def generate_totp_uri(self, secret: str, issuer: str, account: str) -> str:
        """
        Generate an otpauth:// URI for provisioning.

        Args:
            secret: Base32 encoded secret.
            issuer: Service issuer name.
            account: Account name.

        Returns:
            otpauth URI string for QR code generation.
        """
        try:
            totp = pyotp.TOTP(secret)
            return totp.provisioning_uri(name=account, issuer_name=issuer)
        except Exception:
            return ""