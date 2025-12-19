"""
Sentra TOTP Generator

Implements Time-based One-Time Password algorithm (RFC 6238) for 2FA codes.
"""

import time
import pyotp
from typing import Optional
from src.database_manager import DatabaseManager
from urllib.parse import urlparse, parse_qs

class RateLimitError(Exception):
    """Raised when TOTP verification attempts exceed the limit."""
    pass

class TOTPGenerator:
    """
    TOTP generator compliant with RFC 6238
    """

    def __init__(self, db_path: str = "data/vault.db"):
        # Rate Limiting State
        self.db = DatabaseManager(db_path)
        # Policy: Max 5 attempts every 30 seconds
        self.RATE_LIMIT_COUNT = 5
        self.RATE_LIMIT_WINDOW = 30.0
        
        # Internal key for tracking (does not need to be persisted)
        self._tracking_salt = b"sentra-totp-tracking"

    def _check_rate_limit(self, entry_id: str) -> bool:
        """
        Check if attempts for this secret exceed the policy.
        
        Security:
        - Uses crypto_engine.compute_hmac to create a deterministic ID.
        - Prevents storing raw secrets in the rate-limit memory.
        """
        now = int(time.time())
        cutoff = now - int(self.RATE_LIMIT_WINDOW)

        count = self.db.count_recent_totp_attempts(
            secret_id=entry_id,
            since_ts=cutoff
        )

        return count < self.RATE_LIMIT_COUNT

    @staticmethod
    def generate_totp( secret: str, time_step: int = 30) -> str:
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
        except (TypeError, ValueError) as e:
            raise ValueError("Invalid TOTP secret. Must be a valid Base32 string.") from e

    @staticmethod
    def get_time_remaining( time_step: int = 30) -> int:
        """
        Get seconds remaining until the current TOTP code expires.

        Args:
            time_step: TOTP time-step in seconds.

        Returns:
            Seconds remaining (0 - time_step).
        """
        current_time = int(time.time())
        return time_step - (current_time % time_step)

    def is_valid_totp(
        self,
        entry_id: str,
        secret: str,
        code: str,
        window: int = 1
    ) -> bool:
        now = int(time.time())

        # 1. Check limit (do NOT record yet)
        cutoff = now - int(self.RATE_LIMIT_WINDOW)
        count = self.db.count_recent_totp_attempts(entry_id, cutoff)

        if count >= self.RATE_LIMIT_COUNT:
            raise RateLimitError(
                f"Too many failed attempts. Please wait {int(self.RATE_LIMIT_WINDOW)}s."
            )

        # 2. Verify TOTP
        try:
            totp = pyotp.TOTP(secret)
            ok = totp.verify(code, valid_window=window)
        except Exception:
            ok = False

        # 3. Record ONLY failed attempts
        if not ok:
            self.db.record_totp_attempt(entry_id, now)

        return ok

    @staticmethod
    def parse_totp_uri( uri: str) -> Optional[str]:
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

    @staticmethod
    def generate_totp_uri( secret: str, issuer: str, account: str) -> str:
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