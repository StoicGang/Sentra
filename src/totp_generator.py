"""
Sentra TOTP Generator

Implements Time-based One-Time Password algorithm (RFC 6238) for 2FA codes.
"""

import time
import pyotp
from typing import Optional
from urllib.parse import urlparse, parse_qs

class TOTPGenerator:
    """
    TOTP generator compliant with RFC 6238
    """

    def generate_totp(self, secret: str, time_step: int = 30) -> str:
        """
        Generate a 6-digit TOTP code for the current time.

        Args:
            secret: Base32 encoded TOTP secret key.
            time_step: Validity duration of TOTP in seconds (default 30).

        Returns:
            6-digit TOTP string.
        """
        totp = pyotp.TOTP(secret, interval=time_step)
        return totp.now()

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
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=window)

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
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=account, issuer_name=issuer)
