import time
import pytest
import pyotp
from unittest.mock import patch, MagicMock

from src.totp_generator import (
    TOTPGenerator,
    RateLimitError,
)

# RFC 6238 test vector compatible Base32 secret
VALID_SECRET = "JBSWY3DPEHPK3PXP"  # "Hello!" in Base32

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tg():
    """Return generator instance with in-memory DB."""
    gen = TOTPGenerator(db_path=":memory:")
    # Initialize the database schema with the totp_attempts table
    gen.db.initialize_database()
    return gen
