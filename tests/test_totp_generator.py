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
def mock_hmac():
    """
    Mock the crypto engine's compute_hmac to return deterministic IDs
    based on the input data (secret).
    """
    with patch("src.totp_generator.compute_hmac") as mock:
        # Simple side effect: return the secret itself as bytes so unique secrets get unique IDs
        mock.side_effect = lambda data, key: data 
        yield mock

@pytest.fixture
def tg(mock_hmac):
    """Return generator instance with mocked crypto."""
    return TOTPGenerator()

# ---------------------------------------------------------------------------
# generate_totp
# ---------------------------------------------------------------------------

def test_generate_totp_returns_6_digit_code(tg):
    code = tg.generate_totp(VALID_SECRET)
    assert isinstance(code, str)
    assert code.isdigit()
    assert len(code) == 6

def test_generate_totp_deterministic_for_same_time(tg):
    with patch("time.time", return_value=1_700_000_000):
        c1 = tg.generate_totp(VALID_SECRET)
        c2 = tg.generate_totp(VALID_SECRET)
        assert c1 == c2

def test_generate_totp_rejects_invalid_secret(tg):
    with pytest.raises(ValueError):
        tg.generate_totp("not-base32!!!")

# ---------------------------------------------------------------------------
# get_time_remaining
# ---------------------------------------------------------------------------

def test_get_time_remaining_bounds(tg):
    with patch("time.time", return_value=100):
        remaining = tg.get_time_remaining(time_step=30)
        # 100 % 30 = 10. Remaining = 30 - 10 = 20.
        assert remaining == 20
        assert 0 < remaining <= 30

def test_get_time_remaining_exact_boundary(tg):
    with patch("time.time", return_value=90):
        # 90 % 30 = 0. Remaining = 30 - 0 = 30.
        assert tg.get_time_remaining(30) == 30

# ---------------------------------------------------------------------------
# _check_rate_limit (via is_valid_totp)
# ---------------------------------------------------------------------------

def test_rate_limit_allows_initial_attempts(tg):
    # Mock verify to avoid secondary time calls or crypto logic
    with patch("pyotp.TOTP.verify", return_value=False):
        for _ in range(tg.RATE_LIMIT_COUNT):
            # Should not raise exception
            tg.is_valid_totp(VALID_SECRET, "000000")

def test_rate_limit_blocks_after_threshold(tg):
    with patch("pyotp.TOTP.verify", return_value=False):
        # Exhaust attempts
        for _ in range(tg.RATE_LIMIT_COUNT):
            tg.is_valid_totp(VALID_SECRET, "000000")

        # Next one should fail
        with pytest.raises(RateLimitError):
            tg.is_valid_totp(VALID_SECRET, "000000")

def test_rate_limit_resets_after_window(tg):
    # We patch verify so it doesn't call time.time(), consuming our side_effect values
    with patch("pyotp.TOTP.verify", return_value=False):
        with patch("time.time", side_effect=[
            0, 1, 2, 3, 4,   # 5 rapid attempts within window
            100              # 6th attempt after window (30s)
        ]):
            # 1. Exhaust attempts
            for _ in range(tg.RATE_LIMIT_COUNT):
                tg.is_valid_totp(VALID_SECRET, "000000")

            # 2. Verify blockage (optional check, implicit in next step)
            
            # 3. After time window passes (t=100)
            # Should NOT raise RateLimitError
            assert tg.is_valid_totp(VALID_SECRET, "000000") is False

def test_rate_limit_tracks_secrets_independently(tg):
    """Ensure blocking one secret doesn't block another."""
    sec1 = "JBSWY3DPEHPK3PXP"
    sec2 = "IZTEEKK2I5JES5CD" # different base32
    
    with patch("pyotp.TOTP.verify", return_value=False):
        # Block sec1
        for _ in range(tg.RATE_LIMIT_COUNT):
            tg.is_valid_totp(sec1, "000000")
        
        with pytest.raises(RateLimitError):
            tg.is_valid_totp(sec1, "000000")
            
        # Sec2 should still be allowed
        assert tg.is_valid_totp(sec2, "000000") is False

# ---------------------------------------------------------------------------
# is_valid_totp
# ---------------------------------------------------------------------------

def test_is_valid_totp_accepts_correct_code(tg):
    # This passes because generate_totp and is_valid_totp both rely on
    # real system time (via datetime inside pyotp) unless explicitly mocked.
    # The patch here only satisfies the rate limiter.
    with patch("time.time", return_value=1_700_000_000):
        code = tg.generate_totp(VALID_SECRET)
        assert tg.is_valid_totp(VALID_SECRET, code) is True

def test_is_valid_totp_rejects_wrong_code(tg):
    assert tg.is_valid_totp(VALID_SECRET, "123456") is False

def test_is_valid_totp_invalid_secret_returns_false(tg):
    # Should return False safely, not crash
    assert tg.is_valid_totp("bad-secret", "123456") is False

def test_is_valid_totp_window_tolerance(tg):
    """
    Verify that the window parameter is correctly passed to pyotp.
    Mocking verify bypasses strict time synchronization issues.
    """
    with patch("pyotp.TOTP.verify") as mock_verify:
        mock_verify.return_value = True
        
        # Patch time just for rate limiting check
        with patch("time.time", return_value=1000):
            result = tg.is_valid_totp(VALID_SECRET, "123456", window=5)
        
        assert result is True
        mock_verify.assert_called_with("123456", valid_window=5)

# ---------------------------------------------------------------------------
# parse_totp_uri
# ---------------------------------------------------------------------------

def test_parse_totp_uri_valid(tg):
    uri = pyotp.TOTP(VALID_SECRET).provisioning_uri(
        name="user@example.com",
        issuer_name="Sentra"
    )
    secret = tg.parse_totp_uri(uri)
    assert secret == VALID_SECRET

def test_parse_totp_uri_invalid_scheme(tg):
    uri = "https://example.com?secret=ABC"
    assert tg.parse_totp_uri(uri) is None

def test_parse_totp_uri_missing_secret(tg):
    uri = "otpauth://totp/Service:User?issuer=Service"
    assert tg.parse_totp_uri(uri) is None

def test_parse_totp_uri_malformed(tg):
    assert tg.parse_totp_uri(":::") is None

# ---------------------------------------------------------------------------
# generate_totp_uri
# ---------------------------------------------------------------------------

def test_generate_totp_uri_success(tg):
    uri = tg.generate_totp_uri(
        secret=VALID_SECRET,
        issuer="Sentra",
        account="user@example.com"
    )
    assert uri.startswith("otpauth://totp/")
    assert "issuer=Sentra" in uri
    assert "user%40example.com" in uri

def test_generate_totp_uri_invalid_secret_returns_empty(tg):
    with patch("pyotp.TOTP", side_effect=Exception("boom")):
        uri = tg.generate_totp_uri(
            secret="bad",
            issuer="Sentra",
            account="user"
        )
        assert uri == ""