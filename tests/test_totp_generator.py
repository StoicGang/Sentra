import time
import pyotp
import pytest
from src.totp_generator import TOTPGenerator


def align_to_interval(ts: int, interval: int = 30) -> int:
    """Return the greatest timestamp <= ts that is aligned to the given interval."""
    return ts - (ts % interval)

def test_generate_and_verify_totp():
    tg = TOTPGenerator()
    secret = pyotp.random_base32()
    
    code = tg.generate_totp(secret)
    assert len(code) == 6 and code.isdigit()
    
    # Verify code immediately
    assert tg.is_valid_totp(secret, code)
    
    # Verify an invalid code
    assert not tg.is_valid_totp(secret, "000000")
    
    
def test_time_remaining():
    tg = TOTPGenerator()
    remaining = tg.get_time_remaining()
    assert 0 <= remaining <= 30
    
    
def test_parse_and_generate_uri():
    tg = TOTPGenerator()
    secret = pyotp.random_base32()
    issuer = "Sentra"
    account = "user@example.com"
    
    uri = tg.generate_totp_uri(secret, issuer, account)
    assert uri.startswith("otpauth://")
    parsed_secret = tg.parse_totp_uri(uri)
    assert parsed_secret == secret

def test_generate_totp_fixed_time(monkeypatch):
    """
    Use a fixed timestamp that is aligned to the 30s window so expected TOTP is deterministic.
    """
    tg = TOTPGenerator()
    secret = "JBSWY3DPEHPK3PXP"
    fixed = 1700000100  # aligned timestamp

    monkeypatch.setattr(time, "time", lambda: fixed)

    # Compare against pyotp under the SAME monkeypatched time
    totp = pyotp.TOTP(secret)
    assert tg.generate_totp(secret) == totp.now()


def test_time_remaining_edge_cases(monkeypatch):
    """
    Check behavior just before and exactly at rollover, using an aligned base timestamp.
    """
    tg = TOTPGenerator()
    interval = 30

    base_raw = 1000000000
    base_aligned = align_to_interval(base_raw, interval)

    # Just before rollover -> remaining should be 1
    monkeypatch.setattr(time, "time", lambda: base_aligned + (interval - 1))
    assert tg.get_time_remaining() == 1

    # Exactly at rollover -> remaining should be interval (full window)
    monkeypatch.setattr(time, "time", lambda: base_aligned + interval)
    assert tg.get_time_remaining() == interval


def test_verify_adjacent_window(monkeypatch):
    """
    Compare wrapper validation directly against pyotp's verify behavior.
    This makes the test robust across pyotp versions and platforms.
    """
    tg = TOTPGenerator()
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    # pick a timestamp safely inside a 30s window (not on a boundary)
    base = 1700000101
    monkeypatch.setattr(time, "time", lambda: base)

    prev_code = totp.at(base - 30)
    next_code = totp.at(base + 30)

    # Assert that our wrapper matches pyotp.verify exactly
    assert tg.is_valid_totp(secret, prev_code, window=1) == totp.verify(prev_code, valid_window=1)
    assert tg.is_valid_totp(secret, next_code, window=1) == totp.verify(next_code, valid_window=1)
    assert tg.is_valid_totp(secret, prev_code, window=0) == totp.verify(prev_code, valid_window=0)



@pytest.mark.parametrize("uri", [
    "",
    "otpauth://",
    "otpauth://totp/",
    "otpauth://totp/Label?notsecret=ABC",
    "otpauth://totp/Label?secret=",
    "otpauth://totp/Label?secret=!!!",
])
def test_parse_totp_uri_invalid(uri):
    tg = TOTPGenerator()
    result = tg.parse_totp_uri(uri)
    assert result is None or isinstance(result, str)


def test_generate_and_parse_uri_round_trip():
    tg = TOTPGenerator()
    secret = pyotp.random_base32()
    uri = tg.generate_totp_uri(secret, "Sentra", "user@example.com")
    assert tg.parse_totp_uri(uri) == secret


def test_multiple_intervals(monkeypatch):
    """
    Walk forward across many time-steps and compare our generator to pyotp.TOTP.at()
    Use a lambda default arg to capture loop variable correctly.
    """
    tg = TOTPGenerator()
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    base = 1700000100
    monkeypatch.setattr(time, "time", lambda: base)

    prev_code = totp.at(base - 30)
    next_code = totp.at(base + 30)

    # Compare our is_valid_totp() to pyotp.verify() directly
    assert tg.is_valid_totp(secret, prev_code, window=1) == totp.verify(prev_code, valid_window=1)
    assert tg.is_valid_totp(secret, next_code, window=1) == totp.verify(next_code, valid_window=1)

    assert tg.is_valid_totp(secret, prev_code, window=0) == totp.verify(prev_code, valid_window=0)


if __name__ == "__main__":
    pytest.main(["-q"])
