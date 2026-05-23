"""
Tests for Sentra Replay Cache
Verifies replay protection, TTL eviction, and capacity limits.
"""
import pytest
import time
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from src.security.replay_cache import ReplayCache, ReplayError

def test_nonce_duplicate_detection():
    cache = ReplayCache()
    nonce = b"unique-nonce-1"
    
    # First time: OK
    assert cache.check_and_add(nonce) is True
    
    # Second time: ReplayError
    with pytest.raises(ReplayError):
        cache.check_and_add(nonce)

def test_nonce_expiration():
    # Cache with 1 second TTL
    cache = ReplayCache(ttl_seconds=1)
    nonce = b"expiring-nonce"
    
    with patch.object(ReplayCache, '_get_current_time', return_value=1000.0):
        cache.check_and_add(nonce)
        
        # Immediate replay check
        with pytest.raises(ReplayError):
            cache.check_and_add(nonce)
            
    # Mock time jump past TTL
    with patch.object(ReplayCache, '_get_current_time', return_value=1002.0):
        # Should be allowed now (or at least not raise ReplayError if we re-add)
        # Note: In our implementation, we allow re-adding if expired.
        assert cache.check_and_add(nonce) is True

def test_cache_capacity_limit():
    # Cache limited to 3 nonces
    cache = ReplayCache(max_size=3)
    
    cache.check_and_add(b"n1")
    cache.check_and_add(b"n2")
    cache.check_and_add(b"n3")
    
    # Adding 4th should trigger eviction of the oldest (if none expired)
    # Our implementation evicts the oldest timestamp if full.
    cache.check_and_add(b"n4")
    
    assert len(cache._cache) == 3
    
    # n1 should have been evicted (oldest)
    assert cache.verify_freshness(b"n1") is True
    assert cache.check_and_add(b"n1") is True

def test_concurrent_insertions():
    cache = ReplayCache(max_size=100)
    nonces = [f"nonce-{i}".encode() for i in range(50)]
    
    def add_nonce(n):
        try:
            return cache.check_and_add(n)
        except ReplayError:
            return False

    with ThreadPoolExecutor(max_workers=10) as executor:
        # Mix of unique and duplicate nonces
        results = list(executor.map(add_nonce, nonces + nonces))
    
    # Exactly 50 should have succeeded
    assert results.count(True) == 50
    assert results.count(False) == 50

def test_malformed_nonces():
    cache = ReplayCache()
    
    with pytest.raises(ValueError):
        cache.check_and_add(b"") # Empty
    
    with pytest.raises(ValueError):
        cache.check_and_add("not-bytes") # type error

def test_secure_compare():
    assert ReplayCache.secure_compare(b"abc", b"abc") is True
    assert ReplayCache.secure_compare(b"abc", b"def") is False
    # Test with different lengths (compare_digest handles this or raises)
    assert ReplayCache.secure_compare(b"abc", b"abcd") is False

def test_cleanup_on_full():
    # Test that cleanup is actually called when reaching max_size
    cache = ReplayCache(max_size=2, ttl_seconds=10)
    
    with patch.object(ReplayCache, '_get_current_time', return_value=1000.0):
        cache.check_and_add(b"n1")
        cache.check_and_add(b"n2")
        
    # Now n1 and n2 are in cache. 
    # Mock time jump so n1 and n2 are expired.
    with patch.object(ReplayCache, '_get_current_time', return_value=1020.0):
        # Adding n3 should trigger cleanup of n1, n2
        cache.check_and_add(b"n3")
        assert len(cache._cache) == 1
        assert "n3".encode().hex() in cache._cache
