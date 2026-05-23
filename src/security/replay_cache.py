"""
Sentra Replay Cache
Prevents replay attacks by tracking recently seen nonces.
Uses a bounded memory-safe eviction strategy with TTL support.
"""
import time
import hmac
import threading
from typing import Set, Dict, Optional


class ReplayError(Exception):
    """Raised when a replay attempt is detected."""
    pass


class ReplayCache:
    """
    In-memory cache for nonces to prevent replay attacks.
    Nonces are automatically evicted after TTL expires or if the cache exceeds capacity.
    """

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 3600):
        """
        Initialize the replay cache.
        
        Args:
            max_size: Maximum number of nonces to track.
            ttl_seconds: How long a nonce is considered valid for replay protection.
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, float] = {}  # nonce_hex -> expiry_time
        self._lock = threading.Lock()

    def _get_current_time(self) -> float:
        return time.time()

    def check_and_add(self, nonce: bytes) -> bool:
        """
        Check if a nonce has been seen before. If not, add it to the cache.
        
        Args:
            nonce: The raw nonce bytes.
            
        Returns:
            bool: True if the nonce is fresh and was added.
            
        Raises:
            ReplayError: If the nonce is already in the cache.
        """
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) == 0:
            raise ValueError("Nonce must be a non-empty bytes-like object")

        nonce_hex = nonce.hex()
        now = self._get_current_time()

        with self._lock:
            # 1. Cleanup expired entries periodically or when full
            if len(self._cache) >= self.max_size:
                self._cleanup(now)

            # 2. Check for existence (Constant-time check if needed, 
            # though dictionary lookup is generally okay for non-secrets)
            # We use a standard check for performance, but ensure it's thread-safe.
            if nonce_hex in self._cache:
                expiry = self._cache[nonce_hex]
                if now < expiry:
                    raise ReplayError("Replay attempt detected: nonce already seen")
                else:
                    # Nonce expired, we can re-add it (though typically nonces shouldn't repeat)
                    del self._cache[nonce_hex]

            # 3. Add to cache
            self._cache[nonce_hex] = now + self.ttl_seconds
            
            # 4. Final safety check on size
            if len(self._cache) > self.max_size:
                # Evict the oldest entry if still full after cleanup
                oldest_key = min(self._cache, key=lambda k: self._cache[k])
                del self._cache[oldest_key]

        return True

    def _cleanup(self, now: float):
        """Remove all expired nonces from the cache."""
        expired_keys = [k for k, v in self._cache.items() if v <= now]
        for k in expired_keys:
            del self._cache[k]

    def verify_freshness(self, nonce: bytes) -> bool:
        """
        Pure check without adding. Useful for pre-validation.
        """
        nonce_hex = nonce.hex()
        now = self._get_current_time()
        
        with self._lock:
            if nonce_hex in self._cache:
                expiry = self._cache[nonce_hex]
                return now >= expiry
        return True

    def clear(self):
        """Clear the entire cache."""
        with self._lock:
            self._cache.clear()

    @staticmethod
    def secure_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison for cryptographic buffers."""
        return hmac.compare_digest(a, b)
