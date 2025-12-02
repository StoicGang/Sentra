import json
import time
from typing import Tuple
from src.adaptive_lockout import AdaptiveLockout

class MockDBManager:
    def __init__(self):
        self.storage = {}
    def get_metadata(self, key):
        return self.storage.get(key, None)
    def update_metadata(self, key, value):
        print(f"Metadata updated - Key: {key}, Value: {value[:60]}...")  # Preview only
        self.storage[key] = value

def test_record_failure():
    db = MockDBManager()
    config = {}
    lockout = AdaptiveLockout(db, config)
    
    # Initially no attempts
    assert lockout.current_session_attempts == 0
    assert lockout.failed_attempt_history == []
    
    # Record a failure
    lockout.record_failure()
    assert lockout.current_session_attempts == 1
    assert len(lockout.failed_attempt_history) == 1
    
    # Record multiple failures
    for _ in range(150):
        lockout.record_failure()
    
    assert lockout.current_session_attempts == 151
    assert len(lockout.failed_attempt_history) == 100  # History trimmed to last 100

    print("record_failure test passed!")

def check_and_delay(self) -> Tuple[bool, int]:
    """
    Check if a new unlock attempt is allowed and return delay in seconds.
    
    Returns:
        allowed (bool): True if attempt allowed
        delay_seconds (int): Required delay before next attempt (0 if allowed)
    """
    max_delay = self.config.get("max_lockout_delay", 300)  # default 5 minutes
    now = int(time.time())
    
    # If no failed attempts, allow immediately
    if not self.failed_attempt_history:
        return True, 0
    
    last_attempt = self.failed_attempt_history[-1]
    time_since_last = now - last_attempt
    
    # Delay doubles with each consecutive failure, starting at 1 second
    # Calculate delay based on current session attempts
    delay = min(max_delay, 2 ** (self.current_session_attempts - 1)) if self.current_session_attempts > 0 else 0
    
    if time_since_last >= delay:
        return True, 0  # Enough time passed to allow attempt
    
    return False, delay - time_since_last

if __name__ == "__main__":
    test_record_failure()
    check_and_delay()