"""
Adaptive Lockout Manager
Handles adaptive brute-force protection with dynamic delays and historical tracking.
"""

import json
import time

class AdaptiveLockout:
    def __init__(self, dbmanager, config):
        """
        Initialize adaptive lockout manager
        
        Args:
            dbmanager: Instance of DatabaseManager for metadata access
            config: Config dictionary or object
            
        Loads historical failed login timestamps from database and initializes counters.
        """
        self.dbmanager = dbmanager
        self.config = config
        self.current_session_attempts = 0
        self.last_attempt_time = None
        
        history_json = self.dbmanager.get_metadata("failed_attempts_history")
        if history_json:
            self.failed_attempt_history = json.loads(history_json)
        else:
            self.failed_attempt_history = []

    def record_failure(self):
        """
        Record a failed unlock attempt.
        
        Actions:
        - Increment current session failure counter.
        - Append current UNIX timestamp (int) to failed_attempt_history list.
        - Trim failed_attempt_history to last 100 entries.
        - Save updated history JSON to database metadata.
        """
        self.current_session_attempts += 1
        current_time = int(time.time())
        self.failed_attempt_history.append(current_time)
        
        # Keep only the last 100 failed attempts
        if len(self.failed_attempt_history) > 100:
            self.failed_attempt_history = self.failed_attempt_history[-100:]
        
        history_json = json.dumps(self.failed_attempt_history)
        self.dbmanager.update_metadata("failed_attempts_history", history_json)

    def check_and_delay(self) -> tuple[bool, int]:
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

    def reset_session(self):
        """
        Reset current session attempt count and last attempt time.
        """
        self.current_session_attempts = 0
        self.last_attempt_time = None

    def get_status_message(self) -> str:
        """
        Generate a user-friendly message about current lockout status.
        
        Returns:
            Status string
        """
        allowed, delay = self.check_and_delay()
        
        if delay == -1:
            return "Vault locked due to repeated failures. Please use recovery key to unlock."
        
        if not allowed:
            return f"Too many failed attempts. Please wait {delay} seconds before trying again."
        
        attempts_left = max(0, 5 - self.current_session_attempts)
        if attempts_left == 0:
            return "Multiple failed attempts detected. Delays will increase on further failures."
        
        return f"You have {attempts_left} attempts left before delays are enforced."
