"""
Adaptive Lockout Manager
Handles adaptive brute-force protection with dynamic delays and historical tracking.
"""

import json
import time
from src.database_manager import DatabaseManager
from typing import Dict, Any, Tuple

class AdaptiveLockout:
    def __init__(self, dbmanager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize adaptive lockout manager
        
        Args:
            dbmanager: Instance of DatabaseManager for metadata access
            config: Config dictionary or object
            
        Loads historical failed login timestamps from database and initializes counters.
        """
        self.dbmanager = dbmanager
        self.config = config

    def record_failure(self):
        """
        Record a failed unlock attempt.
        
        Actions:
        - Increment current session failure counter.
        - Append current UNIX timestamp (int) to failed_attempt_history list.
        - Trim failed_attempt_history to last 100 entries.
        - Save updated history JSON to database metadata.
        """
        self.dbmanager.record_lockout_failure()

    def check_and_delay(self) -> Tuple[bool, int]:
        """
        Determine whether a new unlock attempt is allowed.
        Uses sliding-window adaptive delay based on recent failures.
        """
        max_delay = int(self.config.get("max_lockout_delay", 300))  # seconds
        lookback_window = int(self.config.get("history_window_seconds", 1800))  # default: 30 minutes

        now = int(time.time())
        cutoff = now - lookback_window

        # Fetch only recent attempts
        timestamps = self.dbmanager.get_lockout_history(since_timestamp=cutoff)
        count = len(timestamps)

        if count == 0:
            return True, 0

        last_attempt = timestamps[-1]
        time_since_last = now - last_attempt

        # Exponential backoff: 1s, 2s, 4s, 8s… up to max_delay
        delay = min(max_delay, 2 ** (count - 1))

        # If enough time has passed, allow attempt & reset history
        if time_since_last >= delay:
            self.reset_session()
            return True, 0

        # Otherwise, still locked
        return False, delay - time_since_last


    def reset_session(self):
        """
        Reset current session attempt count and last attempt time.
        """
        self.dbmanager.clear_lockout_history()

    def get_status_message(self) -> str:
        """
        Generate a user-friendly message about current lockout status.
        
        Returns:
            Status string
        """
        allowed, delay = self.check_and_delay()
        
        if not allowed:
            return f"Too many failed attempts. Please wait {delay} seconds."
            
        # Estimate attempts left (assuming 5 is the warning threshold)
        timestamps = self.dbmanager.get_lockout_history()
        attempts_left = max(0, 5 - len(timestamps))
        
        if attempts_left == 0:
            return "Multiple failed attempts detected. Delays are active."
            
        return f"You have {attempts_left} attempts left before delays begin."
