"""
Adaptive Lockout Manager
Handles adaptive brute-force protection with dynamic delays and historical tracking.
"""

import time
import math
from src.database_manager import DatabaseManager
from typing import Dict, Any, Tuple

class AdaptiveLockout:

    DEFAULT_MAX_DELAY = 300              # seconds
    DEFAULT_HISTORY_WINDOW = 1800         # seconds (30 min)
    DEFAULT_TRIM_LIMIT = 100              # max rows kept

    def __init__(self, dbmanager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize adaptive lockout manager

        Args:
            dbmanager: Instance of DatabaseManager for metadata access
            config: Config dictionary or object

        Loads historical failed login timestamps from database and initializes counters.
        """
        self.dbmanager = dbmanager
        # normalize and validate config values used by this module
        self.config = dict(config) if config is not None else {}

        config_keys = ["max_lockout_delay", "history_window_seconds", "history_trim_limit"]
        for key in config_keys:
            if key in self.config and not isinstance(self.config[key], int):
                raise ValueError("AdaptiveLockout config values must be integers")

        try:
            self.max_delay = int(
                self.config.get("max_lockout_delay", self.DEFAULT_MAX_DELAY)
            )
            self.history_window = int(
                self.config.get("history_window_seconds", self.DEFAULT_HISTORY_WINDOW)
            )
            self.trim_limit = int(
                self.config.get("history_trim_limit", self.DEFAULT_TRIM_LIMIT)
            )

        except (TypeError, ValueError) as e:
            raise ValueError("AdaptiveLockout config values must be integers") from e

        if self.max_delay < 0 or self.history_window <= 0 or self.trim_limit <= 0:
            raise ValueError("AdaptiveLockout config values must be positive")

    def record_failure(self):
        """
        Record a failed unlock attempt via the database manager.

        Fixes MAJOR-11 (Race Condition): Delegates transaction entirely to
        DatabaseManager to ensure atomic Insert + Prune.
        """
        self.dbmanager.record_lockout_failure(
            retention_seconds=self.history_window,
            trim_limit=self.trim_limit
        )

    def check_and_delay(self) -> Tuple[bool, int]:
        """
        Determine whether a new unlock attempt is allowed.
        Uses sliding-window adaptive delay based on recent failures.
        """
        max_delay = self.max_delay
        lookback_window = self.history_window

        now = int(time.time())
        cutoff = now - lookback_window

        timestamps = self.dbmanager.get_lockout_history(since_timestamp=cutoff)
        # ensure timestamps sorted ascending (DB layer already returns ASC)
        count = max(0, len(timestamps))

        if count == 0:
            return True, 0

        last_attempt = timestamps[-1]
        time_since_last = max(0, now - int(last_attempt))

        # Fix MAJOR-10: Cap exponent logic to prevent overflow/waste
        # Calculate max useful exponent: 2^x = max_delay  =>  x = log2(max_delay)
        if max_delay > 1:
            max_useful_exp = int(math.ceil(math.log2(max_delay)))
        else:
            max_useful_exp = 0

        # Exponential backoff: 1s, 2s, 4s...
        exp = count - 1
        if exp < 0:
            exp = 0

        # Clamp exponent BEFORE power calculation
        exp = min(exp, max_useful_exp)

        # Calculate delay
        delay = 2 ** exp

        # Final safety clip
        delay = min(delay, max_delay)

        remaining = delay - time_since_last
        if remaining <= 0:
            return True, 0
        return False, int(remaining)

    def reset_session(self):
        """
        Reset current session attempt count and last attempt time.
        """
        self.dbmanager.clear_lockout_history()

    def get_status_message(self) -> dict:
        """
        Generate a user-friendly message about current lockout status.
        
        Returns:
            Status string
        """
        allowed, delay = self.check_and_delay()
        failures = len(self.dbmanager.get_lockout_history())

        return {
            "allowed": allowed,
            "delay": max(0, int(delay)),
            "failures": failures,
        }