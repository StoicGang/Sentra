"""
Adaptive Lockout Manager
Handles adaptive brute-force protection with dynamic delays and historical tracking.
"""

import time
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
        Record a failed unlock attempt.
        
        Actions:
        - Increment current session failure counter.
        - Append current UNIX timestamp (int) to failed_attempt_history list.
        - Trim failed_attempt_history to last 100 entries.
        - Save updated history JSON to database metadata.
        """
        # DB layer handles insertion + time-based pruning
        self.dbmanager.record_lockout_failure()

        # AdaptiveLockout layer handles count-based pruning ONLY
        try:
            conn = self.dbmanager.connect()
            conn.execute(
                """
                DELETE FROM lockout_attempts
                WHERE id IN (
                    SELECT id FROM lockout_attempts
                    ORDER BY attempt_ts DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (self.trim_limit,)
            )
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise

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

        # Exponential backoff: 1s, 2s, 4s, ... capped by max_delay
        # Use (count-1) but guard against huge exponent.
        exp = count - 1
        if exp < 0:
            exp = 0
        # avoid ridiculously large intermediate by bounding exponent
        max_exp = 31  # 2**31 is already huge; will be capped by max_delay
        exp = min(exp, max_exp)
        delay = min(max_delay, 2 ** exp)

        remaining = delay - time_since_last
        if remaining <= 0:
            return True, 0
        return False, remaining

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