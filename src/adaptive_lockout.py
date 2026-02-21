"""
Adaptive Lockout Manager
Handles adaptive brute-force protection with dynamic delays and historical tracking.
"""

import time
import math
from datetime import datetime, timezone
from src.database_manager import DatabaseManager
from typing import Dict, Any, Optional, Tuple

class AdaptiveLockout:

    DEFAULT_MAX_DELAY = 300              # seconds (soft backoff cap)
    DEFAULT_HISTORY_WINDOW = 1800         # seconds (30 min sliding window)
    DEFAULT_TRIM_LIMIT = 100              # max rows kept
    DEFAULT_HARD_LOCKOUT_THRESHOLD = 10   # failures before hard lockout
    DEFAULT_HARD_LOCKOUT_DURATION = 86400 # seconds (24 hours)

    def __init__(self, dbmanager: DatabaseManager, config: Dict[str, Any]):
        """
        Initialize adaptive lockout manager.

        Args:
            dbmanager: Instance of DatabaseManager for metadata access
            config: Config dictionary. Supports keys:
                max_lockout_delay      — soft-backoff cap in seconds (default 300)
                history_window_seconds — sliding window length (default 1800)
                history_trim_limit     — max DB rows kept (default 100)
                hard_lockout_threshold — failures before hard lockout (default 10)
                hard_lockout_duration  — hard lockout duration in seconds (default 86400)
        """
        self.dbmanager = dbmanager
        self.config = dict(config) if config is not None else {}

        config_keys = [
            "max_lockout_delay", "history_window_seconds", "history_trim_limit",
            "hard_lockout_threshold", "hard_lockout_duration",
        ]
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
            self.hard_lockout_threshold = int(
                self.config.get("hard_lockout_threshold", self.DEFAULT_HARD_LOCKOUT_THRESHOLD)
            )
            self.hard_lockout_duration = int(
                self.config.get("hard_lockout_duration", self.DEFAULT_HARD_LOCKOUT_DURATION)
            )

        except (TypeError, ValueError) as e:
            raise ValueError("AdaptiveLockout config values must be integers") from e

        if self.max_delay < 0 or self.history_window <= 0 or self.trim_limit <= 0:
            raise ValueError("AdaptiveLockout config values must be positive")
        if self.hard_lockout_threshold < 1 or self.hard_lockout_duration < 1:
            raise ValueError("hard_lockout_threshold and hard_lockout_duration must be >= 1")

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

        Hard lockout:  >= hard_lockout_threshold failures in history window
                       → blocked for hard_lockout_duration seconds from last failure.
        Soft backoff:  < threshold failures → exponential delay (1s, 2s, 4s … max_delay).

        Returns:
            (allowed: bool, remaining_seconds: int)
        """
        now = int(time.time())
        cutoff = now - self.history_window
        timestamps = self.dbmanager.get_lockout_history(since_timestamp=cutoff)
        count = len(timestamps)

        if count == 0:
            return True, 0

        last_attempt = int(timestamps[-1])
        time_since_last = max(0, now - last_attempt)

        # --- Hard lockout check ---
        if count >= self.hard_lockout_threshold:
            hard_remaining = self.hard_lockout_duration - time_since_last
            if hard_remaining > 0:
                return False, int(hard_remaining)
            # Hard lockout expired — allow but don't auto-clear history here
            return True, 0

        # --- Soft exponential backoff ---
        if self.max_delay > 1:
            max_useful_exp = int(math.ceil(math.log2(self.max_delay)))
        else:
            max_useful_exp = 0

        exp = min(max(count - 1, 0), max_useful_exp)
        delay = min(2 ** exp, self.max_delay)

        remaining = delay - time_since_last
        if remaining <= 0:
            return True, 0
        return False, int(remaining)

    def reset_session(self):
        """Clear lockout history after a successful unlock."""
        self.dbmanager.clear_lockout_history()

    def get_status(self) -> Dict[str, Any]:
        """
        Return a rich status dict for CLI display and monitoring.

        Keys:
            allowed          — bool: can an attempt be made right now?
            delay_seconds    — int: seconds to wait (0 if allowed)
            failures         — int: number of failures in the history window
            hard_locked      — bool: True when >= hard_lockout_threshold failures
            next_allowed_at  — Optional[str]: ISO-8601 UTC timestamp when lockout lifts
            attempts_before_hard_lockout — int: remaining soft attempts before hard lockout
        """
        now = int(time.time())
        cutoff = now - self.history_window
        timestamps = self.dbmanager.get_lockout_history(since_timestamp=cutoff)
        count = len(timestamps)
        allowed, delay = self.check_and_delay()

        hard_locked = count >= self.hard_lockout_threshold
        next_allowed_at: Optional[str] = None
        if not allowed and timestamps:
            last_ts = int(timestamps[-1])
            if hard_locked:
                unlock_ts = last_ts + self.hard_lockout_duration
            else:
                if self.max_delay > 1:
                    max_exp = int(math.ceil(math.log2(self.max_delay)))
                else:
                    max_exp = 0
                exp = min(max(count - 1, 0), max_exp)
                soft_delay = min(2 ** exp, self.max_delay)
                unlock_ts = last_ts + soft_delay
            next_allowed_at = datetime.fromtimestamp(unlock_ts, tz=timezone.utc).isoformat()

        remaining_soft = max(0, self.hard_lockout_threshold - count)

        return {
            "allowed": allowed,
            "delay_seconds": delay,
            "failures": count,
            "hard_locked": hard_locked,
            "next_allowed_at": next_allowed_at,
            "attempts_before_hard_lockout": remaining_soft,
        }

    # Keep old name as alias for backward compatibility with existing call sites
    def get_status_message(self) -> dict:
        """Deprecated alias for get_status()."""
        return self.get_status()