"""
tests/test_adaptive_lockout.py
Unit tests for AdaptiveLockout — brute-force protection module.
"""

import time
import pytest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_db(history=None, clear_ok=True):
    """Return a mocked DatabaseManager with controllable lockout history."""
    db = MagicMock()
    db.get_lockout_history.return_value = list(history or [])
    db.record_lockout_failure.return_value = None
    db.clear_lockout_history.return_value = None
    return db


def make_lockout(db=None, config=None):
    from src.adaptive_lockout import AdaptiveLockout
    if db is None:
        db = make_db()
    return AdaptiveLockout(dbmanager=db, config=config or {})


# ---------------------------------------------------------------------------
# Init / Config Validation
# ---------------------------------------------------------------------------

class TestInit:
    def test_defaults_are_sane(self):
        al = make_lockout()
        assert al.max_delay == 300
        assert al.history_window == 1800
        assert al.trim_limit == 100
        assert al.hard_lockout_threshold == 10
        assert al.hard_lockout_duration == 86400

    def test_custom_config_accepted(self):
        al = make_lockout(config={
            "max_lockout_delay": 60,
            "history_window_seconds": 600,
            "history_trim_limit": 50,
            "hard_lockout_threshold": 5,
            "hard_lockout_duration": 3600,
        })
        assert al.max_delay == 60
        assert al.history_window == 600
        assert al.hard_lockout_threshold == 5
        assert al.hard_lockout_duration == 3600

    def test_non_int_config_raises(self):
        from src.adaptive_lockout import AdaptiveLockout
        with pytest.raises(ValueError, match="integers"):
            AdaptiveLockout(dbmanager=make_db(), config={"max_lockout_delay": "fast"})

    def test_zero_history_window_raises(self):
        from src.adaptive_lockout import AdaptiveLockout
        with pytest.raises(ValueError):
            AdaptiveLockout(dbmanager=make_db(), config={"history_window_seconds": 0})

    def test_zero_hard_lockout_threshold_raises(self):
        from src.adaptive_lockout import AdaptiveLockout
        with pytest.raises(ValueError):
            AdaptiveLockout(dbmanager=make_db(), config={"hard_lockout_threshold": 0})


# ---------------------------------------------------------------------------
# check_and_delay — no failures
# ---------------------------------------------------------------------------

class TestNoFailures:
    def test_no_history_is_immediately_allowed(self):
        now = int(time.time())
        db = make_db(history=[])
        al = make_lockout(db)
        allowed, delay = al.check_and_delay()
        assert allowed is True
        assert delay == 0


# ---------------------------------------------------------------------------
# check_and_delay — soft exponential backoff
# ---------------------------------------------------------------------------

class TestSoftBackoff:
    def _make_al_with_n_failures(self, n, now=None):
        """Creates n failures all at time `now` (so time_since_last ≈ 0)."""
        now = now or int(time.time())
        history = [now] * n
        db = make_db(history=history)
        al = make_lockout(db)
        return al, now

    def test_one_failure_blocks_for_one_second(self):
        now = int(time.time())
        al, _ = self._make_al_with_n_failures(1, now)
        with patch("src.adaptive_lockout.time.time", return_value=now):
            allowed, delay = al.check_and_delay()
        assert allowed is False
        assert delay == 1   # 2^0 = 1

    def test_two_failures_blocks_for_two_seconds(self):
        now = int(time.time())
        al, _ = self._make_al_with_n_failures(2, now)
        with patch("src.adaptive_lockout.time.time", return_value=now):
            allowed, delay = al.check_and_delay()
        assert allowed is False
        assert delay == 2   # 2^1 = 2

    def test_three_failures_blocks_for_four_seconds(self):
        now = int(time.time())
        al, _ = self._make_al_with_n_failures(3, now)
        with patch("src.adaptive_lockout.time.time", return_value=now):
            allowed, delay = al.check_and_delay()
        assert allowed is False
        assert delay == 4   # 2^2

    def test_delay_caps_at_max_delay(self):
        # 100 failures should still cap at max_delay
        now = int(time.time())
        al, _ = self._make_al_with_n_failures(9, now)  # 9 < threshold (10)
        # Artificially set max_delay low
        al.max_delay = 4
        with patch("src.adaptive_lockout.time.time", return_value=now):
            allowed, delay = al.check_and_delay()
        assert allowed is False
        assert delay <= al.max_delay

    def test_expired_backoff_allows_attempt(self):
        """After enough time has passed since last failure, allow attempt."""
        past = int(time.time()) - 100   # 100 seconds ago
        now = int(time.time())
        al, _ = self._make_al_with_n_failures(1, past)
        # history is [past], last attempt was 100s ago; delay for 1 failure = 1s
        with patch("src.adaptive_lockout.time.time", return_value=now):
            allowed, delay = al.check_and_delay()
        assert allowed is True
        assert delay == 0


# ---------------------------------------------------------------------------
# check_and_delay — hard lockout
# ---------------------------------------------------------------------------

class TestHardLockout:
    def test_at_threshold_triggers_hard_lockout(self):
        now = int(time.time())
        db = make_db(history=[now] * 10)  # exactly threshold
        al = make_lockout(db)
        with patch("src.adaptive_lockout.time.time", return_value=now):
            allowed, delay = al.check_and_delay()
        assert allowed is False
        assert delay == al.hard_lockout_duration  # full 24h remaining

    def test_above_threshold_still_hard_locked(self):
        now = int(time.time())
        db = make_db(history=[now] * 15)  # above threshold
        al = make_lockout(db)
        with patch("src.adaptive_lockout.time.time", return_value=now):
            allowed, delay = al.check_and_delay()
        assert allowed is False

    def test_hard_lockout_expires_allows_attempt(self):
        """After hard_lockout_duration from last failure, allow attempt."""
        past = int(time.time()) - 86401   # just past 24h
        db = make_db(history=[past] * 10)
        al = make_lockout(db)
        now = past + 86401
        with patch("src.adaptive_lockout.time.time", return_value=now):
            allowed, delay = al.check_and_delay()
        assert allowed is True
        assert delay == 0

    def test_custom_threshold(self):
        now = int(time.time())
        db = make_db(history=[now] * 5)
        al = make_lockout(db, config={"hard_lockout_threshold": 5, "hard_lockout_duration": 3600})
        with patch("src.adaptive_lockout.time.time", return_value=now):
            allowed, delay = al.check_and_delay()
        assert allowed is False
        assert delay == 3600


# ---------------------------------------------------------------------------
# record_failure / reset_session
# ---------------------------------------------------------------------------

class TestSideEffects:
    def test_record_failure_delegates_to_db(self):
        db = make_db()
        al = make_lockout(db)
        al.record_failure()
        db.record_lockout_failure.assert_called_once_with(
            retention_seconds=al.history_window,
            trim_limit=al.trim_limit,
        )

    def test_reset_session_clears_history(self):
        db = make_db()
        al = make_lockout(db)
        al.reset_session()
        db.clear_lockout_history.assert_called_once()


# ---------------------------------------------------------------------------
# get_status
# ---------------------------------------------------------------------------

class TestGetStatus:
    def test_clean_state(self):
        db = make_db(history=[])
        al = make_lockout(db)
        status = al.get_status()
        assert status["allowed"] is True
        assert status["delay_seconds"] == 0
        assert status["failures"] == 0
        assert status["hard_locked"] is False
        assert status["next_allowed_at"] is None
        assert status["attempts_before_hard_lockout"] == al.hard_lockout_threshold

    def test_soft_backoff_state(self):
        now = int(time.time())
        db = make_db(history=[now] * 3)   # 3 failures < threshold 10
        al = make_lockout(db)
        with patch("src.adaptive_lockout.time.time", return_value=now):
            status = al.get_status()
        assert status["allowed"] is False
        assert status["hard_locked"] is False
        assert status["failures"] == 3
        assert status["next_allowed_at"] is not None
        assert status["attempts_before_hard_lockout"] == 7  # 10 - 3

    def test_hard_lockout_state(self):
        now = int(time.time())
        db = make_db(history=[now] * 10)
        al = make_lockout(db)
        with patch("src.adaptive_lockout.time.time", return_value=now):
            status = al.get_status()
        assert status["hard_locked"] is True
        assert status["allowed"] is False
        assert status["attempts_before_hard_lockout"] == 0
        assert status["next_allowed_at"] is not None

    def test_get_status_message_alias(self):
        """get_status_message() is an alias for get_status()."""
        db = make_db(history=[])
        al = make_lockout(db)
        assert al.get_status_message() == al.get_status()


# ---------------------------------------------------------------------------
# Integration: VaultController raises AccountLockedError
# ---------------------------------------------------------------------------

class TestVaultControllerIntegration:
    def test_unlock_raises_account_locked_error_when_locked(self):
        """VaultController.unlock_vault raises AccountLockedError if lockout blocks."""
        from src.vault_controller import VaultController, AccountLockedError

        now = int(time.time())
        history = [now] * 10  # hard lockout

        mock_db = MagicMock()
        mock_db.load_vault_metadata.return_value = None   # vault not initialized
        mock_db.initialize_database.return_value = True
        mock_db.get_lockout_history.return_value = history

        vc = VaultController.__new__(VaultController)
        vc.db = mock_db
        vc.config = {}

        from src.adaptive_lockout import AdaptiveLockout
        vc.adaptive_lockout = AdaptiveLockout(dbmanager=mock_db, config={})
        vc.is_unlocked = False
        vc._schema_initialized = True
        import threading
        vc._state_lock = threading.RLock()

        with patch("src.adaptive_lockout.time.time", return_value=now):
            with pytest.raises(AccountLockedError) as exc_info:
                vc.unlock_vault("anypassword", create_if_missing=False)

        assert exc_info.value.hard_locked is True
        assert exc_info.value.delay_seconds > 0

    def test_account_locked_error_has_next_allowed_at(self):
        """AccountLockedError.next_allowed_at is set for hard lockout."""
        from src.vault_controller import AccountLockedError

        err = AccountLockedError(
            "locked",
            delay_seconds=3600,
            hard_locked=True,
            next_allowed_at="2026-02-22T00:00:00+00:00",
        )
        assert err.hard_locked is True
        assert err.next_allowed_at == "2026-02-22T00:00:00+00:00"
        assert err.delay_seconds == 3600
