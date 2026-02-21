"""
tests/test_recovery_manager.py
Unit tests for src/recovery_manager.py and VaultController recovery integration.

Coverage:
  - Setup passphrase (happy path, empty passphrase, wrong vault_key size)
  - Setup codes (happy path, count validation, idempotent regeneration)
  - recover_with_passphrase (correct, wrong, no-config)
  - recover_with_code (correct, wrong, used, no-config)
  - One-time-use enforcement (second use rejected)
  - disable_recovery / get_status
  - VaultController.setup_recovery_passphrase/codes/recover_vault/disable/status
"""
import os
import json
import pytest
import tempfile
import sqlite3

from unittest.mock import MagicMock, patch

# Module under test
from src.recovery_manager import (
    RecoveryManager,
    RecoveryError,
    RecoveryNotEnabledError,
    RecoveryCredentialError,
    _generate_code,
    _normalise_code,
)
from src.database_manager import DatabaseManager
from src.vault_controller import (
    VaultController, VaultError, VaultLockedError,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture()
def tmp_db(tmp_path):
    """Return a fresh DatabaseManager backed by a temp file."""
    db_path = str(tmp_path / "vault.db")
    db = DatabaseManager(db_path)
    db.initialize_database()
    return db


@pytest.fixture()
def rm(tmp_db):
    """Return a RecoveryManager with an empty (but schema-ready) database."""
    return RecoveryManager(tmp_db)


@pytest.fixture()
def vault_key():
    """Return a valid 32-byte vault key."""
    return os.urandom(32)


# ============================================================
# Code generation helpers
# ============================================================

class TestCodeHelpers:
    def test_generate_code_format(self):
        code = _generate_code()
        parts = code.split("-")
        assert len(parts) == 4
        assert all(len(p) == 5 for p in parts)
        assert code == code.upper()

    def test_generate_code_random(self):
        codes = {_generate_code() for _ in range(20)}
        assert len(codes) > 1  # extremely unlikely to collide

    def test_normalise_strips_whitespace(self):
        assert _normalise_code("  ab12c-de34f-gh56i-jk78l  ") == "AB12C-DE34F-GH56I-JK78L"


# ============================================================
# RecoveryManager — setup_passphrase
# ============================================================

class TestSetupPassphrase:
    def test_happy_path(self, rm, vault_key):
        """Should store a passphrase row without raising."""
        rm.setup_passphrase(vault_key, "correct horse battery staple")
        status = rm.get_status()
        assert status["enabled"] is True
        assert status["type"] == "passphrase"

    def test_empty_passphrase_raises(self, rm, vault_key):
        with pytest.raises(ValueError, match="non-empty"):
            rm.setup_passphrase(vault_key, "")

    def test_whitespace_only_passphrase_raises(self, rm, vault_key):
        with pytest.raises(ValueError):
            rm.setup_passphrase(vault_key, "   ")

    def test_wrong_vault_key_size_raises(self, rm):
        with pytest.raises(ValueError, match="32 bytes"):
            rm.setup_passphrase(b"tooshort", "passphrase")

    def test_replaces_existing_passphrase(self, rm, vault_key):
        """Re-calling setup_passphrase replaces the old row (not duplicates it)."""
        rm.setup_passphrase(vault_key, "first passphrase")
        rm.setup_passphrase(vault_key, "second passphrase")
        conn = rm.db.connect()
        count = conn.execute(
            "SELECT COUNT(*) FROM vault_recovery WHERE type='passphrase'"
        ).fetchone()[0]
        assert count == 1


# ============================================================
# RecoveryManager — setup_codes
# ============================================================

class TestSetupCodes:
    def test_returns_correct_count(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=8)
        assert len(codes) == 8

    def test_codes_unique(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=8)
        assert len(set(codes)) == 8

    def test_code_format(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=1)
        parts = codes[0].split("-")
        assert len(parts) == 4
        assert all(len(p) == 5 for p in parts)

    def test_replaces_existing_codes(self, rm, vault_key):
        rm.setup_codes(vault_key, count=4)
        rm.setup_codes(vault_key, count=4)
        conn = rm.db.connect()
        count = conn.execute(
            "SELECT COUNT(*) FROM vault_recovery WHERE type='code'"
        ).fetchone()[0]
        assert count == 4

    def test_invalid_count_raises(self, rm, vault_key):
        with pytest.raises(ValueError, match="count"):
            rm.setup_codes(vault_key, count=0)
        with pytest.raises(ValueError, match="count"):
            rm.setup_codes(vault_key, count=17)

    def test_wrong_vault_key_size_raises(self, rm):
        with pytest.raises(ValueError):
            rm.setup_codes(b"short", count=4)


# ============================================================
# RecoveryManager — recover_with_passphrase
# ============================================================

class TestRecoverWithPassphrase:
    def test_correct_passphrase_returns_vault_key(self, rm, vault_key):
        passphrase = "correct horse battery staple"
        rm.setup_passphrase(vault_key, passphrase)
        recovered = rm.recover_with_passphrase(passphrase)
        assert recovered == vault_key

    def test_wrong_passphrase_raises(self, rm, vault_key):
        rm.setup_passphrase(vault_key, "right passphrase")
        with pytest.raises(RecoveryCredentialError):
            rm.recover_with_passphrase("wrong passphrase")

    def test_no_passphrase_configured_raises(self, rm):
        with pytest.raises(RecoveryNotEnabledError):
            rm.recover_with_passphrase("any passphrase")

    def test_passphrase_is_case_sensitive(self, rm, vault_key):
        rm.setup_passphrase(vault_key, "Hello World")
        with pytest.raises(RecoveryCredentialError):
            rm.recover_with_passphrase("hello world")


# ============================================================
# RecoveryManager — recover_with_code
# ============================================================

class TestRecoverWithCode:
    def test_correct_code_returns_vault_key(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=4)
        recovered = rm.recover_with_code(codes[0])
        assert recovered == vault_key

    def test_wrong_code_raises(self, rm, vault_key):
        rm.setup_codes(vault_key, count=4)
        with pytest.raises(RecoveryCredentialError):
            rm.recover_with_code("AAAAA-BBBBB-CCCCC-DDDDD")

    def test_no_codes_configured_raises(self, rm):
        with pytest.raises(RecoveryNotEnabledError):
            rm.recover_with_code("AAAAA-BBBBB-CCCCC-DDDDD")

    def test_code_is_case_insensitive(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=2)
        lower_code = codes[0].lower()
        recovered = rm.recover_with_code(lower_code)
        assert recovered == vault_key

    def test_code_whitespace_stripped(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=2)
        padded = "  " + codes[1] + "  "
        recovered = rm.recover_with_code(padded)
        assert recovered == vault_key

    # ---- One-time-use enforcement ----
    def test_used_code_rejected_on_second_attempt(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=2)
        rm.recover_with_code(codes[0])  # use it once — should succeed
        with pytest.raises(RecoveryCredentialError):
            rm.recover_with_code(codes[0])  # second attempt must fail

    def test_used_code_does_not_invalidate_other_codes(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=3)
        rm.recover_with_code(codes[0])
        # Other codes still valid
        recovered = rm.recover_with_code(codes[1])
        assert recovered == vault_key

    def test_code_marked_used_in_db(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=2)
        rm.recover_with_code(codes[0])
        conn = rm.db.connect()
        used_count = conn.execute(
            "SELECT COUNT(*) FROM vault_recovery WHERE type='code' AND used=1"
        ).fetchone()[0]
        assert used_count == 1


# ============================================================
# RecoveryManager — disable + status
# ============================================================

class TestDisableAndStatus:
    def test_status_disabled_when_empty(self, rm):
        s = rm.get_status()
        assert s == {
            "enabled": False,
            "type": None,
            "codes_total": 0,
            "codes_remaining": 0,
        }

    def test_status_passphrase_only(self, rm, vault_key):
        rm.setup_passphrase(vault_key, "some phrase")
        s = rm.get_status()
        assert s["enabled"] is True
        assert s["type"] == "passphrase"
        assert s["codes_total"] == 0

    def test_status_codes_only(self, rm, vault_key):
        rm.setup_codes(vault_key, count=8)
        s = rm.get_status()
        assert s["enabled"] is True
        assert s["type"] == "codes"
        assert s["codes_total"] == 8
        assert s["codes_remaining"] == 8

    def test_status_codes_decremented_after_use(self, rm, vault_key):
        codes = rm.setup_codes(vault_key, count=4)
        rm.recover_with_code(codes[0])
        s = rm.get_status()
        assert s["codes_remaining"] == 3
        assert s["codes_total"] == 4

    def test_status_both(self, rm, vault_key):
        rm.setup_passphrase(vault_key, "phrase")
        rm.setup_codes(vault_key, count=4)
        s = rm.get_status()
        assert s["type"] == "both"

    def test_disable_clears_all(self, rm, vault_key):
        rm.setup_passphrase(vault_key, "phrase")
        rm.setup_codes(vault_key, count=4)
        rm.disable_recovery()
        s = rm.get_status()
        assert s["enabled"] is False

    def test_disable_idempotent(self, rm):
        rm.disable_recovery()  # no crash on empty
        rm.disable_recovery()


# ============================================================
# VaultController integration
# ============================================================

class TestVaultControllerRecovery:
    @pytest.fixture()
    def unlocked_vc(self, tmp_path):
        """Return an unlocked VaultController with a fresh, schema-initialised DB."""
        db_path = str(tmp_path / "vault.db")
        vc = VaultController(db_path, config={
            "argon2_memory_cost": 8 * 1024,
            "argon2_time_cost": 1,
            "argon2_parallelism": 1,
        })
        # Ensure schema is applied before unlock_vault checks adaptive_lockout
        vc.db.initialize_database()
        vc._schema_initialized = True
        vc.unlock_vault("SuperSecret123!", create_if_missing=True)
        return vc

    def _make_vc(self, tmp_path, **config):
        """Helper: create + fully initialise a VaultController backed by tmp_path."""
        db_path = str(tmp_path / "vault.db")
        vc = VaultController(db_path, config={
            "argon2_memory_cost": 8 * 1024,
            "argon2_time_cost": 1,
            "argon2_parallelism": 1,
            **config,
        })
        vc.db.initialize_database()
        vc._schema_initialized = True
        return vc

    def test_setup_recovery_passphrase_requires_unlock(self, tmp_path):
        db_path = str(tmp_path / "vault.db")
        vc = VaultController(db_path)
        with pytest.raises(VaultLockedError):
            vc.setup_recovery_passphrase("recovery phrase here")

    def test_setup_recovery_codes_requires_unlock(self, tmp_path):
        db_path = str(tmp_path / "vault.db")
        vc = VaultController(db_path)
        with pytest.raises(VaultLockedError):
            vc.setup_recovery_codes()

    def test_setup_passphrase_roundtrip_via_controller(self, unlocked_vc):
        unlocked_vc.setup_recovery_passphrase("my recovery phrase")
        s = unlocked_vc.get_recovery_status()
        assert s["enabled"] is True
        assert s["type"] == "passphrase"

    def test_setup_codes_returns_list_via_controller(self, unlocked_vc):
        codes = unlocked_vc.setup_recovery_codes(count=4)
        assert len(codes) == 4

    def test_recover_vault_with_passphrase(self, tmp_path):
        """Full recovery flow: create vault, set passphrase, lock, recover."""
        vc = self._make_vc(tmp_path)
        vc.unlock_vault("OldPassword123!", create_if_missing=True)
        vc.setup_recovery_passphrase("my secret recovery phrase")
        vc.lock_vault()

        # Fresh controller simulating restart
        vc2 = self._make_vc(tmp_path)
        result = vc2.recover_vault(
            credential="my secret recovery phrase",
            credential_type="passphrase",
            new_password="NewPassword456!",
        )
        assert result is True
        assert vc2.is_unlocked is True

    def test_recover_vault_with_code(self, tmp_path):
        """Full recovery flow using one-time code."""
        vc = self._make_vc(tmp_path)
        vc.unlock_vault("OldPassword123!", create_if_missing=True)
        codes = vc.setup_recovery_codes(count=4)
        vc.lock_vault()

        vc2 = self._make_vc(tmp_path)
        result = vc2.recover_vault(
            credential=codes[0],
            credential_type="code",
            new_password="NewPassword456!",
        )
        assert result is True
        # Can unlock with new password after recovery
        vc2.lock_vault()
        vc3 = self._make_vc(tmp_path)
        vc3.unlock_vault("NewPassword456!")
        assert vc3.is_unlocked is True

    def test_recover_wrong_passphrase_raises(self, tmp_path):
        vc = self._make_vc(tmp_path)
        vc.unlock_vault("Pass123!", create_if_missing=True)
        vc.setup_recovery_passphrase("correct phrase")
        vc.lock_vault()

        vc2 = self._make_vc(tmp_path)
        with pytest.raises(RecoveryCredentialError):
            vc2.recover_vault("wrong phrase", "passphrase", "NewPass456!")

    def test_disable_recovery_via_controller(self, unlocked_vc):
        unlocked_vc.setup_recovery_passphrase("phrase to remove")
        unlocked_vc.disable_recovery()
        s = unlocked_vc.get_recovery_status()
        assert s["enabled"] is False

    def test_get_recovery_status_no_unlock_required(self, tmp_path):
        db_path = str(tmp_path / "vault.db")
        vc = VaultController(db_path)
        # Should not raise even when locked
        s = vc.get_recovery_status()
        assert s["enabled"] is False
