"""
src/recovery_manager.py
Optional account recovery for Sentra Password Manager.

Two modes:
  passphrase — Argon2id-derived key wraps a copy of the vault key
  codes      — Per-code HKDF-derived key wraps a copy of the vault key;
               each code is one-time-use; an HMAC verifier enables fast reject

Security properties:
  - Plaintext credentials are NEVER stored
  - Each row uses an independent random salt/nonce (no reuse)
  - Verifier allows "wrong code" detection without the vault key
  - One-time codes are permanently invalidated (used=1) after first use
  - Recovery does NOT bypass brute-force lockout
"""

import os
import hmac
import hashlib
import secrets
import string
from typing import List, Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2 import low_level
from argon2.exceptions import HashingError

from src.database_manager import DatabaseManager, DatabaseError


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RECOVERY_KDF_INFO = b"sentra-recovery-passphrase-v1"
_CODE_KDF_INFO     = b"sentra-recovery-code-v1"
_VERIFY_MAGIC      = b"sentra-recovery-verify"

# Argon2id params for passphrase (lighter than master key — still strong)
_ARGON2_TIME_COST   = 2
_ARGON2_MEMORY_COST = 32768   # 32 MB
_ARGON2_PARALLELISM = 2
_ARGON2_HASH_LEN    = 32

# Code format: groups of 5 uppercase alphanumeric chars separated by dashes
# e.g.  "AK7X2-9MNQ4-FPLR8-BVCW6"
_CODE_CHARS  = string.ascii_uppercase + string.digits
_CODE_GROUPS = 4
_CODE_GROUP_LEN = 5


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class RecoveryError(Exception):
    """Base exception for recovery operations."""
    pass

class RecoveryNotEnabledError(RecoveryError):
    """Raised when no recovery credential exists."""
    pass

class RecoveryCredentialError(RecoveryError):
    """Raised when the supplied credential is wrong or already used."""
    pass


# ---------------------------------------------------------------------------
# Internal crypto helpers
# ---------------------------------------------------------------------------

def _argon2_derive(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a passphrase using Argon2id."""
    try:
        return low_level.hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_ARGON2_HASH_LEN,
            type=low_level.Type.ID,
        )
    except HashingError as e:
        raise RecoveryError(f"Key derivation failed: {e}") from e


def _hkdf_derive(code: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a recovery code using HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_CODE_KDF_INFO,
    ).derive(code.encode("utf-8"))


def _chacha_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with ChaCha20-Poly1305. Returns (nonce, ciphertext, tag)."""
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    # ChaCha20Poly1305 appends 16-byte tag to ciphertext
    ct_and_tag = chacha.encrypt(nonce, plaintext, None)
    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]
    return nonce, ciphertext, tag


def _chacha_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Decrypt with ChaCha20-Poly1305. Raises RecoveryCredentialError on bad tag."""
    from cryptography.exceptions import InvalidTag
    chacha = ChaCha20Poly1305(key)
    try:
        return chacha.decrypt(nonce, ciphertext + tag, None)
    except InvalidTag as e:
        raise RecoveryCredentialError("Invalid credential — decryption failed.") from e


def _make_verifier(key: bytes) -> bytes:
    """HMAC-SHA256 of the derived key against a fixed magic value.
    Used for fast wrong-code detection before attempting vault key decryption."""
    return hmac.new(key, _VERIFY_MAGIC, hashlib.sha256).digest()


def _check_verifier(key: bytes, stored_verifier: bytes) -> bool:
    """Return True if key matches the stored verifier (constant-time compare)."""
    expected = _make_verifier(key)
    return hmac.compare_digest(expected, stored_verifier)


def _generate_code() -> str:
    """Generate a random recovery code in AAAAA-BBBBB-CCCCC-DDDDD format."""
    groups = [
        "".join(secrets.choice(_CODE_CHARS) for _ in range(_CODE_GROUP_LEN))
        for _ in range(_CODE_GROUPS)
    ]
    return "-".join(groups)


def _normalise_code(code: str) -> str:
    """Strip whitespace and upper-case; keep dashes. Allows copy-paste flexibility."""
    return code.strip().upper()


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _ensure_table(conn) -> None:
    """Ensure vault_recovery table exists (idempotent)."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault_recovery (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT NOT NULL CHECK (type IN ('passphrase', 'code')),
            code_index  INTEGER,
            kdf_salt    BLOB NOT NULL,
            nonce       BLOB NOT NULL,
            ciphertext  BLOB NOT NULL,
            tag         BLOB NOT NULL,
            verifier    BLOB,
            used        INTEGER DEFAULT 0 CHECK (used IN (0, 1)),
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)


# ---------------------------------------------------------------------------
# RecoveryManager
# ---------------------------------------------------------------------------

class RecoveryManager:
    """
    Manages optional account recovery for a Sentra vault.

    All DB operations run in transactions.  The vault_key passed to setup
    methods is the raw bytes in memory — it is never written to disk in
    plaintext.
    """

    def __init__(self, db: DatabaseManager):
        self.db = db

    # ------------------------------------------------------------------ #
    #  Setup Methods                                                       #
    # ------------------------------------------------------------------ #

    def setup_passphrase(self, vault_key: bytes, passphrase: str) -> None:
        """
        Encrypt vault_key under an Argon2id-derived key from passphrase and
        store the result.  Replaces any existing passphrase row atomically.

        Args:
            vault_key:  Raw 32-byte vault key currently in SecureMemory.
            passphrase: User-chosen recovery passphrase (non-empty string).

        Raises:
            ValueError: If passphrase is empty or vault_key is wrong length.
            RecoveryError: On Argon2id failure.
            DatabaseError: On DB write failure.
        """
        if not passphrase or not passphrase.strip():
            raise ValueError("Recovery passphrase must be a non-empty string.")
        if len(vault_key) != 32:
            raise ValueError("vault_key must be 32 bytes.")

        salt = os.urandom(16)
        key  = _argon2_derive(passphrase, salt)
        nonce, ciphertext, tag = _chacha_encrypt(key, vault_key)
        verifier = _make_verifier(key)

        conn = None
        try:
            conn = self.db.connect()
            _ensure_table(conn)
            conn.execute("BEGIN IMMEDIATE;")
            # Remove old passphrase row(s) first
            conn.execute("DELETE FROM vault_recovery WHERE type = 'passphrase'")
            conn.execute(
                """INSERT INTO vault_recovery
                       (type, code_index, kdf_salt, nonce, ciphertext, tag, verifier)
                   VALUES ('passphrase', NULL, ?, ?, ?, ?, ?)""",
                (salt, nonce, ciphertext, tag, verifier),
            )
            conn.commit()
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            raise DatabaseError(f"Failed to store recovery passphrase: {e}") from e

    def setup_codes(self, vault_key: bytes, count: int = 8) -> List[str]:
        """
        Generate `count` one-time recovery codes, encrypt a copy of vault_key
        under each code's HKDF-derived key, and store all rows atomically.
        Replaces any existing code rows.

        Args:
            vault_key: Raw 32-byte vault key.
            count:     Number of codes to generate (1–16 inclusive).

        Returns:
            List of plaintext code strings (user must store these offline).

        Raises:
            ValueError: Invalid arguments.
            DatabaseError: On DB write failure.
        """
        if len(vault_key) != 32:
            raise ValueError("vault_key must be 32 bytes.")
        if not 1 <= count <= 16:
            raise ValueError("count must be between 1 and 16.")

        # Generate all codes + encrypted blobs before touching the DB
        rows = []
        codes = []
        for idx in range(count):
            code = _generate_code()
            codes.append(code)
            salt = os.urandom(16)
            key  = _hkdf_derive(code, salt)
            nonce, ciphertext, tag = _chacha_encrypt(key, vault_key)
            verifier = _make_verifier(key)
            rows.append((idx, salt, nonce, ciphertext, tag, verifier))

        conn = None
        try:
            conn = self.db.connect()
            _ensure_table(conn)
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("DELETE FROM vault_recovery WHERE type = 'code'")
            conn.executemany(
                """INSERT INTO vault_recovery
                       (type, code_index, kdf_salt, nonce, ciphertext, tag, verifier)
                   VALUES ('code', ?, ?, ?, ?, ?, ?)""",
                rows,
            )
            conn.commit()
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            raise DatabaseError(f"Failed to store recovery codes: {e}") from e

        return codes

    # ------------------------------------------------------------------ #
    #  Recovery Methods                                                    #
    # ------------------------------------------------------------------ #

    def recover_with_passphrase(self, passphrase: str) -> bytes:
        """
        Verify passphrase and return the decrypted vault key.

        Raises:
            RecoveryNotEnabledError: No passphrase recovery is configured.
            RecoveryCredentialError: Wrong passphrase.
            DatabaseError: On DB read failure.
        """
        conn = self.db.connect()
        _ensure_table(conn)
        cursor = conn.execute(
            "SELECT kdf_salt, nonce, ciphertext, tag, verifier "
            "FROM vault_recovery WHERE type = 'passphrase' LIMIT 1"
        )
        row = cursor.fetchone()
        if row is None:
            raise RecoveryNotEnabledError("No passphrase recovery is configured.")

        salt, nonce, ciphertext, tag, stored_verifier = (
            bytes(row["kdf_salt"]), bytes(row["nonce"]),
            bytes(row["ciphertext"]), bytes(row["tag"]),
            bytes(row["verifier"]),
        )

        key = _argon2_derive(passphrase, salt)

        # Fast reject before decryption (prevents timing oracle)
        if not _check_verifier(key, stored_verifier):
            raise RecoveryCredentialError("Invalid recovery passphrase.")

        return _chacha_decrypt(key, nonce, ciphertext, tag)

    def recover_with_code(self, code: str) -> bytes:
        """
        Verify a one-time recovery code and return the decrypted vault key.
        On success, the code row is permanently marked used=1.

        Raises:
            RecoveryNotEnabledError: No code recovery configured.
            RecoveryCredentialError: Wrong or already-used code.
            DatabaseError: On DB read/write failure.
        """
        code = _normalise_code(code)
        conn = self.db.connect()
        _ensure_table(conn)

        cursor = conn.execute(
            "SELECT id, kdf_salt, nonce, ciphertext, tag, verifier "
            "FROM vault_recovery WHERE type = 'code' AND used = 0"
        )
        rows = cursor.fetchall()
        if not rows:
            raise RecoveryNotEnabledError("No unused recovery codes are configured.")

        # Try each active code row by verifier match (constant-time per row)
        matched_row = None
        matched_key = None
        for row in rows:
            salt = bytes(row["kdf_salt"])
            key  = _hkdf_derive(code, salt)
            if _check_verifier(key, bytes(row["verifier"])):
                matched_row = row
                matched_key = key
                break

        if matched_row is None:
            raise RecoveryCredentialError("Invalid or unrecognised recovery code.")

        # Decrypt vault key
        nonce      = bytes(matched_row["nonce"])
        ciphertext = bytes(matched_row["ciphertext"])
        tag        = bytes(matched_row["tag"])
        vault_key  = _chacha_decrypt(matched_key, nonce, ciphertext, tag)

        # Permanently mark this code used
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                "UPDATE vault_recovery SET used = 1 WHERE id = ?",
                (matched_row["id"],),
            )
            conn.commit()
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            raise DatabaseError(f"Failed to invalidate recovery code: {e}") from e

        return vault_key

    # ------------------------------------------------------------------ #
    #  Management                                                          #
    # ------------------------------------------------------------------ #

    def disable_recovery(self) -> None:
        """Delete all recovery rows. Recovery is fully disabled afterwards."""
        conn = None
        try:
            conn = self.db.connect()
            _ensure_table(conn)
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("DELETE FROM vault_recovery")
            conn.commit()
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            raise DatabaseError(f"Failed to disable recovery: {e}") from e

    def get_status(self) -> Dict[str, Any]:
        """
        Return a dict summarising recovery configuration.

        Keys:
            enabled          — bool: any recovery row exists
            type             — str: 'passphrase', 'codes', 'both', or None
            codes_total      — int: total code rows (used + unused)
            codes_remaining  — int: unused code rows
        """
        conn = self.db.connect()
        _ensure_table(conn)

        cursor = conn.execute(
            "SELECT type, used FROM vault_recovery"
        )
        rows = cursor.fetchall()

        has_passphrase = any(r["type"] == "passphrase" for r in rows)
        code_rows      = [r for r in rows if r["type"] == "code"]
        codes_total    = len(code_rows)
        codes_remaining = sum(1 for r in code_rows if r["used"] == 0)

        if has_passphrase and codes_total > 0:
            rtype = "both"
        elif has_passphrase:
            rtype = "passphrase"
        elif codes_total > 0:
            rtype = "codes"
        else:
            rtype = None

        return {
            "enabled":          rtype is not None,
            "type":             rtype,
            "codes_total":      codes_total,
            "codes_remaining":  codes_remaining,
        }
