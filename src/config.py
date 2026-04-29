"""
Sentra Configuration Manager
Centralizes path definitions and environment variable loading.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# 1. Locate the Project Root
# Assumes structure: project/src/config.py
# So we go up two levels to find project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 2. Load .env file
# This will load variables from .env into os.environ
load_dotenv(PROJECT_ROOT / ".env")

# 3. Define Default Paths
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "vault.db"
DEFAULT_SCHEMA_PATH = DEFAULT_DATA_DIR / "schema.sql"

# 4. Export Configuration
# Priority: Environment Variable -> .env file -> Default Paths
DB_PATH = os.getenv("SENTRA_DB_PATH", str(DEFAULT_DB_PATH))
SCHEMA_PATH = os.getenv("SENTRA_SCHEMA_PATH", str(DEFAULT_SCHEMA_PATH))

# Ensure data directory exists if we are using the default path
if str(DEFAULT_DATA_DIR) in DB_PATH:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# ============================================================
# Security & UX Constants — single source of truth
# Import these everywhere instead of redefining locally.
# ============================================================

# Password policy
MIN_PASSWORD_LENGTH: int = int(os.getenv("SENTRA_MIN_PASSWORD_LENGTH", "12"))
DEFAULT_PASSWORD_LENGTH: int = int(os.getenv("SENTRA_DEFAULT_PASSWORD_LENGTH", "16"))
MAX_PASSWORD_LENGTH: int = 128

# Auth / lockout
MAX_LOGIN_ATTEMPTS: int = 3
MAX_UNLOCK_ATTEMPTS: int = 10

# Secure display
REVEAL_DURATION_SECS: int = int(os.getenv("SENTRA_REVEAL_DURATION", "10"))
CLIPBOARD_CLEAR_SECS: int = int(os.getenv("SENTRA_CLIPBOARD_CLEAR", "30"))

# Input sanitization
MAX_INPUT_LENGTH: int = 1000
