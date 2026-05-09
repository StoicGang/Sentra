# Sentra

A secure, local-first password manager with a modular CLI and per-entry encryption. Sentra stores all secrets in a local SQLite vault protected by Argon2id key derivation and ChaCha20-Poly1305 authenticated encryption. No cloud, no telemetry — your data stays on your machine.

## Features

- **Encrypted vault** — Argon2id master key derivation, ChaCha20-Poly1305 AEAD encryption, per-entry HKDF key isolation
- **Interactive CLI shell** — Drop into an interactive session or run one-off commands
- **Password generation** — Cryptographically secure generator with strength scoring, dictionary checks, and keyboard pattern detection
- **TOTP support** — Generate and manage time-based one-time passwords
- **Multi-vault management** — Create, switch between, and manage multiple independent vaults
- **Encrypted backup & restore** — HMAC-verified, versioned backup format (v2) with per-backup derived keys
- **Account recovery** — Passphrase-based or one-time recovery codes to regain access if the master password is forgotten
- **Adaptive brute-force protection** — Exponential backoff with a hard lockout after repeated failures
- **Secure memory handling** — OS-level memory locking (`VirtualLock`/`mlock`) with verified zeroization and fork protection
- **Timed secret display** — Passwords shown for a limited duration, then erased from the terminal
- **Clipboard auto-clear** — Copied secrets are wiped from the clipboard after a configurable timeout
- **Soft delete & restore** — Deleted entries go to trash before permanent removal
- **Audit logging** — All vault operations (unlock, create, update, delete, security events) are logged
- **Self-destruct** — Configurable auto-destruct after N failed attempts, or manual trigger
- **Full-text search** — FTS5-powered search across entry titles, URLs, usernames, and tags
- **Supply chain security** — Locked dependencies with SHA-256 hashes and CycloneDX SBOM

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.8+ |
| Encryption | `cryptography` (ChaCha20-Poly1305, HKDF-SHA256) |
| Key Derivation | `argon2-cffi` (Argon2id), PBKDF2-HMAC-SHA256 |
| Database | SQLite (WAL mode, FTS5) via `sqlite-utils` |
| CLI Framework | `argparse` + interactive shell |
| TOTP | `pyotp` |
| Clipboard | `pyperclip` |
| Output | `rich`, `colorama`, `tabulate` |
| Dependency Lock | `pip-tools` (hashed requirements) |
| SBOM | CycloneDX |

## Installation

### Prerequisites

- Python 3.8 or higher
- pip

### Setup

```bash
# Clone the repository
git clone https://github.com/StoicGang/Sentra.git
cd Sentra

# Create and activate a virtual environment
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies (locked with integrity hashes)
pip install -r requirements.txt

# Or install as an editable package
pip install -e .
```

## Configuration

Sentra uses a `.env` file in the project root for path configuration. Copy the example or create your own:

```ini
# Path to the SQLite vault database
SENTRA_DB_PATH=data/vault.db

# Path to the SQL schema file
SENTRA_SCHEMA_PATH=data/schema.sql
```

### Environment Variables

All settings have sensible defaults. Override via `.env` or shell environment:

| Variable | Default | Description |
|---|---|---|
| `SENTRA_DB_PATH` | `data/vault.db` | Path to the vault database |
| `SENTRA_SCHEMA_PATH` | `data/schema.sql` | Path to the SQL schema |
| `SENTRA_MIN_PASSWORD_LENGTH` | `12` | Minimum password length policy |
| `SENTRA_DEFAULT_PASSWORD_LENGTH` | `16` | Default generated password length |
| `SENTRA_REVEAL_DURATION` | `10` | Seconds a password stays visible on screen |
| `SENTRA_CLIPBOARD_CLEAR` | `30` | Seconds before clipboard is auto-wiped |

## Usage

### Interactive Shell

Run without arguments to enter the interactive shell:

```bash
python main.py
```

### One-off Commands

```bash
python main.py <command> [options]
```

### CLI Reference

| Command | Description |
|---|---|
| `login` | Unlock the vault |
| `lock` | Lock the vault |
| `add` | Add a new entry (`-t` title, `-u` username, `-p` password, `-g` auto-generate) |
| `list` | List entries (`--category`, `--favorite`, `--trash`, `--totp`) |
| `get` | View entry details (`-s` timed reveal, `-c` copy to clipboard) |
| `search <query>` | Full-text search across entries |
| `update` | Update an existing entry |
| `delete` | Soft-delete an entry (`--permanent` for hard delete) |
| `restore` | Recover an entry from trash |
| `genpass` | Generate a password (`-l` length, `-c` copy) |
| `totp` | Show TOTP code (`-s` secret, `-w` watch mode) |
| `backup` | Create an encrypted backup (`-o` output path) |
| `import` | Restore from a backup file (`-i` input path) |
| `export` | Export entries to CSV (`-o` output path) |
| `vaults` | Manage vaults (list, create, remove, switch) |
| `switch` | Switch active vault |
| `recovery` | Manage recovery options (status, change, disable) |
| `forget-masterpass` | Recover access using recovery credentials |
| `status` | Show vault status and metadata |
| `audit` | View audit log (`-l` limit) |
| `security` | Run a security health check |
| `self-destruct` | Configure or trigger vault self-destruct |
| `copy` | Copy last viewed password or TOTP code |
| `config` | Application settings (`--clipboard-timeout`) |

### Examples

```bash
# First run — creates a new vault interactively
python main.py login

# Add an entry with auto-generated password
python main.py add -t "GitHub" -u "user@example.com" -g -l 24

# View entry with timed reveal (clears after 10s)
python main.py get -t "GitHub" -s

# Copy password to clipboard (auto-clears after 30s)
python main.py get -t "GitHub" -c

# Generate a standalone password
python main.py genpass -l 20 -c

# Create an encrypted backup
python main.py backup -o vault_backup.enc

# Search entries
python main.py search "github"

# View security audit log
python main.py audit -l 20
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src --cov=cli --cov-report=html

# Run a specific test file
pytest tests/test_crypto.py -v
```

### Test Coverage

The test suite covers:

- Cryptographic operations (encryption, decryption, key derivation, HMAC)
- Vault lifecycle (create, unlock, lock, state machine)
- Password generation and strength scoring
- Backup creation and restoration
- Recovery manager (passphrase and code-based)
- Secure memory (locking, zeroization)
- Secure display (timed reveal, clipboard)
- Adaptive lockout (exponential backoff, hard lockout)
- Self-destruct mechanism
- CLI commands and argument parsing

## Supply Chain Security

Sentra uses strict dependency locking and generates a Software Bill of Materials (SBOM) for compliance and integrity.

- **Updating dependencies**: Edit `requirements.in`, then compile with hashes:
  ```bash
  pip-compile --generate-hashes --allow-unsafe requirements.in
  ```
- **Regenerating the SBOM**: After dependency changes:
  ```bash
  cyclonedx-py requirements requirements.txt -o bom.json
  ```

## Security Notes

- The vault is stored locally in an encrypted SQLite database. **If you lose your master password and have no recovery credentials configured, your data cannot be recovered.**
- Secrets are handled with care: OS-level memory locking prevents swap-to-disk, keys are zeroized on lock, and clipboard contents are auto-cleared.
- Argon2id parameters are tuned for a ~2 second unlock time on modern hardware.
- Each entry uses a unique HKDF-derived key (per-entry salt), so compromising one entry does not expose others.
- Run Sentra only on a trusted machine. Do not share vault exports unless encrypted and transferred securely.

## Contributing

Contributions are welcome. Please open issues for bugs or feature requests and follow the standard pull request workflow. Add tests for new behavior.

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 StoicGang
