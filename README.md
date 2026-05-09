# Sentra

A local-first password manager with a modular CLI. Sentra stores secrets in a local SQLite database protected by Argon2id key derivation and ChaCha20-Poly1305 authenticated encryption. Designed with a focus on local operation, cryptographic standards, and audibility.

## Features

- **Encrypted Secrets** — Passwords and notes are protected by ChaCha20-Poly1305 AEAD encryption with per-entry HKDF key isolation. *(Note: Titles, URLs, and Usernames remain plaintext for searchability).*
- **Interactive CLI shell** — Drop into an interactive session or run one-off commands.
- **Password Generation** — Generator with strength scoring, dictionary checks, and keyboard pattern detection.
- **TOTP Support** — Generate and manage time-based one-time passwords.
- **Multi-Vault Management** — Create, switch between, and manage multiple independent vaults.
- **Encrypted Backup & Restore** — HMAC-verified, versioned backups encrypted with keys derived from the master key.
- **Account Recovery** — Passphrase-based or one-time recovery codes to regain access if the master password is lost.
- **Interactive Rate Limiting** — Application-level exponential backoff prevents rapid manual password guessing at the CLI.
- **Best-Effort Key Memory Protection** — Uses OS-level memory locking (`VirtualLock`/`mlock`) to protect active master key buffers from swapping to disk.
- **Timed Secret Display** — Visually hides passwords from the terminal screen after a duration, and auto-clears standard OS clipboards.
- **Vault Deletion** — Configurable trigger to delete the database file after N failed interactive attempts.
- **Soft Delete & Restore** — Deleted entries go to trash before permanent removal.
- **Audit Logging** — Vault operations (unlock, create, update, delete) are logged internally.
- **Full-Text Search** — FTS5-powered search across unencrypted entry metadata.
- **Supply Chain Security** — Locked dependencies with SHA-256 hashes and CycloneDX SBOM.

## Threat Model & Limitations

Sentra is designed to protect your secrets at rest against offline extraction, assuming the attacker does not have your master password. However, it is critical to understand its limitations to make informed security decisions:

- **Plaintext Metadata:** To enable fast full-text searching (via SQLite FTS5), entry Titles, URLs, Usernames, and Tags are stored in **plaintext**. An attacker with access to your `vault.db` file can see which services you use, even without the master password.
- **Offline Brute-Force:** The interactive lockout feature only protects against manual guessing at the CLI. If an attacker copies your `vault.db` file to their own machine, the lockout is bypassed. Your defense against offline attacks relies entirely on the strength of your Master Password against Argon2id.
- **Malware & Keyloggers:** Sentra runs in user-space. It does not protect against OS-level keyloggers, screen scrapers, or advanced malware that can dump Python process memory.
- **Memory Protection Limits:** While Sentra makes a best-effort attempt to lock the master key buffer in memory, Python is a managed language. Immutable byte strings and individual passwords may still reside in standard memory and be subject to garbage collection unpredictability.
- **Clipboard & Terminal History:** The clipboard auto-clear feature sends an empty string, but this may not erase secrets from OS-level clipboard managers (like Windows Clipboard History `Win+V` or macOS clipboard managers). Terminal erasure may also not clear scrollback buffers depending on your terminal emulator.
- **Vault Deletion Forensics:** The auto-destruct feature performs a standard file deletion (`os.remove`). It does not securely overwrite disk sectors. Due to wear-leveling on modern SSDs, deleted databases may be highly recoverable via forensic tools.
- **CSV Exports:** Using the export feature produces an absolute plaintext CSV file. Ensure this file is used only temporarily and is not synced to insecure cloud storage.

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
| `export` | Export entries to CSV (Warning: Plaintext) |
| `vaults` | Manage vaults (list, create, remove, switch) |
| `switch` | Switch active vault |
| `recovery` | Manage recovery options (status, change, disable) |
| `forget-masterpass` | Recover access using recovery credentials |
| `status` | Show vault status and metadata |
| `audit` | View audit log (`-l` limit) |
| `security` | Run a security health check |
| `self-destruct` | Configure or trigger vault deletion |
| `copy` | Copy last viewed password or TOTP code |
| `config` | Application settings (`--clipboard-timeout`) |

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src --cov=cli --cov-report=html
```

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

## Security Notes & Backups

- **Backup Encryption:** The backup encryption key is derived directly from the live vault's master encryption key. Backups do not use a separate password. If you lose your master password (and have no recovery codes), you also permanently lose the ability to decrypt your backups.
- **Key Derivation:** Argon2id parameters are tuned to provide offline brute-force resistance while aiming for a ~2 second unlock time on modern hardware.
- **Entry Isolation:** Each encrypted entry uses a unique HKDF-derived key (per-entry salt).
- **Environment Context:** Run Sentra only on a trusted machine. Do not share vault exports unless encrypted and transferred securely.

## Contributing

Contributions are welcome. Please open issues for bugs or feature requests and follow the standard pull request workflow. Add tests for new behavior.

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 StoicGang
