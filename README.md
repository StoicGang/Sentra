# Sentra — CLI & Web Password Manager

Sentra is a secure, local-first password manager. It provides a robust command-line interface and a modern web dashboard for managing your encrypted vault. It features strong crypto primitives, password generation, TOTP support, and secure session management.

**Key features**
- **Encrypted vault** using strong crypto primitives (see [src/crypto_engine.py](src/crypto_engine.py)).
- **Web Dashboard** with a modern React interface ([web/frontend/](web/frontend/)).
- **Password generation** with strength scoring ([src/password_generator.py](src/password_generator.py)).
- **TOTP** generation and management ([src/totp_generator.py](src/totp_generator.py)).
- **Adaptive lockout** and secure in-memory handling ([src/adaptive_lockout.py](src/adaptive_lockout.py), [src/secure_memory.py](src/secure_memory.py)).
- **Backup / import / export** utilities and basic audit tooling.

**Quick Links**
- Web Launch: [sentra_web.py](sentra_web.py)
- CLI entry: [sentra_cli.py](sentra_cli.py)
- Core modules: [src/crypto_engine.py](src/crypto_engine.py), [src/vault_controller.py](src/vault_controller.py)
- Tests: [tests/](tests/)

## Installation

### Python Backend & CLI
Recommended: create a virtual environment and install with pip.

```bash
python -m venv .venv
source .venv/bin/activate   # on Windows: .venv\Scripts\activate
pip install -U pip
pip install -e .[dev]       # editable install
```

Dependencies include `cryptography`, `argon2-cffi`, `pyotp`, `fastapi`, and `uvicorn`.

### Web Frontend (Development)
The frontend requires Node.js (v18+) and npm.

```bash
cd web/frontend
npm install
```

## Usage

Run the CLI directly for interactive use:

```bash
python sentra_cli.py --help
```

Typical commands (handled by the CLI dispatcher in `sentra_cli.py`):
- `add` — add a new entry (title, username, password, notes)
- `list` — list entries with pagination and filters
- `get` — show a single entry (safely)
- `update` — update an existing entry
- `delete` — delete an entry (confirmation required)
- `search` — search entries
- `genpass` — generate a password with strength feedback
- `totp` — show/generate TOTP codes for an entry
- `backup` / `import` / `export` — vault backup and data import/export
- `audit` / `security` — run basic auditing and security checks
- `lock` — lock the vault

The CLI includes a guided first-time setup flow that creates the encrypted vault.

## Examples

Create a new entry interactively:

```bash
python sentra_cli.py add
```

Generate a strong password from the CLI:

```bash
python sentra_cli.py genpass --length 20 --symbols
```

Export vault data (encrypted or csv, as supported):

```bash
python sentra_cli.py export --format csv --out vault_export.csv
```

## Development

- Run tests with `pytest`:

```bash
pytest -q
```

- Tests live in the `tests/` directory and cover crypto, storage, CLI flows, and utilities.

## Supply Chain Security

Sentra implements strict dependency locking and generates a Software Bill of Materials (SBOM) for compliance and integrity.

- **Updating Dependencies**: We use `pip-tools`. To add or update a package, edit `requirements.in` and run:
  ```bash
  pip-compile --generate-hashes requirements.in
  ```
- **Generating SBOM**: To regenerate the Electronic SBOM (`bom.json`) after dependency changes, run:
  ```bash
  cyclonedx-py requirements requirements.txt -o bom.json
  ```

## Security notes

- The project stores secrets locally in an encrypted vault. Choose a strong master password — it cannot be recovered if lost.
- Secrets are handled with care (secure memory, adaptive lockout) but you should still run on a trusted machine.
- Do not share vault exports unless encrypted and transferred securely.

## Contributing

Contributions welcome. Please open issues for bugs or feature requests and follow typical pull request workflow. Add tests for new behavior.
