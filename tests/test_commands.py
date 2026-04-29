"""
tests/test_commands.py - Sentra CLI command smoke tests.
Runs every command via subprocess and checks for crashes / import errors.
Does NOT require a live vault — vault-locked commands are tested for
correct "unlock prompt" behavior, not actual vault operations.

Usage:
    python tests/test_commands.py
"""
from __future__ import annotations
import subprocess
import sys
import os

PYTHON = sys.executable
CLI = os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py")

PASS = "✓"
FAIL = "✗"
SKIP = "~"

results = []


def run(args: list[str], input_text: str = "\n") -> tuple[int, str, str]:
    """Run main.py with given args, feed input_text to stdin."""
    proc = subprocess.run(
        [PYTHON, CLI] + args,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return proc.returncode, proc.stdout, proc.stderr


def check(label: str, args: list[str], *, must_contain: str = None,
          must_not_contain: str = "Traceback", input_text: str = "\n",
          expect_code: int = None):
    """Run a command and record pass/fail."""
    try:
        code, out, err = run(args, input_text=input_text)
        combined = out + err

        fail_reason = None
        if must_not_contain and must_not_contain in combined:
            fail_reason = f"output contained '{must_not_contain}'"
        elif must_contain and must_contain not in combined:
            fail_reason = f"expected '{must_contain}' not found in output"
        elif expect_code is not None and code != expect_code:
            fail_reason = f"exit code {code}, expected {expect_code}"

        if fail_reason:
            results.append((FAIL, label, fail_reason, combined[:300]))
        else:
            results.append((PASS, label, "", ""))
    except subprocess.TimeoutExpired:
        results.append((FAIL, label, "timed out after 15s", ""))
    except Exception as e:
        results.append((FAIL, label, str(e), ""))


# ── No-auth commands ──────────────────────────────────────────────────────────

check("--help",
      ["--help"],
      must_contain="Sentra - Secure Password Manager")

check("--version",
      ["--version"],
      must_contain="")  # just no crash

check("genpass (default length)",
      ["genpass"],
      must_contain="Generated Password")

check("genpass --length 16",
      ["genpass", "--length", "16"],
      must_contain="Generated Password")

check("genpass --length 32",
      ["genpass", "--length", "32"],
      must_contain="Generated Password")

check("genpass --length 7 (too short)",
      ["genpass", "--length", "7"],
      must_contain="Length must be between")

check("genpass --length 129 (too long)",
      ["genpass", "--length", "129"],
      must_contain="Length must be between")

check("genpass --help",
      ["genpass", "--help"],
      must_contain="")

# ── Help for every subcommand ─────────────────────────────────────────────────

for cmd in [
    "login", "lock", "add", "list", "get", "search", "update",
    "delete", "restore", "totp", "backup", "import", "export",
    "vaults", "switch", "recovery", "forget-masterpass",
    "status", "audit", "security", "self-destruct", "copy", "config",
]:
    check(f"{cmd} --help", [cmd, "--help"], must_contain="")

# ── Vault-locked commands (should prompt for password, not crash) ─────────────
# We send a blank password — vault will reject it but should NOT traceback.

for cmd in ["list", "add", "get", "search", "update", "delete",
            "restore", "backup", "export", "audit", "status"]:
    check(f"{cmd} (locked, blank input)",
          [cmd],
          input_text="\n\n\n",
          must_not_contain="Traceback")

# ── Unknown command ───────────────────────────────────────────────────────────

check("unknown command",
      ["foobar"],
      must_contain="",          # just no traceback
      must_not_contain="Traceback")

# ── --no-color flag ───────────────────────────────────────────────────────────

check("--no-color genpass",
      ["--no-color", "genpass"],
      must_contain="Generated Password")

# ── Print results ─────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  SENTRA COMMAND SMOKE TESTS")
print("=" * 60)

passed = sum(1 for r in results if r[0] == PASS)
failed = sum(1 for r in results if r[0] == FAIL)

for status, label, reason, snippet in results:
    if status == PASS:
        print(f"  {PASS}  {label}")
    else:
        print(f"  {FAIL}  {label}")
        print(f"       reason : {reason}")
        if snippet:
            print(f"       output : {snippet[:200]!r}")

print("=" * 60)
print(f"  {passed} passed  |  {failed} failed  |  {len(results)} total")
print("=" * 60 + "\n")

sys.exit(0 if failed == 0 else 1)
