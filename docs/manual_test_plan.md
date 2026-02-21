# Sentra — Manual Test Plan

This document outlines the manual testing procedures for the Sentra Password Manager CLI. It covers installation, authentication, entry management, security tools, and the account recovery system.

---

## 1. Initial Setup & Onboarding

### 1.1 First-Time Launch (Vault Creation)
*   **Action:** Run `python sentra_cli.py` on a fresh system (no `vault.db`).
*   **Expected Behavior:**
    *   System welcomes user to Sentra First Time Setup.
    *   Prompts for a new master password.
    *   If password is < 12 characters, it must reject and prompt again.
    *   Prompts to confirm password (must match).
*   **Result:** Vault is created; user is immediately logged in.

### 1.2 Recovery Onboarding
*   **Action:** Complete vault creation.
*   **Expected Behavior:**
    *   System prompts to set up account recovery (Passphrase, Codes, or Skip).
    *   **Test [1] Passphrase:** Enter a recovery phrase. Should confirm setup.
    *   **Test [2] Codes:** Should generate 8 codes (XXXXX-XXXXX-XXXXX-XXXXX) and prompt the user to "print/save" them.
    *   **Test [3] Skip:** Should show a warning that "No recovery will be possible" and continue.

---

## 2. Authentication & Session Management

### 2.1 Login (Unlock)
*   **Action:** Run `sentra login`.
*   **Condition [A]:** Enter correct master password.
    *   **Result:** Success message, vault unlocked.
*   **Condition [B]:** Enter incorrect password.
    *   **Result:** Error message, prompt again (up to 3 times).

### 2.2 Lock
*   **Action:** Run `sentra lock`.
*   **Expected Behavior:**
    *   Clears the internal session key.
    *   Subsequent commands (e.g., `list`) should prompt for login first.

---

## 3. Adaptive Lockout (Brute Force Protection)

### 3.1 Soft Backoff (Delay)
*   **Action:** Enter wrong password 1, 2, and 3 times in a row.
*   **Expected Behavior:**
    *   1st fail: Successive attempt allowed immediately.
    *   2nd fail: Warns about 1s delay.
    *   3rd fail: Warns about 2s delay.

### 3.2 Hard Lockout
*   **Action:** Fail login 5 times (default threshold).
*   **Expected Behavior:**
    *   System blocks ALL login attempts for 300s (5 mins).
    *   Shows exact time remaining until next allowed attempt.
    *   Restarting the CLI should NOT bypass this (state is in DB).

---

## 4. Entry Management

### 4.1 Add Entry
*   **Action:** `sentra add --title "GitHub" --username "user" --password "pass123"`
*   **Expected Behavior:**
    *   Entry created. Audit log should record 'CREATE'.
    *   Try adding `sentra add --gen`: should generate a secure password automatically.

### 4.2 List & Search
*   **Action [A]:** `sentra list`
    *   **Result:** Shows table of all active entries.
*   **Action [B]:** `sentra search github`
    *   **Result:** Returns entry matching title/URL.

### 4.3 Get (Secure Display)
*   **Action [1] Timed Reveal:** `sentra get --title GitHub --show`
    *   **Result:** Password shown. Countdown "clears in 20s" appears. After 20s, the password line and countdown are erased from the terminal.
*   **Action [2] Clipboard Copy:** `sentra get --title GitHub --copy`
    *   **Result:** Password is in clipboard. Terminal shows "clears in 30s". After 30s, clipboard is wiped (`""`).

### 4.4 Update & Delete
*   **Action [A] Update:** `sentra update --title GitHub --password "new-pass"`
    *   **Result:** Password changed.
*   **Action [B] Delete:** `sentra delete --title GitHub`
    *   **Result:** Entry disappears from `list`. Audit log shows 'SOFT_DELETE'.

---

## 5. Account Recovery (The "Lost Password" Scenario)

### 5.1 Recovery with Passphrase
*   **Action:** `sentra recover`, choose 'passphrase'.
*   **Steps:** Enter correct recovery phrase → Enter NEW master password.
*   **Expected Behavior:**
    *   Vault metadata updated with new Master Key (Argon2id).
    *   Vault unlocks. Previous master password no longer works.

### 5.2 Recovery with One-Time Code
*   **Action:** `sentra recover`, choose 'code'.
*   **Steps:** Enter one of the 8 codes → Enter NEW master password.
*   **Expected Behavior:**
    *   Success.
    *   **Crucial Test:** Try using the SAME code again. It must be rejected (one-time use enforced).

---

## 6. Maintenance & Backups

### 6.1 Encrypted Backup
*   **Action:** `sentra backup -o my_backup.sen`
*   **Result:** Compressed, encrypted binary file created. Content is unreadable with Notepad.

### 6.2 Import
*   **Action:** Create a new empty vault → `sentra import -i my_backup.sen`
*   **Result:** Entries from backup are merged into current vault.

### 6.3 Export (Plaintext Warning)
*   **Action:** `sentra export -o data.csv`
*   **Expected Behavior:**
    *   System shows "DANGER: Plaintext export" warning.
    *   Requires confirmation.
    *   CSV contains all secrets (use with extreme caution).

---

## 7. Performance & Cleanup Test

### 7.1 Security Audit
*   **Action:** `sentra audit`
    *   **Result:** Shows chronological list of every CREATE, UPDATE, DELETE action.

### 7.2 Security Health Check
*   **Action:** `sentra security`
    *   **Result:** Scans for:
        *   Weak/Short passwords.
        *   Duplicate passwords across entries.
        *   Entries missing 2FA (TOTP) secrets.

---

## 8. Self-Destruct (Emergency Data Wipe)

### 8.1 Configuration
*   **Action:** `sentra self-destruct --threshold 3`
    *   **Result:** Error (requires unlock). Log in first, then set.
*   **Action:** `sentra self-destruct --status`
    *   **Result:** Shows status (Enabled/Disabled) and threshold.

### 8.2 Automatic Trigger
*   **Action:** Fail login 3 times (wait for backoff delays in between).
*   **Expected Behavior:** 
    *   On the 3rd fail, terminal shows a large alert: **CRITICAL SECURITY ALERT: VAULT DESTROYED**.
    *   `vault.db` file is physically gone from the folder.
    *   Application exits immediately.

### 8.3 Manual Trigger
*   **Action:** `sentra self-destruct`
*   **Steps:** 
    1.  Enter Master Password.
    2.  Prompt: "Type 'DESTROY'": Enter 'DESTROY'.
    3.  Prompt: "Type 'YES DELETE EVERYTHING'": Enter it.
*   **Expected Behavior:** Vault is wiped immediately. Audit log is gone. No recovery is possible.
