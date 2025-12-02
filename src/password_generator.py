"""
Sentra Password Generator

Generates high-entropy passwords with configurable length and character sets.
Uses cryptographically secure randomness (secrets).
"""

from typing import Dict, Tuple, Set
import string
import secrets
import math

COMMON_PASSWORDS = {"password", "123456", "qwerty", "letmein", "admin", "welcome"}
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

class PasswordGenerator:
    """
    Password generator with configurable complexity.

    Responsibilities:
        - high-entropy passwords
        - guaranteed inclusion of uppercase, lowercase, digits, and symbols
        - cryptographically secure randomness (secrets)
        - vault-unique passwords (if provided with a used_passwords set)
    """

    FULL_CHARSETS = [
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        SPECIAL_CHARS,
    ]

    def __init__(self, min_length: int = 12, max_length: int = 64):
        """
        Initialize password generator with length constraints.

        Args:
            min_length: Minimum allowed length for generated passwords.
            max_length: Maximum allowed length for generated passwords.
        """
        self.min_length = min_length
        self.max_length = max_length

    def _generate_strong_password(self, length: int) -> Tuple[str, str]:
        RULE_MIN = 8

        if length < RULE_MIN:
            raise ValueError(f"Password length must be at least {RULE_MIN}.")
        if length > self.max_length:
            raise ValueError(f"Password length must not exceed {self.max_length}.")

        warning_message = ""
        if RULE_MIN <= length < 12:
            warning_message = (
                "Warning: Password length less than 12 may be insecure. "
                "Consider using 12 or more characters."
            )

        # guaranteed characters
        required = [secrets.choice(s) for s in self.FULL_CHARSETS]

        # fill the rest
        all_chars = "".join(self.FULL_CHARSETS)
        remaining = length - len(required)

        generated = required + [secrets.choice(all_chars) for _ in range(remaining)]
        secrets.SystemRandom().shuffle(generated)

        return "".join(generated), warning_message

    def generate_password(
        self,
        length: int = 16,
        used_passwords: Set[str] = None,
    ) -> Tuple[str, str]:
        """
        Generates a high-quality, unique password.

        If used_passwords is provided, ensures the generated password
        does not match an existing one (vault uniqueness).
        """

        if used_passwords is None:
            used_passwords = set()

        # Keep generating until unique
        while True:
            pwd, warn = self._generate_strong_password(length)
            if pwd not in used_passwords:
                return pwd, warn
    
    def calculate_strength(self, password:str) -> Tuple[int, str, Dict]:
        """
        Evaluate password strength.

        Args:
            password: The password string to evaluate.

        Returns:
            score (int): 0-100 strength score
            label (str): Strength label
            diagnostics (Dict): Detailed components of scoring, e.g. entropy_bits, deductions
        """

        diagnostics: Dict[str, object] = {}
        length = len(password)
        lower_pw = password.lower()

        charset_size = 0
        if any (c.islower() for c in password):
            charset_size += len(string.ascii_lowercase)
        if any (c.isupper() for c in password):
            charset_size += len(string.ascii_uppercase)
        if any (c.isdigit() for c in password):
            charset_size += len(string.digits)
        if any(c in SPECIAL_CHARS for c in password):
            charset_size += len(SPECIAL_CHARS)

        diagnostics['charset_size'] = charset_size
        diagnostics["length"] = length

        # Entropy calculation
        entropy_bits = length * math.log2(charset_size) if charset_size else 0
        diagnostics["entropy_bits"] = round(entropy_bits, 2)

        # repeated deductions
        repeat_deductions = sum(
            2 for i in range(1, length) if password[i] == password[i - 1]
        )

        # continuous block check
        sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789"]
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in lower_pw:
                    repeat_deductions += 5

        diagnostics['repeat_deductions'] = repeat_deductions

        dictionary_matches = [word for word in COMMON_PASSWORDS if word in lower_pw]
        diagnostics['dictionary_matches'] = dictionary_matches 

        # base score
        base_score = min(100, int(entropy_bits))  # 0–100

        # final score
        deductions = repeat_deductions + (10 * len(dictionary_matches))
        diagnostics["deductions"] = deductions

        score = max(0, min(100, base_score - deductions))
        diagnostics["final_score"] = score

        if score < 30:
            label = "Weak"
        elif score < 50:
            label = "Fair"
        elif score < 75:
            label = "Good"
        elif score < 90:
            label = "Strong"
        else:
            label = "Very Strong"

        return score, label, diagnostics