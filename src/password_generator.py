"""
Sentra Password Generator

Generates high-entropy passwords with configurable length and character sets.
Uses cryptographically secure randomness (secrets).
"""

from typing import Dict, Tuple, Set, Optional, List
import string
import re
import secrets
import math
import os
import warnings

BASE_PATTERNS = {
    "password", "123456", "qwerty", "letmein", "admin", "welcome", "sentra",
    "login", "master", "access", "secret", "football", "baseball", "dragon",
    "summer", "winter", "autumn", "spring", "sunshine", "monkey", "charlie",
    "love", "iloveyou", "superman", "batman", "jesus", "god"
}
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

MAX_ENTROPY_LEN = 256 
RULE_MIN = 8

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

    KEYBOARD_PATTERNS = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",  # QWERTY
        "1234567890",                          # Digits top row
        "qazwsxedc", "plokijuhy"               # Vertical/Diagonal
    ]

    def __init__(self, min_length: int = 12, max_length: int = 64, dict_path: str = "data/common_passwords.txt"):
        """
        Initialize password generator with length constraints.

        Args:
            min_length: Minimum allowed length for generated passwords.
            max_length: Maximum allowed length for generated passwords.
        """
        self.min_length = min_length
        self.max_length = max_length

        self.common_passwords = set()
        self._load_dictionary(dict_path)

    def _load_dictionary(self, path: str):
        """
        Load common passwords from a text file into memory.
        """
        try:
            if not os.path.isabs(path):
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                path = os.path.join(base_dir, path)

            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word = line.strip().lower()
                        if len(word) > 3:
                            self.common_passwords.add(word)

                self.dictionary_loaded = True
                self.dictionary_size = len(self.common_passwords)

            else:
                self.dictionary_loaded = False
                self.dictionary_size = 0
                warnings.warn(
                    f"Password dictionary not found at {path}. "
                    "Password strength evaluation is degraded.",
                    RuntimeWarning
                )

        except Exception as e:
            self.dictionary_loaded = False
            self.dictionary_size = 0
            warnings.warn(
                f"Password dictionary failed to load ({e}). "
                "Password strength evaluation is degraded.",
                RuntimeWarning
            )


    def _generate_strong_password(self, length: int) -> Tuple[str, str]:
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
            
    def _levenshtein_distance(self, s1: str, s2: str, max_dist: int = None) -> int:
        """
        Calculates edit distance (inserts, deletes, substitutions) between two strings.
        Used for fuzzy matching against dictionary words and user inputs.
        """
        if max_dist is not None and abs(len(s1) - len(s2)) > max_dist:
            return max_dist + 1

        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
            
        previous_row = list(range(len(s2) + 1))

        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            min_in_row = current_row[0]

            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                val = min(insertions, deletions, substitutions)
                current_row.append(val)
                min_in_row = min(min_in_row, val)

            if max_dist is not None and min_in_row > max_dist:
                return max_dist + 1  # early abort

            previous_row = current_row

        return previous_row[-1]
    
    def calculate_strength(self, password:str, user_inputs: Optional[List[str]] = None) -> Tuple[int, str, Dict]:
        diagnostics: Dict[str, object] = {}
        length = len(password)
        lower_pw = password.lower()

        # 1. Entropy Calculation
        charset_size = 0
        if any(c.islower() for c in password): charset_size += 26
        if any(c.isupper() for c in password): charset_size += 26
        if any(c.isdigit() for c in password): charset_size += 10
        if any(c in SPECIAL_CHARS for c in password): charset_size += len(SPECIAL_CHARS)

        diagnostics['charset_size'] = charset_size
        diagnostics["length"] = length

        effective_length = min(length, MAX_ENTROPY_LEN)

        entropy_bits = (
            effective_length * math.log2(charset_size)
            if charset_size > 0 else 0
        )
        diagnostics["entropy_bits"] = round(entropy_bits, 2)

        # 2. Penalty Calculation (Running Total)
        deductions = 0

        # A. Repeats
        repeat_deductions = sum(2 for i in range(1, length) if password[i] == password[i - 1])
        deductions += repeat_deductions
        diagnostics['repeat_deductions'] = repeat_deductions

        # B. Sequential (abc, 123)
        sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789"]
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in lower_pw:
                    deductions += 5  # FIX: Add to main deductions
                    diagnostics.setdefault("weak_patterns", []).append("sequential")

        # C. Keyboard Patterns
        for pat in self.KEYBOARD_PATTERNS:
            for i in range(len(pat) - 2):
                fragment = pat[i:i+3]
                rev_fragment = fragment[::-1]
                if fragment in lower_pw or rev_fragment in lower_pw:
                    deductions += 10
                    diagnostics.setdefault("weak_patterns", []).append(f"keyboard ({fragment})")

        # D. Date Patterns
        if re.search(r'(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])', password) or \
           re.search(r'(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19|20)\d{2}', password):
             deductions += 25
             diagnostics.setdefault("weak_patterns", []).append("date_pattern")

        # FIX: Add check for isolated Years (1900-2099)
        elif re.search(r'(19|20)\d{2}', password):
             deductions += 15
             diagnostics.setdefault("weak_patterns", []).append("year_pattern")

        # E. Alternating Patterns
        if re.search(r'(.{2,})\1', password):
             deductions += 10
             diagnostics.setdefault("weak_patterns", []).append("alternating_pattern")

        # F. Common Substitutions (Leet Speak)
        subs = {'@': 'a', '0': 'o', '3': 'e', '1': 'i', '$': 's', '!': 'i', '4': 'a'}
        normalized = lower_pw
        for char, repl in subs.items():
            normalized = normalized.replace(char, repl)
        
        # Check against common passwords
        # Layer 1: Exact check against MASSIVE external list (O(1) lookup)
        # Catches "dragon123", "password123" if they are in the loaded file
        if normalized in self.common_passwords or lower_pw in self.common_passwords:
            deductions += 40
            diagnostics.setdefault("dictionary_matches", []).append("COMMON_LEAK_LIST")

        # Layer 2: Fuzzy check against SMALL internal list
        # Catches "P@ssw0rd!" (variations of base words)
        for word in BASE_PATTERNS:
            threshold = 1 if len(word) < 5 else 2
            if word in normalized or self._levenshtein_distance(normalized, word, threshold) <= threshold:
                deductions += 25
                diagnostics.setdefault("dictionary_matches", []).append(word)

        if user_inputs:
            for input_word in user_inputs:
                if not input_word or len(input_word) < 3: continue
                input_norm = input_word.lower()
                
                # Check fuzzy match against user info
                threshold = 1 if len(input_norm) < 5 else 2
                if input_norm in normalized or self._levenshtein_distance(normalized, input_norm, threshold) <= threshold:
                    deductions += 30  # Heavy penalty for using own name/email
                    diagnostics.setdefault("context_matches", []).append(input_word)

        # 3. Final Scoring
        base_score = min(100, int(entropy_bits))
        
        # FIX: Do not overwrite 'deductions'. Use the running total calculated above.
        diagnostics["deductions"] = deductions

        score = max(0, min(100, base_score - deductions))
        diagnostics["final_score"] = score

        if score < 40: label = "Weak"
        elif score < 60: label = "Fair"
        elif score < 75: label = "Good"
        elif score < 90: label = "Strong"
        else: label = "Very Strong"

        return score, label, diagnostics