import pytest
import re

from src.password_generator import (
    PasswordGenerator,
    SPECIAL_CHARS,
    BASE_PATTERNS,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pg(tmp_path):
    # Use a non-existent dictionary path to avoid filesystem dependency
    return PasswordGenerator(dict_path=str(tmp_path / "no_dict.txt"))

# ---------------------------------------------------------------------------
# Password Generation
# ---------------------------------------------------------------------------

def test_generate_password_default_length(pg):
    pwd, warn = pg.generate_password()
    assert isinstance(pwd, str)
    assert len(pwd) == 16
    assert warn == ""

def test_generate_password_custom_length(pg):
    pwd, _ = pg.generate_password(length=20)
    assert len(pwd) == 20

def test_generate_password_min_length_enforced(pg):
    with pytest.raises(ValueError):
        pg.generate_password(length=7)

def test_generate_password_max_length_enforced(pg):
    with pytest.raises(ValueError):
        pg.generate_password(length=pg.max_length + 1)

def test_generate_password_uniqueness(pg):
    used = set()
    for _ in range(5):
        pwd, _ = pg.generate_password(used_passwords=used)
        assert pwd not in used
        used.add(pwd)

def test_generated_password_has_all_char_classes(pg):
    pwd, _ = pg.generate_password(length=16)

    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in SPECIAL_CHARS for c in pwd)

def test_short_password_warning(pg):
    pwd, warn = pg.generate_password(length=8)
    assert "Warning" in warn

# ---------------------------------------------------------------------------
# Strength Calculation – Basics
# ---------------------------------------------------------------------------

def test_strength_empty_password(pg):
    score, label, diag = pg.calculate_strength("")
    assert score == 0
    assert label == "Weak"
    assert diag["entropy_bits"] == 0

def test_strength_strong_password(pg):
    pwd, _ = pg.generate_password(length=20)
    score, label, diag = pg.calculate_strength(pwd)

    assert score >= 60
    assert label in {"Good", "Strong", "Very Strong"}
    assert diag["final_score"] == score

# ---------------------------------------------------------------------------
# Repetition & Sequence Penalties
# ---------------------------------------------------------------------------

def test_repeated_characters_penalty(pg):
    pwd = "AAaaBBbb11!!"
    score, _, diag = pg.calculate_strength(pwd)
    assert diag["repeat_deductions"] > 0

def test_sequential_pattern_penalty(pg):
    pwd = "abcXYZ123!!!"
    score, _, diag = pg.calculate_strength(pwd)
    assert "weak_patterns" in diag
    assert "sequential" in diag["weak_patterns"]

# ---------------------------------------------------------------------------
# Keyboard Pattern Penalty
# ---------------------------------------------------------------------------

def test_keyboard_pattern_penalty(pg):
    pwd = "qwertyQ1!"
    score, _, diag = pg.calculate_strength(pwd)
    assert any("keyboard" in p for p in diag.get("weak_patterns", []))

# ---------------------------------------------------------------------------
# Date & Year Patterns
# ---------------------------------------------------------------------------

def test_full_date_pattern_penalty(pg):
    pwd = "Password20240101!"
    score, _, diag = pg.calculate_strength(pwd)
    assert "date_pattern" in diag.get("weak_patterns", [])

def test_year_pattern_penalty(pg):
    pwd = "Secure1999!"
    score, _, diag = pg.calculate_strength(pwd)
    assert "year_pattern" in diag.get("weak_patterns", [])

# ---------------------------------------------------------------------------
# Alternating / Repeated Substrings
# ---------------------------------------------------------------------------

def test_alternating_pattern_penalty(pg):
    pwd = "ababAB12!!"
    score, _, diag = pg.calculate_strength(pwd)
    assert "alternating_pattern" in diag.get("weak_patterns", [])

# ---------------------------------------------------------------------------
# Dictionary & Fuzzy Matching
# ---------------------------------------------------------------------------

def test_base_dictionary_match_penalty(pg):
    pwd = "P@ssw0rd!"
    score, _, diag = pg.calculate_strength(pwd)
    assert "dictionary_matches" in diag
    assert any(word in BASE_PATTERNS for word in diag["dictionary_matches"])

def test_fuzzy_dictionary_match(pg):
    pwd = "dr4g0n!!"
    score, _, diag = pg.calculate_strength(pwd)
    assert "dictionary_matches" in diag

# ---------------------------------------------------------------------------
# User Context Matching
# ---------------------------------------------------------------------------

def test_user_context_penalty(pg):
    pwd = "johnSecure!23"
    score, _, diag = pg.calculate_strength(pwd, user_inputs=["john"])
    assert "context_matches" in diag
    assert "john" in diag["context_matches"]

# ---------------------------------------------------------------------------
# Scoring Bounds & Labels
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pwd,expected", [
    ("password", "Weak"),
    ("Password123", "Weak"),  # Updated: triggers repeats, sequential, and dict
])
def test_strength_labels(pg, pwd, expected):
    score, label, _ = pg.calculate_strength(pwd)
    assert label == expected

def test_score_is_bounded(pg):
    pwd = "A" * 100
    score, _, _ = pg.calculate_strength(pwd)
    assert 0 <= score <= 100

# ---------------------------------------------------------------------------
# Diagnostics Integrity
# ---------------------------------------------------------------------------

def test_diagnostics_contains_expected_fields(pg):
    pwd, _ = pg.generate_password()
    _, _, diag = pg.calculate_strength(pwd)

    for key in [
        "entropy_bits",
        "deductions",
        "final_score",
        "charset_size",
        "length",
    ]:
        assert key in diag