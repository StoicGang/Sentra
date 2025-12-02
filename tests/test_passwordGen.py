import pytest
from src.password_generator import PasswordGenerator, SPECIAL_CHARS


def test_generate_password_default():
    pg = PasswordGenerator()

    pwd, warn = pg.generate_password()

    # length correct
    assert len(pwd) == 16

    # warning: should be empty because length=16 >= 12
    assert warn == ""

    # must contain all required classes
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in SPECIAL_CHARS for c in pwd)


def test_generate_short_password_warning():
    pg = PasswordGenerator()

    pwd, warn = pg.generate_password(length=10)

    assert len(pwd) == 10
    assert "Warning" in warn   # must warn for < 12


def test_generate_password_minimum_enforced():
    pg = PasswordGenerator(min_length=12)

    # Still must block below RULE_MIN (8)
    with pytest.raises(ValueError):
        pg.generate_password(length=7)

    # But lengths between 8–11 should be allowed
    pwd, warn = pg.generate_password(length=8)
    assert len(pwd) == 8
    assert "Warning" in warn


def test_generate_password_maximum_enforced():
    pg = PasswordGenerator(max_length=32)

    with pytest.raises(ValueError):
        pg.generate_password(length=40)


def test_unique_password_generation():
    pg = PasswordGenerator()

    used = {"ABCdef123!@", "XyZ987!!lkj"}

    pwd, _ = pg.generate_password(used_passwords=used)

    # must not be inside used set
    assert pwd not in used


def test_inclusion_of_all_charsets_even_if_length_small():
    pg = PasswordGenerator()

    # Minimum length must be >= 12 by default, so set custom lower bound
    pg = PasswordGenerator(min_length=8)

    pwd, _ = pg.generate_password(length=8)

    # must contain all 4 categories
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in SPECIAL_CHARS for c in pwd)


def test_strength_weak_common_password():
    pg = PasswordGenerator()

    score, label, diag = pg.calculate_strength("password")

    assert label == "Weak"
    assert score < 30
    assert "password" in diag["dictionary_matches"]


def test_strength_strong_password():
    pg = PasswordGenerator()

    pwd = "Xy!9$Lp#vOd7QwRt"

    score, label, diag = pg.calculate_strength(pwd)

    assert score > 75
    assert label in ("Strong", "Very Strong")


def test_strength_repeated_characters():
    pg = PasswordGenerator()

    score, label, diag = pg.calculate_strength("aaaBBB111!!!")

    assert diag["repeat_deductions"] > 0
    assert label != "Very Strong"

if __name__ == "__main__":
    test_generate_password_default()
    test_generate_password_maximum_enforced()
    test_generate_password_minimum_enforced()
    test_generate_short_password_warning()
    test_inclusion_of_all_charsets_even_if_length_small()
    test_unique_password_generation()
    test_strength_strong_password()
    test_strength_repeated_characters()
    test_strength_weak_common_password()