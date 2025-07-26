"""Unit tests for password functionality."""

import pytest
from app.core.password import (
    hash_password,
    verify_password,
    validate_password,
    calculate_password_strength,
    generate_secure_password,
    needs_rehash,
    PasswordPolicy,
    password_policy,
)


class TestPasswordHashing:
    """Test password hashing functionality."""

    @pytest.mark.unit
    def test_hash_password(self):
        """Test password hashing."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        assert hashed != password
        assert len(hashed) > 50  # Argon2 hashes are long
        assert hashed.startswith("$argon2")

    @pytest.mark.unit
    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) is True

    @pytest.mark.unit
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        password = "TestPassword123!"
        wrong_password = "WrongPassword123!"
        hashed = hash_password(password)
        
        assert verify_password(wrong_password, hashed) is False

    @pytest.mark.unit
    def test_verify_password_invalid_hash(self):
        """Test password verification with invalid hash."""
        password = "TestPassword123!"
        invalid_hash = "invalid-hash"
        
        assert verify_password(password, invalid_hash) is False

    @pytest.mark.unit
    def test_needs_rehash(self):
        """Test password rehash detection."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Fresh hash should not need rehashing
        assert needs_rehash(hashed) is False


class TestPasswordPolicy:
    """Test password policy validation."""

    @pytest.mark.unit
    def test_valid_password(self):
        """Test validation of valid password."""
        password = "ValidPassword123!"
        errors = validate_password(password)
        
        assert errors == []

    @pytest.mark.unit
    def test_password_too_short(self):
        """Test validation of too short password."""
        password = "Short1!"
        errors = validate_password(password)
        
        assert len(errors) > 0
        assert any("at least" in error for error in errors)

    @pytest.mark.unit
    def test_password_too_long(self):
        """Test validation of too long password."""
        password = "A" * 200 + "1!"
        errors = validate_password(password)
        
        assert len(errors) > 0
        assert any("exceed" in error for error in errors)

    @pytest.mark.unit
    def test_password_no_uppercase(self):
        """Test validation of password without uppercase."""
        password = "nouppercase123!"
        errors = validate_password(password)
        
        assert len(errors) > 0
        assert any("uppercase" in error for error in errors)

    @pytest.mark.unit
    def test_password_no_lowercase(self):
        """Test validation of password without lowercase."""
        password = "NOLOWERCASE123!"
        errors = validate_password(password)
        
        assert len(errors) > 0
        assert any("lowercase" in error for error in errors)

    @pytest.mark.unit
    def test_password_no_digits(self):
        """Test validation of password without digits."""
        password = "NoDigitsHere!"
        errors = validate_password(password)
        
        assert len(errors) > 0
        assert any("digit" in error for error in errors)

    @pytest.mark.unit
    def test_password_no_special_chars(self):
        """Test validation of password without special characters."""
        password = "NoSpecialChars123"
        errors = validate_password(password)
        
        assert len(errors) > 0
        assert any("special" in error for error in errors)

    @pytest.mark.unit
    def test_password_contains_username(self):
        """Test validation of password containing username."""
        password = "MyUsernamePassword123!"
        username = "myusername"
        errors = validate_password(password, username)
        
        assert len(errors) > 0
        assert any("username" in error for error in errors)

    @pytest.mark.unit
    def test_common_password_patterns(self):
        """Test validation of common password patterns."""
        common_passwords = [
            "password123!",
            "Password123!",
            "123456789!",
            "qwerty123!",
            "admin123!",
        ]
        
        for password in common_passwords:
            errors = validate_password(password)
            assert len(errors) > 0
            assert any("common patterns" in error for error in errors)

    @pytest.mark.unit
    def test_empty_password(self):
        """Test validation of empty password."""
        password = ""
        errors = validate_password(password)
        
        assert len(errors) > 0
        assert any("required" in error for error in errors)

    @pytest.mark.unit
    def test_none_password(self):
        """Test validation of None password."""
        password = None
        errors = validate_password(password)
        
        assert len(errors) > 0
        assert any("required" in error for error in errors)


class TestPasswordStrength:
    """Test password strength calculation."""

    @pytest.mark.unit
    def test_strong_password_score(self):
        """Test strong password gets high score."""
        password = "VeryStrongP@ssw0rd2024!"
        result = calculate_password_strength(password)
        
        assert result["score"] >= 80
        assert result["label"] in ["Good", "Strong"]
        assert result["is_valid"] is True
        assert result["errors"] == []

    @pytest.mark.unit
    def test_weak_password_score(self):
        """Test weak password gets low score."""
        password = "weak"
        result = calculate_password_strength(password)
        
        assert result["score"] < 50
        assert result["label"] in ["Very Weak", "Weak"]
        assert result["is_valid"] is False
        assert len(result["errors"]) > 0

    @pytest.mark.unit
    def test_medium_password_score(self):
        """Test medium password gets medium score."""
        password = "MediumPass123"
        result = calculate_password_strength(password)
        
        assert 30 <= result["score"] <= 80
        assert result["label"] in ["Weak", "Fair", "Good"]

    @pytest.mark.unit
    def test_empty_password_score(self):
        """Test empty password gets zero score."""
        password = ""
        result = calculate_password_strength(password)
        
        assert result["score"] == 0
        assert result["label"] == "Very Weak"
        assert result["is_valid"] is False


class TestPasswordGeneration:
    """Test secure password generation."""

    @pytest.mark.unit
    def test_generate_secure_password_default_length(self):
        """Test generating secure password with default length."""
        password = generate_secure_password()
        
        assert len(password) == 16
        assert validate_password(password) == []  # Should pass all validations

    @pytest.mark.unit
    def test_generate_secure_password_custom_length(self):
        """Test generating secure password with custom length."""
        length = 24
        password = generate_secure_password(length)
        
        assert len(password) == length
        assert validate_password(password) == []  # Should pass all validations

    @pytest.mark.unit
    def test_generate_secure_password_contains_all_types(self):
        """Test generated password contains all character types."""
        password = generate_secure_password()
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*" for c in password)
        
        assert has_upper
        assert has_lower
        assert has_digit
        assert has_special

    @pytest.mark.unit
    def test_generate_secure_password_uniqueness(self):
        """Test that generated passwords are unique."""
        passwords = [generate_secure_password() for _ in range(10)]
        
        # All passwords should be unique
        assert len(set(passwords)) == len(passwords)


class TestPasswordPolicyClass:
    """Test PasswordPolicy class functionality."""

    @pytest.mark.unit
    def test_password_policy_initialization(self):
        """Test password policy initialization."""
        policy = PasswordPolicy()
        
        assert policy.min_length >= 8
        assert policy.max_length >= policy.min_length
        assert isinstance(policy.require_uppercase, bool)
        assert isinstance(policy.require_lowercase, bool)
        assert isinstance(policy.require_digits, bool)
        assert isinstance(policy.require_special, bool)

    @pytest.mark.unit
    def test_calculate_strength_score_edge_cases(self):
        """Test strength score calculation edge cases."""
        policy = PasswordPolicy()
        
        # Empty password
        assert policy.calculate_strength_score("") == 0
        
        # Very long strong password
        long_password = "VeryLongAndComplexP@ssw0rd!" * 3
        score = policy.calculate_strength_score(long_password)
        assert score >= 80

    @pytest.mark.unit
    def test_repetitive_characters_detection(self):
        """Test detection of repetitive characters."""
        policy = PasswordPolicy()
        
        # Password with repetitive characters
        repetitive_password = "Aaaa1234!"
        assert policy._has_repetitive_chars(repetitive_password) is True
        
        # Password with sequences
        sequence_password = "Abc1234!"
        assert policy._has_repetitive_chars(sequence_password) is True
        
        # Good password
        good_password = "GoodP@ssw0rd!"
        assert policy._has_repetitive_chars(good_password) is False

    @pytest.mark.unit
    def test_common_pattern_detection(self):
        """Test detection of common patterns."""
        policy = PasswordPolicy()
        
        common_patterns = [
            "password123",
            "123456789",
            "qwertyuiop",
            "admin123",
            "letmein123",
        ]
        
        for pattern in common_patterns:
            assert policy._is_common_pattern(pattern) is True
        
        # Good password should not match common patterns
        assert policy._is_common_pattern("UniqueP@ssw0rd2024!") is False

    @pytest.mark.unit
    def test_strength_labels(self):
        """Test strength label assignment."""
        policy = PasswordPolicy()
        
        assert policy.get_strength_label(10) == "Very Weak"
        assert policy.get_strength_label(40) == "Weak"
        assert policy.get_strength_label(60) == "Fair"
        assert policy.get_strength_label(75) == "Good"
        assert policy.get_strength_label(90) == "Strong"


class TestPasswordPolicyGlobal:
    """Test global password policy instance."""

    @pytest.mark.unit
    def test_global_password_policy_exists(self):
        """Test that global password policy instance exists."""
        assert password_policy is not None
        assert isinstance(password_policy, PasswordPolicy)

    @pytest.mark.unit
    def test_global_password_policy_methods(self):
        """Test global password policy methods work."""
        password = "TestPassword123!"
        
        errors = password_policy.validate(password)
        assert isinstance(errors, list)
        
        score = password_policy.calculate_strength_score(password)
        assert isinstance(score, int)
        assert 0 <= score <= 100
        
        label = password_policy.get_strength_label(score)
        assert isinstance(label, str)