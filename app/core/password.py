"""Password hashing and validation utilities using Passlib with Argon2."""

import re
from typing import List, Optional

from passlib.context import CryptContext
from passlib.hash import argon2

from app.config.settings import settings


# Configure password context with Argon2
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64 MB
    argon2__time_cost=3,        # 3 iterations
    argon2__parallelism=1,      # 1 thread
    argon2__hash_len=32,        # 32 byte hash
)


class PasswordPolicy:
    """Password policy validation and enforcement."""

    def __init__(self):
        self.min_length = settings.PASSWORD_MIN_LENGTH
        self.max_length = settings.PASSWORD_MAX_LENGTH
        self.require_uppercase = settings.PASSWORD_REQUIRE_UPPERCASE
        self.require_lowercase = settings.PASSWORD_REQUIRE_LOWERCASE
        self.require_digits = settings.PASSWORD_REQUIRE_DIGITS
        self.require_special = settings.PASSWORD_REQUIRE_SPECIAL

    def validate(self, password: str, username: Optional[str] = None) -> List[str]:
        """
        Validate password against policy requirements.
        
        Args:
            password: Password to validate
            username: Username to check against (optional)
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if not password:
            errors.append("Password is required")
            return errors

        # Length validation
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")

        if len(password) > self.max_length:
            errors.append(f"Password must not exceed {self.max_length} characters")

        # Character requirements
        if self.require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        if self.require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        if self.require_digits and not re.search(r"\d", password):
            errors.append("Password must contain at least one digit")

        if self.require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character")

        # Username similarity check
        if username and username.lower() in password.lower():
            errors.append("Password must not contain the username")

        # Common password patterns
        if self._is_common_pattern(password):
            errors.append("Password contains common patterns and is not secure")

        return errors

    def _is_common_pattern(self, password: str) -> bool:
        """
        Check for common insecure password patterns.
        
        Args:
            password: Password to check
            
        Returns:
            True if password contains common patterns
        """
        common_patterns = [
            r"^password",
            r"^123456",
            r"^qwerty",
            r"^admin",
            r"^letmein",
            r"^welcome",
            r"^monkey",
            r"^dragon",
        ]

        password_lower = password.lower()
        for pattern in common_patterns:
            if re.search(pattern, password_lower):
                return True

        # Check for keyboard patterns
        keyboard_patterns = [
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890",
        ]

        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                return True

        return False

    def calculate_strength_score(self, password: str) -> int:
        """
        Calculate password strength score (0-100).
        
        Args:
            password: Password to evaluate
            
        Returns:
            Strength score from 0 (weakest) to 100 (strongest)
        """
        if not password:
            return 0

        score = 0
        
        # Length scoring
        if len(password) >= 8:
            score += 25
        if len(password) >= 12:
            score += 15
        if len(password) >= 16:
            score += 10

        # Character variety scoring
        if re.search(r"[a-z]", password):
            score += 10
        if re.search(r"[A-Z]", password):
            score += 10
        if re.search(r"\d", password):
            score += 10
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 15

        # Bonus for character variety
        char_types = sum([
            bool(re.search(r"[a-z]", password)),
            bool(re.search(r"[A-Z]", password)),
            bool(re.search(r"\d", password)),
            bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
        ])
        
        if char_types >= 3:
            score += 5
        if char_types == 4:
            score += 10

        # Penalty for common patterns
        if self._is_common_pattern(password):
            score -= 20

        # Penalty for repetitive characters
        if self._has_repetitive_chars(password):
            score -= 10

        return max(0, min(100, score))

    def _has_repetitive_chars(self, password: str) -> bool:
        """
        Check for repetitive character patterns.
        
        Args:
            password: Password to check
            
        Returns:
            True if password has repetitive patterns
        """
        # Check for 3+ consecutive identical characters
        if re.search(r"(.)\1{2,}", password):
            return True

        # Check for simple sequences
        sequences = ["abc", "123", "xyz", "789"]
        password_lower = password.lower()
        
        for seq in sequences:
            if seq in password_lower or seq[::-1] in password_lower:
                return True

        return False

    def get_strength_label(self, score: int) -> str:
        """
        Get human-readable strength label for score.
        
        Args:
            score: Password strength score
            
        Returns:
            Strength label
        """
        if score < 30:
            return "Very Weak"
        elif score < 50:
            return "Weak"
        elif score < 70:
            return "Fair"
        elif score < 85:
            return "Good"
        else:
            return "Strong"


# Global password policy instance
password_policy = PasswordPolicy()


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password to verify against
        
    Returns:
        True if password matches hash
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def validate_password(password: str, username: Optional[str] = None) -> List[str]:
    """
    Validate password against policy requirements.
    
    Args:
        password: Password to validate
        username: Username to check against (optional)
        
    Returns:
        List of validation error messages (empty if valid)
    """
    return password_policy.validate(password, username)


def calculate_password_strength(password: str) -> dict:
    """
    Calculate comprehensive password strength information.
    
    Args:
        password: Password to evaluate
        
    Returns:
        Dictionary with strength score, label, and validation errors
    """
    score = password_policy.calculate_strength_score(password)
    label = password_policy.get_strength_label(score)
    errors = password_policy.validate(password)
    
    return {
        "score": score,
        "label": label,
        "is_valid": len(errors) == 0,
        "errors": errors,
    }


def needs_rehash(hashed_password: str) -> bool:
    """
    Check if password hash needs to be updated.
    
    Args:
        hashed_password: Existing password hash
        
    Returns:
        True if hash should be updated
    """
    return pwd_context.needs_update(hashed_password)


def generate_secure_password(length: int = 16) -> str:
    """
    Generate a secure random password.
    
    Args:
        length: Desired password length
        
    Returns:
        Generated secure password
    """
    import secrets
    import string
    
    # Ensure we have all character types
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    
    # Generate password ensuring all character types are present
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*"),
    ]
    
    # Fill remaining length with random characters
    for _ in range(length - 4):
        password.append(secrets.choice(chars))
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password)
    
    return "".join(password)