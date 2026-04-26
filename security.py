"""
security.py

Fixed version:
- Avoids bcrypt 72-byte limit issue
- Still secure for project use
"""

from passlib.context import CryptContext
import hashlib

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def normalize_password(password: str) -> str:
    """
    Prevent bcrypt 72-byte issue by hashing input first.
    This ensures fixed-length safe input.
    """
    return hashlib.sha256(password.encode()).hexdigest()


def hash_password(password: str) -> str:
    """
    Hash password safely using:
    SHA-256 → bcrypt
    """
    safe_password = normalize_password(password)
    return pwd_context.hash(safe_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password using same transformation.
    """
    safe_password = normalize_password(plain_password)
    return pwd_context.verify(safe_password, hashed_password)