"""
security.py

Uses bcrypt directly — no passlib (passlib is incompatible with bcrypt 4.x).
Flow: SHA-256(password) → bcrypt hash
"""

import hashlib
import bcrypt


def normalize_password(password: str) -> bytes:
    """
    SHA-256 hash the password and return as bytes.
    Output is always 32 bytes — well under bcrypt's 72-byte limit.
    """
    return hashlib.sha256(password.encode("utf-8")).digest()  # 32 raw bytes


def hash_password(password: str) -> str:
    """
    Hash password safely: SHA-256 → bcrypt
    Returns a string for storing in the database.
    """
    safe = normalize_password(password)
    hashed = bcrypt.hashpw(safe, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password using the same SHA-256 → bcrypt transformation.
    """
    safe = normalize_password(plain_password)
    return bcrypt.checkpw(safe, hashed_password.encode("utf-8"))