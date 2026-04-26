"""
crypto_engine.py

Temporary stub for testing.
Real Shamir implementation will replace this file later.
"""


def generate_shares(secret: int, k: int, n: int):
    """
    Fake share generation.
    Just for backend testing.
    """
    return [(i, secret + i) for i in range(1, n + 1)]


def reconstruct_secret(shares):
    """
    Fake reconstruction logic.
    Returns original secret.
    """
    return shares[0][1] - shares[0][0]