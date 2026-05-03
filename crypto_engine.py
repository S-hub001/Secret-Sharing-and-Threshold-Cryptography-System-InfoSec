"""
  Shamir's Secret Sharing — Cryptographic Engine
  Crypto Engine Lead
  Finite Field Arithmetic + Share Generation + Lagrange Interpolation
"""

import secrets
import hashlib
from typing import List, Tuple

#  FINITE FIELD PRIME
#  P = 2^256 - 189  (large safe prime for GF(P))
P = 2**256 - 189


#  STEP 1 — FINITE FIELD ARITHMETIC

def mod_add(a: int, b: int) -> int:
    """Addition in GF(P)"""
    return (a + b) % P


def mod_sub(a: int, b: int) -> int:
    """Subtraction in GF(P)"""
    return (a - b) % P


def mod_mul(a: int, b: int) -> int:
    """Multiplication in GF(P)"""
    return (a * b) % P


def mod_inv(a: int) -> int:
    """
    Modular inverse using Fermat's Little Theorem.
    Since P is prime: a^(-1) ≡ a^(P-2) mod P
    """
    if a % P == 0:
        raise ValueError("No modular inverse for zero.")
    return pow(a, P - 2, P)


def mod_div(a: int, b: int) -> int:
    """Division in GF(P): a / b = a * b^(-1) mod P"""
    return mod_mul(a, mod_inv(b))


#  STEP 2 — SHARE GENERATION

def _secret_to_int(secret: bytes) -> int:
    """Convert secret bytes → integer. Must fit inside GF(P)."""
    value = int.from_bytes(secret, byteorder='big')
    if value >= P:
        raise ValueError(
            f"Secret too large for field. Max {P.bit_length()} bits."
        )
    return value


def _int_to_secret(value: int, length: int) -> bytes:
    """Convert integer back → bytes of original length."""
    return value.to_bytes(length, byteorder='big')


def _eval_polynomial(coeffs: List[int], x: int) -> int:
    """
    Evaluate polynomial at x using Horner's method (efficient).
    coeffs[0] = secret (constant term)
    coeffs[1..k-1] = random coefficients
    f(x) = c0 + c1*x + c2*x^2 + ... mod P
    """
    result = 0
    for coeff in reversed(coeffs):
        result = mod_add(mod_mul(result, x), coeff)
    return result


def generate_shares(
    secret: bytes,
    k: int,
    n: int
) -> List[Tuple[int, int]]:
    """
    Split a secret into n shares where any k can reconstruct it.

    Args:
        secret : The secret as bytes (e.g. an AES key)
        k      : Minimum threshold to reconstruct
        n      : Total number of shares to generate

    Returns:
        List of (x, y) share tuples — one per shareholder
    """
    if k < 2:
        raise ValueError("Threshold k must be at least 2.")
    if n < k:
        raise ValueError("Total shares n must be >= threshold k.")
    if not secret:
        raise ValueError("Secret cannot be empty.")

    secret_int = _secret_to_int(secret)

    # Build polynomial: f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
    coeffs = [secret_int] + [secrets.randbelow(P) for _ in range(k - 1)]

    # Generate n shares: (x, f(x)) for x = 1 to n
    shares = []
    for x in range(1, n + 1):
        y = _eval_polynomial(coeffs, x)
        shares.append((x, y))

    return shares


#  STEP 3 — RECONSTRUCTION (LAGRANGE INTERPOLATION)

def reconstruct_secret(
    shares: List[Tuple[int, int]],
    secret_length: int = 32          # ← DEFAULT ADDED: AES-256 = 32 bytes
) -> bytes:
    """
    Reconstruct the secret from k or more shares using Lagrange interpolation.

    Formula (evaluated at x=0):
        S = Σ [ y_j * L_j(0) ]  mod P

    Where:
        L_j(0) = Π [ x_m / (x_m - x_j) ]  for m ≠ j,  all mod P

    Args:
        shares        : List of (x, y) tuples
        secret_length : Original byte length of the secret (default 32 for AES-256)

    Returns:
        Reconstructed secret as bytes
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to reconstruct.")

    # Check for duplicate x values
    x_values = [s[0] for s in shares]
    if len(x_values) != len(set(x_values)):
        raise ValueError("Duplicate shares detected. Aborting reconstruction.")

    secret_int = 0

    for j, (x_j, y_j) in enumerate(shares):
        # Compute Lagrange basis L_j(0)
        numerator   = 1
        denominator = 1

        for m, (x_m, _) in enumerate(shares):
            if m == j:
                continue
            # L_j(0) uses x=0: factor = x_m / (x_m - x_j)
            numerator   = mod_mul(numerator,   x_m)
            denominator = mod_mul(denominator, mod_sub(x_m, x_j))

        lagrange_basis = mod_div(numerator, denominator)
        secret_int = mod_add(secret_int, mod_mul(y_j, lagrange_basis))

    return _int_to_secret(secret_int, secret_length)


#  HELPERS — Useful for API layer

def generate_random_secret(byte_length: int = 32) -> bytes:
    """Generate a cryptographically secure random secret."""
    return secrets.token_bytes(byte_length)


def hash_secret(secret: bytes) -> str:
    """SHA-256 fingerprint of the secret (for verification without revealing it)."""
    return hashlib.sha256(secret).hexdigest()


def verify_reconstruction(original: bytes, reconstructed: bytes) -> bool:
    """Constant-time comparison to verify reconstruction succeeded."""
    if len(original) != len(reconstructed):
        return False
    result = 0
    for a, b in zip(original, reconstructed):
        result |= a ^ b
    return result == 0