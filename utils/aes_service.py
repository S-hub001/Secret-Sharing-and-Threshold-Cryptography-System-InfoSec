"""
aes_service.py

Handles:
- AES-256 key generation
- AES-GCM encryption
- AES-GCM decryption
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_aes_key():
    """
    Generate secure 256-bit AES key.
    """
    return os.urandom(32)


def encrypt_data(data: bytes, key: bytes):
    """
    Encrypt data using AES-GCM.
    Returns:
    - ciphertext
    - nonce
    - tag
    """
    nonce = os.urandom(12)

    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, nonce, encryptor.tag


def decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):
    """
    Decrypt AES-GCM encrypted data.
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()