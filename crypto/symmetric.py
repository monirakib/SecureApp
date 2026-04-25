"""
Symmetric encryption using XOR with SHA-256 CTR-mode keystream.
Used for hybrid encryption of documents.
"""

import os
from crypto.sha256 import sha256_hex


def generate_symmetric_key():
    """Generate a random 32-byte symmetric key."""
    return os.urandom(32)


def sha256_bytes(data):
    """SHA-256 hash returning bytes."""
    return bytes.fromhex(sha256_hex(data))


def encrypt_symmetric(data: bytes, key: bytes) -> bytes:
    """Encrypt data using XOR with SHA-256 CTR-mode keystream."""
    keystream = b''
    counter = 0
    while len(keystream) < len(data):
        block_input = key + counter.to_bytes(8, 'big')
        block = sha256_bytes(block_input)
        keystream += block
        counter += 1
    return bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))


def decrypt_symmetric(data: bytes, key: bytes) -> bytes:
    """Decrypt data (XOR is its own inverse)."""
    return encrypt_symmetric(data, key)
