"""
HMAC-SHA256 - implemented from scratch using custom SHA-256.
No use of hmac module or any built-in MAC libraries.
"""

from .sha256 import sha256

BLOCK_SIZE = 64  # SHA-256 block size in bytes


def hmac_sha256(key, message):
    """Compute HMAC-SHA256. Returns 32 bytes.
    
    HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
    where K' is the key padded/hashed to block size.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(message, str):
        message = message.encode('utf-8')

    # If key is longer than block size, hash it
    if len(key) > BLOCK_SIZE:
        key = sha256(key)

    # Pad key to block size
    if len(key) < BLOCK_SIZE:
        key = key + b'\x00' * (BLOCK_SIZE - len(key))

    # Inner and outer padding
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)

    # HMAC = H(opad || H(ipad || message))
    inner_hash = sha256(ipad + message)
    return sha256(opad + inner_hash)


def hmac_sha256_hex(key, message):
    """Compute HMAC-SHA256 and return as hex string."""
    return hmac_sha256(key, message).hex()


def verify_hmac(key, message, expected_tag):
    """Verify HMAC tag using constant-time comparison."""
    if isinstance(expected_tag, str):
        expected_tag = expected_tag.encode()

    computed = hmac_sha256_hex(key, message)
    if isinstance(computed, str):
        computed = computed.encode()

    # Constant-time comparison
    if len(computed) != len(expected_tag):
        return False
    result = 0
    for a, b in zip(computed, expected_tag):
        result |= a ^ b
    return result == 0
