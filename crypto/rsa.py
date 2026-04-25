"""
RSA encryption - implemented entirely from scratch.
No use of any built-in cryptographic libraries.
Uses custom prime generation, modular arithmetic, and big integer operations.
"""

from .utils import generate_prime, mod_inverse, secure_randbelow


def generate_rsa_keypair(bits=1024):
    """Generate an RSA key pair.
    
    Returns:
        (public_key, private_key) where:
        public_key = (e, n)
        private_key = (d, n)
    """
    half_bits = bits // 2

    # Generate two distinct large primes
    p = generate_prime(half_bits)
    q = generate_prime(half_bits)
    while q == p:
        q = generate_prime(half_bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Public exponent
    e = 65537

    # Ensure e and phi are coprime
    from .utils import gcd
    if gcd(e, phi) != 1:
        # Very unlikely with e=65537, regenerate if it happens
        return generate_rsa_keypair(bits)

    # Private exponent
    d = mod_inverse(e, phi)

    return (e, n), (d, n)


def rsa_encrypt_int(m, public_key):
    """Encrypt a single integer m using RSA public key."""
    e, n = public_key
    if m < 0 or m >= n:
        raise ValueError("Message integer must be in range [0, n)")
    return pow(m, e, n)


def rsa_decrypt_int(c, private_key):
    """Decrypt a single integer c using RSA private key."""
    d, n = private_key
    return pow(c, d, n)


def rsa_encrypt_string(plaintext, public_key):
    """Encrypt a string using RSA with chunking.
    
    Prepends a 4-byte length header, pads to chunk boundaries,
    encrypts each chunk as an integer, returns hex-encoded chunks joined by ':'.
    """
    e, n = public_key
    key_size = (n.bit_length() + 7) // 8
    chunk_size = key_size - 1  # Ensure each chunk < n

    data = plaintext.encode('utf-8')
    # Prepend 4-byte length
    data = len(data).to_bytes(4, 'big') + data

    # Pad to multiple of chunk_size
    remainder = len(data) % chunk_size
    if remainder != 0:
        data += b'\x00' * (chunk_size - remainder)

    # Encrypt each chunk
    encrypted_chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        m = int.from_bytes(chunk, 'big')
        c = rsa_encrypt_int(m, (e, n))
        # Encode as fixed-width hex
        hex_str = format(c, '0' + str(key_size * 2) + 'x')
        encrypted_chunks.append(hex_str)

    return ':'.join(encrypted_chunks)


def rsa_decrypt_string(ciphertext, private_key):
    """Decrypt an RSA-encrypted string."""
    d, n = private_key
    key_size = (n.bit_length() + 7) // 8
    chunk_size = key_size - 1

    chunks = ciphertext.split(':')
    decrypted = b''

    for chunk_hex in chunks:
        c = int(chunk_hex, 16)
        m = rsa_decrypt_int(c, (d, n))
        decrypted += m.to_bytes(chunk_size, 'big')

    # Extract original length from first 4 bytes
    original_len = int.from_bytes(decrypted[:4], 'big')
    return decrypted[4:4 + original_len].decode('utf-8')


def serialize_rsa_key(key):
    """Serialize an RSA key (public or private) to a string for storage."""
    first, n = key
    return f"{hex(first)}:{hex(n)}"


def deserialize_rsa_key(key_str):
    """Deserialize an RSA key from a string."""
    parts = key_str.split(':')
    return (int(parts[0], 16), int(parts[1], 16))
