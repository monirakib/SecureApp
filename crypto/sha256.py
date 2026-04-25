"""
SHA-256 hash function - implemented entirely from scratch.
No use of hashlib or any built-in hash libraries.
"""

# Initial hash values: first 32 bits of the fractional parts of the square roots of the first 8 primes
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

MASK32 = 0xFFFFFFFF


def _rotr(x, n):
    """Right rotate a 32-bit integer by n bits."""
    return ((x >> n) | (x << (32 - n))) & MASK32


def _shr(x, n):
    """Right shift a 32-bit integer by n bits."""
    return x >> n


def _ch(x, y, z):
    return (x & y) ^ (~x & z) & MASK32


def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0(x):
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _sigma1(x):
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _gamma0(x):
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _gamma1(x):
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


def _pad_message(message):
    """Pad message according to SHA-256 spec.
    Append bit '1', then zeros, then 64-bit big-endian original length in bits.
    Total length must be multiple of 64 bytes (512 bits).
    """
    msg_len = len(message)
    bit_len = msg_len * 8

    # Append 0x80 (bit '1' followed by seven '0' bits)
    message += b'\x80'

    # Pad with zeros until length ≡ 56 (mod 64)
    while len(message) % 64 != 56:
        message += b'\x00'

    # Append original message length as 64-bit big-endian
    message += bit_len.to_bytes(8, 'big')

    return message


def sha256(message):
    """Compute SHA-256 hash of a byte string. Returns 32 bytes."""
    if isinstance(message, str):
        message = message.encode('utf-8')

    # Pre-processing: pad message
    padded = _pad_message(bytearray(message))

    # Initialize hash values
    h0, h1, h2, h3, h4, h5, h6, h7 = H_INIT

    # Process each 64-byte (512-bit) block
    for block_start in range(0, len(padded), 64):
        block = padded[block_start:block_start + 64]

        # Prepare message schedule W[0..63]
        W = []
        for i in range(16):
            W.append(int.from_bytes(block[i * 4:(i + 1) * 4], 'big'))

        for i in range(16, 64):
            s0 = _gamma0(W[i - 15])
            s1 = _gamma1(W[i - 2])
            W.append((W[i - 16] + s0 + W[i - 7] + s1) & MASK32)

        # Initialize working variables
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        # Compression function: 64 rounds
        for i in range(64):
            T1 = (h + _sigma1(e) + _ch(e, f, g) + K[i] + W[i]) & MASK32
            T2 = (_sigma0(a) + _maj(a, b, c)) & MASK32
            h = g
            g = f
            f = e
            e = (d + T1) & MASK32
            d = c
            c = b
            b = a
            a = (T1 + T2) & MASK32

        # Update hash values
        h0 = (h0 + a) & MASK32
        h1 = (h1 + b) & MASK32
        h2 = (h2 + c) & MASK32
        h3 = (h3 + d) & MASK32
        h4 = (h4 + e) & MASK32
        h5 = (h5 + f) & MASK32
        h6 = (h6 + g) & MASK32
        h7 = (h7 + h) & MASK32

    # Produce the final hash value (big-endian)
    digest = b''
    for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
        digest += val.to_bytes(4, 'big')

    return digest


def sha256_hex(message):
    """Compute SHA-256 hash and return as hex string."""
    return sha256(message).hex()
