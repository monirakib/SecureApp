"""
Elliptic Curve Cryptography (ECC) with ElGamal encryption - implemented from scratch.
Uses the secp256k1 curve. No built-in crypto libraries.

ElGamal on ECC:
  Key gen: private key d, public key Q = d*G
  Encrypt point M: random k, C1 = k*G, C2 = M + k*Q
  Decrypt: M = C2 - d*C1

Message-to-point mapping uses the Koblitz method.
"""

from .utils import secure_randbelow, mod_inverse

# secp256k1 curve parameters
# Curve equation: y^2 = x^3 + 7 (mod p)
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Koblitz encoding factor
KOBLITZ_K = 100

# Maximum bytes per chunk for Koblitz encoding
# x = m * K + j must be < p, so m < p / K
# p is 256 bits, K=100 ~7 bits, so m can be ~249 bits = 31 bytes
# Use 30 bytes for safety margin
ECC_CHUNK_SIZE = 30


class ECPoint:
    """A point on an elliptic curve. Point at infinity has x=None, y=None."""

    def __init__(self, x=None, y=None):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        if other is None:
            return self.is_infinity()
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "ECPoint(INF)"
        return f"ECPoint({hex(self.x)}, {hex(self.y)})"


# Point at infinity (identity element)
POINT_INF = ECPoint()

# Generator point
G = ECPoint(SECP256K1_GX, SECP256K1_GY)

p = SECP256K1_P
a_coeff = SECP256K1_A
b_coeff = SECP256K1_B
n = SECP256K1_N


def point_add(P, Q):
    """Add two points on secp256k1."""
    if P.is_infinity():
        return ECPoint(Q.x, Q.y) if not Q.is_infinity() else ECPoint()
    if Q.is_infinity():
        return ECPoint(P.x, P.y)

    if P.x == Q.x:
        if P.y != Q.y:
            # P + (-P) = O
            return ECPoint()
        else:
            # Point doubling
            return point_double(P)

    # Different points
    lam = ((Q.y - P.y) * mod_inverse(Q.x - P.x, p)) % p
    x_r = (lam * lam - P.x - Q.x) % p
    y_r = (lam * (P.x - x_r) - P.y) % p
    return ECPoint(x_r, y_r)


def point_double(P):
    """Double a point on secp256k1."""
    if P.is_infinity():
        return ECPoint()
    if P.y == 0:
        return ECPoint()

    # For secp256k1, a=0, so: lambda = 3*x^2 / (2*y)
    lam = ((3 * P.x * P.x + a_coeff) * mod_inverse(2 * P.y, p)) % p
    x_r = (lam * lam - 2 * P.x) % p
    y_r = (lam * (P.x - x_r) - P.y) % p
    return ECPoint(x_r, y_r)


def scalar_multiply(k, P):
    """Multiply a point by a scalar using double-and-add method."""
    if k == 0 or P.is_infinity():
        return ECPoint()

    if k < 0:
        k = -k
        P = ECPoint(P.x, (-P.y) % p)

    result = ECPoint()  # Point at infinity
    addend = ECPoint(P.x, P.y)

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1

    return result


def point_negate(P):
    """Negate a point on the curve."""
    if P.is_infinity():
        return ECPoint()
    return ECPoint(P.x, (-P.y) % p)


def is_on_curve(P):
    """Check if a point is on secp256k1."""
    if P.is_infinity():
        return True
    left = (P.y * P.y) % p
    right = (P.x * P.x * P.x + a_coeff * P.x + b_coeff) % p
    return left == right


def mod_sqrt(val, prime):
    """Compute modular square root. For secp256k1, p ≡ 3 (mod 4)."""
    # Since p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4) mod p
    return pow(val, (prime + 1) // 4, prime)


def koblitz_encode(data_int):
    """Encode an integer as a point on secp256k1 using Koblitz method."""
    for j in range(KOBLITZ_K):
        x = data_int * KOBLITZ_K + j
        if x >= p:
            return None

        # Compute y^2 = x^3 + ax + b mod p
        y_sq = (pow(x, 3, p) + a_coeff * x + b_coeff) % p

        # Check if quadratic residue using Euler's criterion
        if pow(y_sq, (p - 1) // 2, p) == 1:
            y = mod_sqrt(y_sq, p)
            point = ECPoint(x, y)
            if is_on_curve(point):
                return point

    return None


def koblitz_decode(point):
    """Decode a curve point back to an integer."""
    return point.x // KOBLITZ_K


def generate_ecc_keypair():
    """Generate an ECC key pair on secp256k1.
    
    Returns:
        (public_key: ECPoint, private_key: int)
    """
    # Private key: random integer in [1, n-1]
    private_key = 1 + secure_randbelow(n - 1)
    # Public key: Q = d * G
    public_key = scalar_multiply(private_key, G)
    return public_key, private_key


def ecc_encrypt_point(M, public_key):
    """Encrypt a point M using ElGamal on ECC.
    
    Args:
        M: ECPoint to encrypt
        public_key: ECPoint (Q = d*G)
    
    Returns:
        (C1, C2) tuple of ECPoints
    """
    k = 1 + secure_randbelow(n - 1)
    C1 = scalar_multiply(k, G)
    C2 = point_add(M, scalar_multiply(k, public_key))
    return C1, C2


def ecc_decrypt_point(C1, C2, private_key):
    """Decrypt an ElGamal-encrypted point.
    
    M = C2 - d*C1
    """
    dC1 = scalar_multiply(private_key, C1)
    neg_dC1 = point_negate(dC1)
    M = point_add(C2, neg_dC1)
    return M


def ecc_encrypt_string(plaintext, public_key):
    """Encrypt a string using ECC ElGamal with Koblitz encoding and chunking.
    
    Returns a hex-encoded string of encrypted chunks.
    Format: c1x,c1y,c2x,c2y;c1x,c1y,c2x,c2y;...
    Prepends 4-byte length header to handle padding.
    """
    data = plaintext.encode('utf-8')
    # Prepend 4-byte length
    data = len(data).to_bytes(4, 'big') + data

    # Pad to multiple of chunk size
    remainder = len(data) % ECC_CHUNK_SIZE
    if remainder != 0:
        data += b'\x00' * (ECC_CHUNK_SIZE - remainder)

    encrypted_chunks = []

    for i in range(0, len(data), ECC_CHUNK_SIZE):
        chunk = data[i:i + ECC_CHUNK_SIZE]
        chunk_int = int.from_bytes(chunk, 'big')

        # Encode as curve point
        M = koblitz_encode(chunk_int)
        if M is None:
            raise ValueError("Failed to encode chunk as curve point")

        # Encrypt
        C1, C2 = ecc_encrypt_point(M, public_key)

        # Serialize: c1x,c1y,c2x,c2y
        chunk_str = f"{hex(C1.x)},{hex(C1.y)},{hex(C2.x)},{hex(C2.y)}"
        encrypted_chunks.append(chunk_str)

    return ';'.join(encrypted_chunks)


def ecc_decrypt_string(ciphertext, private_key):
    """Decrypt an ECC ElGamal-encrypted string."""
    chunks = ciphertext.split(';')
    decrypted = b''

    for chunk_str in chunks:
        parts = chunk_str.split(',')
        c1x, c1y, c2x, c2y = [int(x, 16) for x in parts]

        C1 = ECPoint(c1x, c1y)
        C2 = ECPoint(c2x, c2y)

        # Decrypt
        M = ecc_decrypt_point(C1, C2, private_key)

        # Decode from curve point
        chunk_int = koblitz_decode(M)

        # Convert back to bytes
        byte_len = ECC_CHUNK_SIZE
        decrypted += chunk_int.to_bytes(byte_len, 'big')

    # Extract original length
    original_len = int.from_bytes(decrypted[:4], 'big')
    return decrypted[4:4 + original_len].decode('utf-8')


def serialize_ecc_public_key(point):
    """Serialize an ECC public key point to a string."""
    return f"{hex(point.x)}:{hex(point.y)}"


def deserialize_ecc_public_key(key_str):
    """Deserialize an ECC public key from a string."""
    parts = key_str.split(':')
    return ECPoint(int(parts[0], 16), int(parts[1], 16))


def serialize_ecc_private_key(key_int):
    """Serialize an ECC private key integer to a hex string."""
    return hex(key_int)


def deserialize_ecc_private_key(key_str):
    """Deserialize an ECC private key from a hex string."""
    return int(key_str, 16)
