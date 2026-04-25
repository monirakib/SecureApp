"""
Cryptographic utility functions - implemented from scratch.
Provides modular arithmetic, prime generation, and other primitives.
"""

import os


def secure_random_bytes(n):
    """Generate n cryptographically secure random bytes."""
    return os.urandom(n)


def secure_random_int(bits):
    """Generate a random integer with the specified number of bits."""
    byte_count = (bits + 7) // 8
    rand_bytes = os.urandom(byte_count)
    rand_int = int.from_bytes(rand_bytes, 'big')
    # Ensure exactly 'bits' bits by setting the top bit
    rand_int |= (1 << (bits - 1))
    # Mask to exactly 'bits' bits
    rand_int &= (1 << bits) - 1
    return rand_int


def secure_randbelow(n):
    """Generate a cryptographically secure random integer in [0, n)."""
    if n <= 0:
        raise ValueError("n must be positive")
    byte_length = (n.bit_length() + 7) // 8 + 1
    while True:
        rand_bytes = os.urandom(byte_length)
        rand_int = int.from_bytes(rand_bytes, 'big')
        if rand_int < n:
            return rand_int


def gcd(a, b):
    """Greatest common divisor using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """Extended Euclidean algorithm. Returns (gcd, x, y) where ax + by = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a, m):
    """Modular multiplicative inverse of a mod m."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist (gcd={g})")
    return x % m


# First 200 small primes for quick divisibility checks
SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
    163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
    251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347,
    349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
    443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643,
    647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751,
    757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
    863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977,
    983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063,
    1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
    1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223
]


def is_probably_prime(n, k=20):
    """Miller-Rabin primality test with k rounds."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Check small primes
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Miller-Rabin rounds
    for _ in range(k):
        a = 2 + secure_randbelow(n - 3)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits):
    """Generate a random prime number with the specified number of bits."""
    while True:
        candidate = secure_random_int(bits)
        candidate |= 1  # Make odd
        if is_probably_prime(candidate):
            return candidate


def int_to_bytes(n, length=None):
    """Convert a non-negative integer to bytes (big-endian)."""
    if n == 0:
        b = b'\x00'
    else:
        byte_len = (n.bit_length() + 7) // 8
        b = n.to_bytes(byte_len, 'big')
    if length is not None:
        if len(b) < length:
            b = b'\x00' * (length - len(b)) + b
    return b


def bytes_to_int(b):
    """Convert bytes to a non-negative integer (big-endian)."""
    return int.from_bytes(b, 'big')


def constant_time_compare(a, b):
    """Constant-time comparison to prevent timing attacks."""
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
