"""
Key Management Module - handles key generation, storage, distribution, and rotation.
System RSA keys and HMAC secrets are stored in the keys/ directory.
User ECC keys are stored in the database (private keys encrypted with RSA).
"""

import os
import json
from config import KEYS_DIR, RSA_KEY_BITS
from crypto.rsa import generate_rsa_keypair, serialize_rsa_key, deserialize_rsa_key, rsa_encrypt_string, rsa_decrypt_string
from crypto.ecc import generate_ecc_keypair, serialize_ecc_public_key, serialize_ecc_private_key, deserialize_ecc_private_key
from crypto.sha256 import sha256_hex
from crypto.hmac_custom import hmac_sha256_hex


class KeyManager:
    """Manages cryptographic keys for the system."""

    def __init__(self):
        self.rsa_public_key = None
        self.rsa_private_key = None
        self.hmac_session_key = None
        self.hmac_data_key = None
        self._ensure_keys_dir()

    def _ensure_keys_dir(self):
        os.makedirs(KEYS_DIR, exist_ok=True)

    def initialize(self):
        """Load existing keys or generate new ones."""
        rsa_path = os.path.join(KEYS_DIR, 'system_rsa.json')
        hmac_path = os.path.join(KEYS_DIR, 'hmac_keys.json')

        # Load or generate RSA keys
        if os.path.exists(rsa_path):
            print("[KeyManager] Loading existing RSA keys...")
            with open(rsa_path, 'r') as f:
                data = json.load(f)
            self.rsa_public_key = deserialize_rsa_key(data['public_key'])
            self.rsa_private_key = deserialize_rsa_key(data['private_key'])
        else:
            print(f"[KeyManager] Generating {RSA_KEY_BITS}-bit RSA key pair (this may take a moment)...")
            self.rsa_public_key, self.rsa_private_key = generate_rsa_keypair(RSA_KEY_BITS)
            with open(rsa_path, 'w') as f:
                json.dump({
                    'public_key': serialize_rsa_key(self.rsa_public_key),
                    'private_key': serialize_rsa_key(self.rsa_private_key)
                }, f)
            print("[KeyManager] RSA keys generated and saved.")

        # Load or generate HMAC keys
        if os.path.exists(hmac_path):
            with open(hmac_path, 'r') as f:
                data = json.load(f)
            self.hmac_session_key = bytes.fromhex(data['session_key'])
            self.hmac_data_key = bytes.fromhex(data['data_key'])
        else:
            print("[KeyManager] Generating HMAC keys...")
            self.hmac_session_key = os.urandom(32)
            self.hmac_data_key = os.urandom(32)
            with open(hmac_path, 'w') as f:
                json.dump({
                    'session_key': self.hmac_session_key.hex(),
                    'data_key': self.hmac_data_key.hex()
                }, f)
            print("[KeyManager] HMAC keys generated and saved.")

    def generate_user_ecc_keys(self):
        """Generate a new ECC key pair for a user.
        
        Returns:
            (ecc_public_key_str, ecc_private_key_enc)
            - ecc_public_key_str: serialized public key
            - ecc_private_key_enc: RSA-encrypted serialized private key
        """
        pub, priv = generate_ecc_keypair()
        pub_str = serialize_ecc_public_key(pub)
        priv_str = serialize_ecc_private_key(priv)

        # Encrypt private key with system RSA
        priv_enc = rsa_encrypt_string(priv_str, self.rsa_public_key)

        return pub_str, priv_enc

    def decrypt_user_ecc_private_key(self, ecc_private_key_enc):
        """Decrypt a user's ECC private key using system RSA."""
        priv_str = rsa_decrypt_string(ecc_private_key_enc, self.rsa_private_key)
        return deserialize_ecc_private_key(priv_str)

    def encrypt_user_data(self, plaintext):
        """Encrypt user data (profile fields) with system RSA."""
        return rsa_encrypt_string(plaintext, self.rsa_public_key)

    def decrypt_user_data(self, ciphertext):
        """Decrypt user data with system RSA."""
        return rsa_decrypt_string(ciphertext, self.rsa_private_key)

    def hash_for_lookup(self, value):
        """Create a SHA-256 hash of a value for database lookup."""
        return sha256_hex(value.encode('utf-8'))

    def hash_password(self, password, salt):
        """Hash a password with salt using SHA-256."""
        return sha256_hex(salt.encode('utf-8') + password.encode('utf-8'))

    def compute_data_hmac(self, *fields):
        """Compute HMAC over concatenated fields for integrity verification."""
        combined = '|'.join(str(f) for f in fields)
        return hmac_sha256_hex(self.hmac_data_key, combined.encode('utf-8'))

    def verify_data_hmac(self, expected_hmac, *fields):
        """Verify data integrity HMAC."""
        computed = self.compute_data_hmac(*fields)
        # Constant-time comparison
        if len(computed) != len(expected_hmac):
            return False
        result = 0
        for a, b in zip(computed.encode(), expected_hmac.encode()):
            result |= a ^ b
        return result == 0

    def sign_session_token(self, token):
        """Sign a session token with HMAC."""
        return hmac_sha256_hex(self.hmac_session_key, token.encode('utf-8'))

    def rotate_rsa_keys(self):
        """Rotate system RSA keys. Returns old keys for re-encryption."""
        old_public = self.rsa_public_key
        old_private = self.rsa_private_key

        print(f"[KeyManager] Generating new {RSA_KEY_BITS}-bit RSA key pair...")
        self.rsa_public_key, self.rsa_private_key = generate_rsa_keypair(RSA_KEY_BITS)

        # Save new keys
        rsa_path = os.path.join(KEYS_DIR, 'system_rsa.json')
        with open(rsa_path, 'w') as f:
            json.dump({
                'public_key': serialize_rsa_key(self.rsa_public_key),
                'private_key': serialize_rsa_key(self.rsa_private_key)
            }, f)

        # Archive old keys
        archive_path = os.path.join(KEYS_DIR, f'system_rsa_old_{sha256_hex(os.urandom(8))[:8]}.json')
        with open(archive_path, 'w') as f:
            json.dump({
                'public_key': serialize_rsa_key(old_public),
                'private_key': serialize_rsa_key(old_private)
            }, f)

        print("[KeyManager] RSA keys rotated successfully.")
        return old_public, old_private

    def rotate_hmac_keys(self):
        """Rotate HMAC keys. Old keys returned for any re-verification needed.
        WARNING: all existing HMACs computed with old keys will no longer verify.
        """
        old_session_key = self.hmac_session_key
        old_data_key = self.hmac_data_key

        print("[KeyManager] Generating new HMAC keys...")
        self.hmac_session_key = os.urandom(32)
        self.hmac_data_key = os.urandom(32)

        hmac_path = os.path.join(KEYS_DIR, 'hmac_keys.json')

        # Archive old HMAC keys
        archive_path = os.path.join(KEYS_DIR, f'hmac_keys_old_{sha256_hex(os.urandom(8))[:8]}.json')
        with open(archive_path, 'w') as f:
            json.dump({
                'session_key': old_session_key.hex(),
                'data_key': old_data_key.hex()
            }, f)

        # Save new HMAC keys
        with open(hmac_path, 'w') as f:
            json.dump({
                'session_key': self.hmac_session_key.hex(),
                'data_key': self.hmac_data_key.hex()
            }, f)

        print("[KeyManager] HMAC keys rotated successfully.")
        return old_session_key, old_data_key


# Singleton instance
key_manager = KeyManager()
