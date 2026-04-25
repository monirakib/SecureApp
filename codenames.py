"""Generate random anonymous codenames for whistleblower submissions."""

import os

ADJECTIVES = [
    'Silent', 'Shadow', 'Ghost', 'Iron', 'Steel', 'Dark', 'Swift', 'Brave',
    'Hidden', 'Cyber', 'Phantom', 'Rogue', 'Storm', 'Frost', 'Echo',
    'Viper', 'Apex', 'Neon', 'Onyx', 'Cipher', 'Crimson', 'Azure',
    'Obsidian', 'Quantum', 'Void', 'Nova', 'Zero', 'Omega', 'Delta', 'Helix'
]

NOUNS = [
    'Hawk', 'Fox', 'Wolf', 'Eagle', 'Raven', 'Tiger', 'Bear', 'Cobra',
    'Falcon', 'Lynx', 'Owl', 'Panther', 'Shark', 'Phoenix', 'Dragon',
    'Sphinx', 'Griffin', 'Hydra', 'Sentinel', 'Warden', 'Specter',
    'Oracle', 'Nexus', 'Vertex', 'Prism', 'Aegis', 'Wraith', 'Tempest'
]


def generate_codename():
    """Generate a random codename like 'SilentHawk-7291'."""
    adj_idx = int.from_bytes(os.urandom(1), 'big') % len(ADJECTIVES)
    noun_idx = int.from_bytes(os.urandom(1), 'big') % len(NOUNS)
    num = int.from_bytes(os.urandom(2), 'big') % 10000
    return f"{ADJECTIVES[adj_idx]}{NOUNS[noun_idx]}-{num:04d}"
