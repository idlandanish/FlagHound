"""
Crypto subpackage for FlagHound v2.0
Provides cryptographic utilities including encoding/decoding and cipher solving.
"""

from .affine import mod_inverse, decrypt_affine, bruteforce_affine

__all__ = [
    'mod_inverse',
    'decrypt_affine',
    'bruteforce_affine',
]
