"""
Affine Cipher Module for FlagHound v2.0
Implements decryption and bruteforce for Affine Ciphers (Linear Congruential Ciphers).

The affine cipher encrypts bytes as: cipher_byte = (a * plain_byte + b) % 256
To decrypt: plain_byte = (mod_inverse(a, 256) * (cipher_byte - b)) % 256

Note: mod_inverse(a, 256) only exists if gcd(a, 256) == 1 (i.e., a must be odd).
"""

import math
from typing import Dict, List, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed


def mod_inverse(a: int, m: int) -> int | None:
    """
    Calculate the modular multiplicative inverse of a modulo m using Extended Euclidean Algorithm.
    
    Returns x such that (a * x) % m == 1, or None if no inverse exists.
    
    Args:
        a: The number to find the inverse of
        m: The modulus
        
    Returns:
        The modular inverse if it exists, None otherwise
    """
    if math.gcd(a, m) != 1:
        return None
    
    # Extended Euclidean Algorithm
    def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
        """Returns (gcd, x, y) such that a*x + b*y = gcd"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    _, x, _ = extended_gcd(a % m, m)
    return (x % m + m) % m  # Ensure positive result


def decrypt_affine(data: bytes, a: int, b: int) -> bytes:
    """
    Decrypt data encrypted with an affine cipher.
    
    Applies the decryption formula: p = (mod_inverse(a, 256) * (c - b)) % 256
    
    Args:
        data: The encrypted byte string
        a: The multiplier key (must be coprime with 256, i.e., odd)
        b: The additive key (0-255)
        
    Returns:
        The decrypted byte string
        
    Raises:
        ValueError: If a is not coprime with 256 (i.e., a is even)
    """
    if math.gcd(a, 256) != 1:
        raise ValueError(f"Invalid key 'a={a}': must be coprime with 256 (odd number)")
    
    inv_a = mod_inverse(a, 256)
    if inv_a is None:
        raise ValueError(f"Cannot compute modular inverse for a={a}")
    
    # Apply decryption formula to each byte
    result = bytearray(len(data))
    for i, c in enumerate(data):
        p = (inv_a * (c - b)) % 256
        result[i] = p
    
    return bytes(result)


def _bruteforce_worker(args: tuple[bytes, int, int]) -> Dict | None:
    """
    Worker function for parallel bruteforce processing.
    
    Args:
        args: Tuple of (data, a, b)
        
    Returns:
        Dict with decryption result and score, or None if invalid/low score
    """
    data, a, b = args
    
    # Import here to avoid circular imports in multiprocessing
    from ..crypto_module import score_english
    
    try:
        decrypted = decrypt_affine(data, a, b)
        text = decrypted.decode('utf-8', errors='ignore')
        score = score_english(text)
        
        if score > 0:  # Only return if there's some English-like content
            return {
                'a': a,
                'b': b,
                'result': text,
                'score': score
            }
    except Exception:
        pass
    
    return None


def bruteforce_affine(data: bytes, min_score: float = 0.7) -> List[Dict]:
    """
    Bruteforce all valid (a, b) pairs for an affine cipher.
    
    Iterates through all valid keys:
    - a: 1-255, odd numbers only (coprime with 256)
    - b: 0-255
    
    Uses scoring to identify likely plaintext candidates.
    
    Args:
        data: The encrypted byte string
        min_score: Minimum English frequency score threshold (default: 0.7)
        
    Returns:
        List of successful attempts sorted by score (descending):
        [{'a': int, 'b': int, 'result': str, 'score': float}, ...]
    """
    results: List[Dict] = []
    
    # Generate all valid (a, b) pairs
    # a must be odd (coprime with 256), so we iterate 1, 3, 5, ..., 255
    valid_keys = [(a, b) for a in range(1, 256, 2) for b in range(256)]
    
    # For small datasets or when parallel overhead isn't worth it, use simple loop
    # Otherwise use ProcessPoolExecutor
    use_parallel = len(data) > 1000 and len(valid_keys) > 100
    
    if use_parallel:
        # Parallel processing for large datasets
        with ProcessPoolExecutor() as executor:
            futures = {
                executor.submit(_bruteforce_worker, (data, a, b)): (a, b)
                for a, b in valid_keys
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and result['score'] >= min_score:
                        results.append(result)
                except Exception:
                    pass
    else:
        # Simple sequential loop for smaller datasets
        # Import scoring here to avoid issues
        from ..crypto_module import score_english
        
        for a in range(1, 256, 2):  # Only odd values
            for b in range(256):
                try:
                    decrypted = decrypt_affine(data, a, b)
                    text = decrypted.decode('utf-8', errors='ignore')
                    score = score_english(text)
                    
                    if score >= min_score:
                        results.append({
                            'a': a,
                            'b': b,
                            'result': text,
                            'score': score
                        })
                except ValueError:
                    # Skip invalid keys (shouldn't happen with odd a, but safety check)
                    pass
                except Exception:
                    # Skip decoding errors
                    pass
    
    # Sort by score descending
    results.sort(key=lambda x: x['score'], reverse=True)
    
    return results
