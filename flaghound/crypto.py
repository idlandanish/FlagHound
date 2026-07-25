"""
Crypto Module for FlagHound v2.0
Includes Base64 recursive decoding, URL decode, Rot13, and XOR brute-force engine.
Optimized with Hamming Distance key estimation and early exit on flag patterns.
"""
import base64
import binascii
import string
import urllib.parse
from collections import Counter
from typing import Dict, List, Tuple, Optional

# English letter frequency for scoring
ENGLISH_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
    'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
    'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
    'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
    'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
}

# Common flag patterns for heuristic scoring
FLAG_PATTERNS = [b'flag{', b'FLAG{', b'ctf{', b'CTF{', b'picoCTF{', b'HTB{', b'google{', b'actf{']

# Pre-compiled regex for faster flag detection
import re
FLAG_REGEX = re.compile(rb'(?:flag|ctf|picoctf|htb|google|actf)\{[a-zA-Z0-9_\-]+\}', re.IGNORECASE)

def is_printable_text(data):
    """Check if data is mostly printable ASCII."""
    if not data:
        return False
    printable_count = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable_count / len(data) > 0.85

def score_english(text):
    """Score text based on English letter frequency."""
    if not text:
        return 0
    
    text_lower = text.lower()
    score = 0
    total_letters = 0
    
    for char in text_lower:
        if char.isalpha():
            total_letters += 1
            score += ENGLISH_FREQ.get(char, 0)
    
    if total_letters == 0:
        return 0
    
    return score / total_letters

def xor_decrypt(data, key):
    """XOR decrypt data with given key (bytes or int)."""
    if isinstance(key, int):
        # Single byte key
        return bytes([b ^ key for b in data])
    else:
        # Multi-byte key
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

def auto_decode(data_str):
    """
    Auto-detect and decode various encodings.
    Returns dict of method -> decoded result.
    """
    results = {}
    
    if not data_str:
        return results
    
    # Try Base64 (including recursive)
    try:
        decoded = data_str
        depth = 0
        while depth < 10:  # Max 10 levels of recursive base64
            # Check if it looks like base64
            if all(c in string.ascii_letters + string.digits + '+/=' for c in decoded.strip()):
                # Must have proper padding or be valid without it
                missing_padding = len(decoded) % 4
                if missing_padding:
                    decoded += '=' * (4 - missing_padding)
                try:
                    result = base64.b64decode(decoded).decode('utf-8', errors='ignore')
                    if result.isprintable() and len(result) > 0:
                        decoded = result
                        depth += 1
                        continue
                except Exception:
                    pass
            break
        
        if decoded != data_str:
            results['Base64'] = decoded
    except Exception:
        pass
    
    # Try Hex
    try:
        clean_hex = data_str.replace(' ', '').replace('\n', '')
        if all(c in string.hexdigits for c in clean_hex) and len(clean_hex) % 2 == 0:
            decoded = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 0:
                results['Hex'] = decoded
    except Exception:
        pass
    
    # Try URL decode
    try:
        decoded = urllib.parse.unquote(data_str)
        if decoded != data_str and decoded.isprintable():
            results['URL'] = decoded
    except Exception:
        pass
    
    # Try Rot13
    rot13 = ""
    for char in data_str:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            rot13 += chr((ord(char) - offset + 13) % 26 + offset)
        else:
            rot13 += char
    if rot13 != data_str:
        results['Rot13'] = rot13
    
    # Try Rot47 (common in CTFs)
    rot47 = ""
    for char in data_str:
        code = ord(char)
        if 33 <= code <= 126:
            rot47 += chr(33 + ((code - 33 + 47) % 94))
        else:
            rot47 += char
    if rot47 != data_str:
        results['Rot47'] = rot47
    
    return results

def hamming_distance(b1: bytes, b2: bytes) -> int:
    """Calculate Hamming distance between two byte strings."""
    if len(b1) != len(b2):
        return abs(len(b1) - len(b2))
    
    distance = 0
    for x, y in zip(b1, b2):
        z = x ^ y
        while z:
            distance += z & 1
            z >>= 1
    return distance

def estimate_xor_key_length(data: bytes, min_len: int = 2, max_len: int = 32) -> List[Tuple[int, float]]:
    """
    Estimate XOR key length using normalized Hamming distance.
    Returns list of (key_length, avg_distance) sorted by distance (lower is better).
    """
    if len(data) < max_len * 2:
        return []
    
    distances = []
    
    for key_len in range(min_len, min(max_len + 1, len(data) // 2)):
        # Take multiple blocks and compute average Hamming distance
        num_blocks = min(10, len(data) // key_len)
        if num_blocks < 2:
            continue
        
        total_distance = 0
        comparisons = 0
        
        for i in range(num_blocks - 1):
            block1 = data[i * key_len:(i + 1) * key_len]
            block2 = data[(i + 1) * key_len:(i + 2) * key_len]
            total_distance += hamming_distance(block1, block2)
            comparisons += 1
        
        if comparisons > 0:
            avg_distance = total_distance / comparisons
            normalized = avg_distance / key_len  # Normalize by key length
            distances.append((key_len, normalized))
    
    # Sort by normalized distance (lower suggests correct key length)
    distances.sort(key=lambda x: x[1])
    return distances[:5]  # Return top 5 candidates

def xor_bruteforce(data, max_key_len=4):
    """
    Brute-force XOR encryption with single-byte and short multi-byte keys.
    Uses frequency analysis, Hamming Distance key estimation, and flag pattern heuristics.
    Returns dict of (key) -> decoded_string for best candidates.
    """
    if not data or len(data) < 10:
        return {}
    
    results = {}
    best_scores = []  # List of (score, key, decoded_text)
    
    # Early exit: check if data already contains a flag
    if FLAG_REGEX.search(data):
        match = FLAG_REGEX.search(data).group()
        try:
            results[b'\x00'] = match.decode('utf-8', errors='ignore')
            return results  # Already contains flag, no need to decrypt
        except:
            pass
    
    # Estimate likely key lengths using Hamming distance
    estimated_lengths = estimate_xor_key_length(data, min_len=2, max_len=min(max_key_len, 16))
    priority_lengths = [length for length, _ in estimated_lengths]
    
    # Single-byte XOR (most common in CTFs)
    for key in range(256):
        decoded = xor_decrypt(data, key)
        
        # Quick filter: must be mostly printable
        if not is_printable_text(decoded):
            continue
        
        text = decoded.decode('utf-8', errors='ignore')
        
        # Check for flag pattern first (fast path)
        if FLAG_REGEX.search(decoded.lower()):
            best_scores.insert(0, (1000, bytes([key]), text))  # High score for flag
            continue
        
        # Score based on English frequency
        score = score_english(text)
        
        # Bonus for flag patterns
        for pattern in FLAG_PATTERNS:
            if pattern in decoded.lower():
                score += 50
        
        if score > 2.0:  # Threshold for "looks like English"
            best_scores.append((score, bytes([key]), text))
    
    # Multi-byte XOR with priority on estimated key lengths
    all_key_lengths = list(range(2, min(max_key_len + 1, len(data) // 2)))
    # Reorder: try estimated lengths first
    ordered_lengths = priority_lengths + [l for l in all_key_lengths if l not in priority_lengths]
    
    for key_len in ordered_lengths:
        # Try common short keys first (very common in CTFs)
        common_keys = [
            b'key', b'the', b'and', b'xor', b'flag', b'CTF', b'ctf',
            b'KEY', b'THE', b'AND', b'XOR', b'FLAG',
            b'abc', b'xyz', b'123', b'password', b'secret',
            b'admin', b'root', b'user', b'pass', b'test',
        ]
        
        # Test common keys directly
        for key in common_keys:
            if len(key) == key_len:
                decoded = xor_decrypt(data, key)
                
                # Early exit on flag detection
                if FLAG_REGEX.search(decoded.lower()):
                    text = decoded.decode('utf-8', errors='ignore')
                    best_scores.insert(0, (1000, key, text))
                    continue
                
                if is_printable_text(decoded):
                    text = decoded.decode('utf-8', errors='ignore')
                    score = score_english(text)
                    
                    for pattern in FLAG_PATTERNS:
                        if pattern in decoded.lower():
                            score += 50
                    
                    if score > 2.0:
                        best_scores.append((score, key, text))
        
        # Also try frequency analysis to guess key
        # For each position in key, find most likely byte
        guessed_key = []
        for pos in range(key_len):
            # Extract every key_len-th byte starting at pos
            subset = bytes([data[i] for i in range(pos, len(data), key_len)])
            
            best_byte = 0
            best_score = 0
            for k in range(256):
                decoded_subset = xor_decrypt(subset, k)
                if is_printable_text(decoded_subset):
                    text = decoded_subset.decode('utf-8', errors='ignore')
                    s = score_english(text)
                    if s > best_score:
                        best_score = s
                        best_byte = k
            
            guessed_key.append(best_byte)
        
        if guessed_key:
            key = bytes(guessed_key)
            decoded = xor_decrypt(data, key)
            
            # Early exit on flag detection
            if FLAG_REGEX.search(decoded.lower()):
                text = decoded.decode('utf-8', errors='ignore')
                best_scores.insert(0, (1000, key, text))
                continue
            
            if is_printable_text(decoded):
                text = decoded.decode('utf-8', errors='ignore')
                score = score_english(text)
                
                for pattern in FLAG_PATTERNS:
                    if pattern in decoded.lower():
                        score += 50
                
                if score > 2.0:
                    best_scores.append((score, key, text))
    
    # Sort by score and return top results
    best_scores.sort(reverse=True, key=lambda x: x[0])
    
    # Deduplicate and return top 10
    seen_keys = set()
    for score, key, text in best_scores[:10]:
        if key not in seen_keys:
            results[key] = text
            seen_keys.add(key)
    
    return results

def detect_xor_encrypted(data):
    """
    Heuristic to detect if data might be XOR encrypted.
    Returns True if entropy is high but data shows XOR characteristics.
    """
    if len(data) < 100:
        return False
    
    # Check for repeating patterns (indicates short XOR key)
    # XOR with same key produces repeating patterns at key length intervals
    for key_len in range(1, 8):
        matches = 0
        comparisons = 0
        for i in range(len(data) - key_len):
            if data[i] == data[i + key_len]:
                matches += 1
            comparisons += 1
        
        if comparisons > 0:
            match_ratio = matches / comparisons
            # High match ratio at specific interval suggests XOR
            if match_ratio > 0.1:
                return True
    
    return False
