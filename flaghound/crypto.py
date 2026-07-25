"""
Crypto Module for FlagHound v2.0
Includes Base64 recursive decoding, URL decode, Rot13, and XOR brute-force engine.
"""
import base64
import binascii
import string
import urllib.parse
from collections import Counter

# English letter frequency for scoring
ENGLISH_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
    'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
    'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
    'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
    'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
}

# Common flag patterns for heuristic scoring
FLAG_PATTERNS = [b'flag{', b'FLAG{', b'ctf{', b'CTF{', b'picoCTF{', b'HTB{']

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

def xor_bruteforce(data, max_key_len=4):
    """
    Brute-force XOR encryption with single-byte and short multi-byte keys.
    Uses frequency analysis and flag pattern heuristics.
    Returns dict of (key) -> decoded_string for best candidates.
    """
    if not data or len(data) < 10:
        return {}
    
    results = {}
    best_scores = []  # List of (score, key, decoded_text)
    
    # Single-byte XOR (most common in CTFs)
    for key in range(256):
        decoded = xor_decrypt(data, key)
        
        # Quick filter: must be mostly printable
        if not is_printable_text(decoded):
            continue
        
        text = decoded.decode('utf-8', errors='ignore')
        
        # Score based on English frequency
        score = score_english(text)
        
        # Bonus for flag patterns
        for pattern in FLAG_PATTERNS:
            if pattern in decoded.lower() if isinstance(pattern, bytes) else pattern in text.lower():
                score += 50
        
        if score > 2.0:  # Threshold for "looks like English"
            best_scores.append((score, bytes([key]), text))
    
    # Multi-byte XOR (2-4 bytes)
    for key_len in range(2, min(max_key_len + 1, len(data) // 2)):
        # Try common short keys
        common_keys = [
            b'key', b'the', b'and', b'xor', b'flag', b'CTF',
            b'\x00\x01', b'\xff\xff', b'AB', b'12',
        ]
        
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
