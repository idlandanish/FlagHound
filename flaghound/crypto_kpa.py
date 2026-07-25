"""
FlagHound v2.0 - Known Plaintext Attack (KPA) Engine
Automates detection of stream cipher keystream reuse vulnerabilities.
Detects: Source file with known plaintext + Separate file with ciphertext -> Recovers Flag.
"""

import ast
import re
import os
import logging
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Patterns for hex ciphertexts (common in CTF .txt/.out files)
HEX_PATTERN = re.compile(r'^[0-9a-fA-F]{32,}$', re.MULTILINE)

# Flag pattern for verification
FLAG_PATTERN = re.compile(r'flag\{[a-zA-Z0-9_\-]+\}')

def extract_strings_from_python(file_path: str) -> List[str]:
    """
    Safely extract all string literals from a Python file using AST.
    Filters out short strings likely to be variables or single chars.
    """
    strings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                # Filter: Must be long enough to be a message (>20 chars)
                # Exclude obvious non-messages (paths, imports handled by ast usually but good to be safe)
                if len(node.value) > 20:
                    strings.append(node.value)
            # Python <3.8 compatibility
            elif isinstance(node, ast.Str): 
                if len(node.s) > 20:
                    strings.append(node.s)
    except Exception as e:
        logger.debug(f"Failed to parse Python file {file_path}: {e}")
    
    return strings

def extract_hex_ciphertexts(file_path: str) -> List[bytes]:
    """
    Extract long hex strings from a text file and convert to bytes.
    """
    ciphertexts = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        matches = HEX_PATTERN.findall(content)
        for match in matches:
            try:
                # Convert hex string to bytes
                ciphertexts.append(bytes.fromhex(match))
            except ValueError:
                continue
    except Exception as e:
        logger.debug(f"Failed to read ciphertext file {file_path}: {e}")
    
    return ciphertexts

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with a repeating key."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def solve_kpa(known_plaintext: str, ciphertext: bytes) -> Optional[bytes]:
    """
    Perform Known Plaintext Attack.
    If we know P and have C = P ^ Keystream, then Keystream = P ^ C.
    Then Flag = C_flag ^ Keystream (if the flag was encrypted with the same keystream start).
    
    Assumption: The challenge encrypts the known message and the flag separately 
    using the SAME keystream starting from index 0.
    """
    p_bytes = known_plaintext.encode('utf-8')
    
    # We can only recover the keystream up to the length of the known plaintext
    min_len = min(len(p_bytes), len(ciphertext))
    
    # Recover Keystream segment
    keystream = bytes([p_bytes[i] ^ ciphertext[i] for i in range(min_len)])
    
    # Apply keystream to the ciphertext to get the result
    # Note: In many CTF challenges, the flag is encrypted independently with the same key/nonce.
    # So Result = Ciphertext ^ Keystream recovered from KnownPlaintext
    # However, if the ciphertext IS the flag encrypted, and we have a known plaintext encrypted with the SAME key stream...
    # Actually, the standard scenario is:
    # File A: msg = "Long known text"; enc_msg = encrypt(msg)
    # File B: enc_flag = encrypt(flag)
    # If encrypt() is a stream cipher with fixed nonce/key, then:
    # enc_msg = msg ^ keystream
    # enc_flag = flag ^ keystream
    # Therefore: flag = enc_flag ^ (enc_msg ^ msg)
    # But here we usually don't have enc_msg in the text file, we have the SOURCE code generating it.
    # Wait, the prompt implies:
    # 1. Source has known plaintext string.
    # 2. Text file has ciphertext (hex).
    # Scenario A: The text file contains the encryption of the known plaintext? 
    #    If so, we recover the keystream directly.
    # Scenario B: The text file contains the encryption of the FLAG, and the source shows what the algorithm is?
    #    That requires running the algo.
    # Scenario C (Most common KPA): The text file contains MULTIPLE ciphertexts, or the source output the ciphertext of the known text.
    # Let's assume the prompt's specific logic: 
    # "They encrypted a known message and the flag with the same keystream."
    # This implies we have C_known and C_flag.
    # If the provided text file contains C_known (hex), we derive Keystream = C_known ^ P_known.
    # Then we need C_flag. 
    # BUT often in these challenges, the single hex string in the file IS the flag ciphertext, 
    # and the "known plaintext" is actually embedded in the challenge description or the script itself as a hint 
    # that allows deriving the key directly if the key is short, OR it's a two-time pad scenario.
    
    # Re-reading the prompt logic: 
    # "If FlagHound finds ... Source with known plaintext ... and Ciphertexts ... 
    # I will XOR them and look for flag{"
    # This implies: Result = Ciphertext ^ KnownPlaintext.
    # This only works if the Ciphertext IS (Flag ^ KnownPlaintext) which is rare, 
    # OR if the "Ciphertext" file actually contains the Keystream (unlikely),
    # OR if the challenge is: C_flag = Flag ^ Key, and we found Key = KnownPlaintext (if key is the string).
    
    # Let's implement the most robust interpretation for Stream Cipher Reuse:
    # Hypothesis: The hex string in the .txt file is the Ciphertext of the FLAG.
    # The Python file reveals the KEYSTREAM or the KEY.
    # If the Python file has a long string that looks like a keystream (random-ish), we use it.
    # If the Python file has a long string that is "Known Plaintext", and the .txt file has the encryption of THAT SAME PLAINTEXT...
    # Then we can recover the keystream. But where is the flag ciphertext?
    
    # Alternative Interpretation (Two-Time Pad / Same Nonce):
    # Maybe the .txt file contains TWO hex strings? Or the challenge provides C_known and C_flag.
    # If the tool only sees one hex string and one python file...
    # Perhaps the "Known Plaintext" is actually the KEY? (e.g. key = "Our counter agencies...")
    # Let's try: Decrypted = Ciphertext ^ KnownString (repeating).
    
    candidate = xor_bytes(ciphertext[:min_len], p_bytes)
    
    # Check if result looks like a flag or readable text
    try:
        decoded = candidate.decode('utf-8', errors='strict')
        if 'flag{' in decoded or 'ctf{' in decoded:
            return candidate
        # Heuristic: High printable ratio
        printable = sum(1 for c in decoded if c.isprintable())
        if printable / len(decoded) > 0.85:
            return candidate
    except:
        pass
    
    return None

def scan_directory_for_kpa(directory: str) -> List[Dict]:
    """
    Scan a directory for pairs of (Python Source, Ciphertext Files) suitable for KPA.
    
    This implements the Two-Time Pad / Stream Cipher Reuse attack:
    - Finds Python files with long known plaintext strings
    - Finds .txt/.out files with hex ciphertexts
    - If multiple ciphertext files exist, assumes one is C_known and others are C_flag
    - Recovers flag using: Flag = C_flag ^ C_known ^ P_known
    """
    results = []
    py_files = []
    text_files = []

    # Collect files
    for root, _, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)
            if f.endswith('.py'):
                py_files.append(path)
            elif f.endswith(('.txt', '.out', '.hex')):
                text_files.append(path)

    # Need at least 2 ciphertext files for the attack (C_known + C_flag)
    if len(text_files) < 2:
        logger.debug(f"KPA: Need at least 2 ciphertext files, found {len(text_files)}")
        return results

    # Cross-reference Python files with ciphertext pairs
    for py_path in py_files:
        known_strings = extract_strings_from_python(py_path)
        if not known_strings:
            continue

        # Try all pairs of ciphertext files
        for i, txt_path1 in enumerate(text_files):
            for txt_path2 in text_files[i+1:]:
                ciphers1 = extract_hex_ciphertexts(txt_path1)
                ciphers2 = extract_hex_ciphertexts(txt_path2)
                
                if not ciphers1 or not ciphers2:
                    continue

                # Try all combinations of known plaintext and ciphertext pairs
                for p_text in known_strings:
                    p_bytes = p_text.encode('utf-8')
                    
                    for c1 in ciphers1:
                        for c2 in ciphers2:
                            # Try both orderings: (c1=known, c2=flag) and (c2=known, c1=flag)
                            for c_known, c_flag in [(c1, c2), (c2, c1)]:
                                # Check if lengths are compatible
                                min_len = min(len(p_bytes), len(c_known), len(c_flag))
                                if min_len < 5:  # Need at least "flag{" length
                                    continue
                                
                                # KPA: Flag = C_flag ^ C_known ^ P_known
                                keystream_segment = bytes([c_known[j] ^ p_bytes[j] for j in range(min_len)])
                                recovered = bytes([c_flag[j] ^ keystream_segment[j] for j in range(min_len)])
                                
                                try:
                                    decoded = recovered.decode('utf-8', errors='ignore')
                                    flags = FLAG_PATTERN.findall(decoded)
                                    if flags:
                                        logger.info(f"[KPA SUCCESS] Found flag using {txt_path1} + {txt_path2}")
                                        results.append({
                                            'file': txt_path2,
                                            'source': py_path,
                                            'flags': flags,
                                            'method': 'Known Plaintext Attack (Stream Reuse)',
                                            'preview': decoded[:100]
                                        })
                                except Exception as e:
                                    logger.debug(f"KPA decode failed: {e}")
    
    return results
