"""
FlagHound v2.0 - CTF Automation Tool
Fast triage tool for automating file analysis, nested archive extraction, and obfuscation breaking.
"""

from .triage import analyze_file, quick_scan, calculate_entropy, extract_strings
from .crypto import auto_decode, xor_bruteforce, xor_decrypt, detect_xor_encrypted
from .archives import recursive_extract, detect_archive_type, extract_all_archives
from .web import fetch_url, is_url
from .utils import extract_flags

__version__ = '2.0.0'
__all__ = [
    'analyze_file',
    'quick_scan', 
    'calculate_entropy',
    'extract_strings',
    'auto_decode',
    'xor_bruteforce',
    'xor_decrypt',
    'detect_xor_encrypted',
    'recursive_extract',
    'detect_archive_type',
    'extract_all_archives',
    'fetch_url',
    'is_url',
    'extract_flags',
]
