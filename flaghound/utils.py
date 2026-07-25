import re

# Standard CTF flag formats
FLAG_PATTERNS = [
    r'flag\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'flag-[^\s]+',
    r'FLAG\{[^}]+\}'
]

def extract_flags(text):
    """Scans text for known flag formats."""
    found_flags = set()
    for pattern in FLAG_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        found_flags.update(matches)
    return list(found_flags)