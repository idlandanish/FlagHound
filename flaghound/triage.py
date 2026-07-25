"""
Smart Triage Module for FlagHound v2.0
Core analysis logic with strings extraction, entropy analysis, and mmap support for large files.
"""
import os
import math
import mmap
from collections import Counter
from pathlib import Path

# Magic bytes for file type detection
MAGIC_BYTES = {
    b'\x89PNG': 'PNG Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'PK\x03\x04': 'ZIP Archive',
    b'PK\x05\x06': 'ZIP Archive (empty)',
    b'\x7fELF': 'Linux ELF Binary',
    b'MZ': 'Windows PE Binary',
    b'%PDF': 'PDF Document',
    b'\x1f\x8b': 'GZIP Compressed',
    b'BZh': 'BZIP2 Compressed',
    b'\xfd7zXZ\x00': 'XZ Compressed',
    b'ustar': 'TAR Archive',
    b'Rar!': 'RAR Archive',
    b'7z\xbc\xaf': '7-Zip Archive',
    b'\xca\xfe\xba\xbe': 'Mach-O Binary',
    b'CFFA': 'Adobe Font',
    b'RIFF': 'RIFF Container (WAV/AVI)',
    b'OggS': 'Ogg Vorbis',
    b'FLAC': 'FLAC Audio',
    b'\x00\x00\x00\x18ftypmp4': 'MP4 Video',
    b'\x00\x00\x00\x1cftypmp4': 'MP4 Video',
    b'\x00\x00\x00 ftypisom': 'MP4 Video',
    b'SQLite format 3': 'SQLite Database',
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': 'Possible Encrypted/Empty',
}

def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    
    if length == 0:
        return 0.0
    
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return round(entropy, 2)

def extract_strings(data, min_length=4):
    """
    Extract printable ASCII strings from binary data.
    Uses efficient iteration for large files.
    """
    strings = []
    current_string = []
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string.append(chr(byte))
        else:
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))
            current_string = []
    
    # Don't forget the last string
    if len(current_string) >= min_length:
        strings.append(''.join(current_string))
    
    return strings

def extract_wide_strings(data, min_length=4):
    """Extract UTF-16 wide strings (common in Windows binaries)."""
    strings = []
    i = 0
    
    while i < len(data) - 1:
        current_string = []
        start = i
        
        # Check if it looks like UTF-16LE (alternating null bytes)
        while i < len(data) - 1:
            if data[i+1] == 0 and 32 <= data[i] <= 126:
                current_string.append(chr(data[i]))
                i += 2
            elif data[i] == 0 and 32 <= data[i+1] <= 126:
                # UTF-16BE
                current_string.append(chr(data[i+1]))
                i += 2
            else:
                break
        
        if len(current_string) >= min_length:
            strings.append(''.join(current_string))
        
        i = start + 1 if i == start else i
    
    return strings

def analyze_file(file_path, use_mmap=True):
    """
    Analyze a file and return comprehensive metadata.
    Uses mmap for efficient handling of large files.
    """
    result = {
        'path': str(file_path),
        'size': 0,
        'type': 'Unknown',
        'entropy': 0.0,
        'printable_ratio': 0.0,
        'strings': [],
        'raw_data': b'',
        'error': None
    }
    
    if not os.path.exists(file_path):
        result['error'] = 'File not found'
        return result
    
    try:
        file_size = os.path.getsize(file_path)
        result['size'] = file_size
        
        if file_size == 0:
            result['error'] = 'Empty file'
            return result
        
        # Use mmap for large files (> 10 MB)
        if use_mmap and file_size > 10 * 1024 * 1024:
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # Read header for magic bytes
                    header = mm.read(min(256, file_size))
                    
                    # Calculate entropy on first 1 MB sample
                    sample_size = min(1024 * 1024, file_size)
                    mm.seek(0)
                    sample = mm.read(sample_size)
                    
                    result['entropy'] = calculate_entropy(sample)
                    result['printable_ratio'] = sum(1 for b in sample if 32 <= b <= 126) / len(sample)
                    
                    # Extract strings from sample
                    result['strings'] = extract_strings(sample)
                    
                    # Store raw data for small files only
                    if file_size < 10 * 1024 * 1024:
                        mm.seek(0)
                        result['raw_data'] = mm.read()
                    else:
                        result['raw_data'] = sample
        else:
            # Read entire file for smaller files
            with open(file_path, 'rb') as f:
                data = f.read()
            
            result['raw_data'] = data
            result['entropy'] = calculate_entropy(data)
            result['printable_ratio'] = sum(1 for b in data if 32 <= b <= 126) / len(data) if data else 0
            result['strings'] = extract_strings(data)
        
        # Detect file type using magic bytes
        header = result['raw_data'][:256] if result['raw_data'] else b''
        
        for magic, ftype in MAGIC_BYTES.items():
            if len(magic) <= len(header) and header.startswith(magic):
                result['type'] = ftype
                break
        
        # Additional checks for text-based files
        if result['type'] == 'Unknown':
            if result['printable_ratio'] > 0.9:
                result['type'] = 'Text File'
            elif result['entropy'] > 7.5:
                result['type'] = 'Encrypted/Compressed Data'
        
    except PermissionError:
        result['error'] = 'Permission denied'
    except Exception as e:
        result['error'] = f'Analysis failed: {str(e)}'
    
    return result

def quick_scan(file_path):
    """
    Quick scan without full string extraction for faster processing.
    Returns basic metadata only.
    """
    result = {
        'path': str(file_path),
        'size': 0,
        'type': 'Unknown',
        'entropy': 0.0,
        'printable_ratio': 0.0,
        'error': None
    }
    
    if not os.path.exists(file_path):
        result['error'] = 'File not found'
        return result
    
    try:
        file_size = os.path.getsize(file_path)
        result['size'] = file_size
        
        with open(file_path, 'rb') as f:
            # Read only first 1 MB for quick analysis
            sample = f.read(min(1024 * 1024, file_size))
        
        result['entropy'] = calculate_entropy(sample)
        result['printable_ratio'] = sum(1 for b in sample if 32 <= b <= 126) / len(sample) if sample else 0
        
        # Detect file type
        for magic, ftype in MAGIC_BYTES.items():
            if sample.startswith(magic):
                result['type'] = ftype
                break
        
    except Exception as e:
        result['error'] = f'Scan failed: {str(e)}'
    
    return result
