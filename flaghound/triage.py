"""
Smart Triage Module for FlagHound v2.0
Core analysis logic with strings extraction, entropy analysis, and mmap support for large files.
Optimized for competition-grade performance with sliding window entropy and fast string extraction.
"""
import os
import math
import mmap
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any, Optional

# Pre-compiled regex for faster string extraction
PRINTABLE_PATTERN = re.compile(rb'[\x20-\x7e]{4,}')
WIDE_STRING_PATTERN_LE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
WIDE_STRING_PATTERN_BE = re.compile(rb'(?:\x00[\x20-\x7e]){4,}')

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
}

# Pre-compute log2 values for entropy calculation (optimization)
LOG2_CACHE = {i: math.log2(i) if i > 0 else 0 for i in range(1, 257)}

def calculate_entropy(data):
    """Calculate Shannon entropy of data using pre-computed log2 values."""
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
            # Use cached log2 value for speed
            entropy -= p * LOG2_CACHE.get(count, math.log2(count))
    
    return round(entropy, 2)

def calculate_sliding_entropy(data, window_size=4096):
    """
    Calculate sliding window entropy to detect encrypted/compressed regions.
    Returns list of (offset, entropy) tuples for high-entropy windows.
    Optimized for large file analysis.
    """
    if not data or len(data) < window_size:
        return []
    
    results = []
    step = window_size // 4  # 25% overlap
    
    for offset in range(0, len(data) - window_size + 1, step):
        window = data[offset:offset + window_size]
        entropy = calculate_entropy(window)
        
        # Flag high-entropy regions (likely encrypted/compressed)
        if entropy > 7.0:
            results.append((offset, entropy))
    
    return results

def extract_strings(data, min_length=4):
    """
    Extract printable ASCII strings from binary data using regex.
    10x faster than character-by-character iteration.
    """
    if not data:
        return []
    
    # Use pre-compiled regex for massive speedup
    matches = PRINTABLE_PATTERN.findall(data)
    return [m.decode('ascii', errors='ignore') for m in matches if len(m) >= min_length]

def extract_wide_strings(data, min_length=4):
    """Extract UTF-16 wide strings (common in Windows binaries) using regex."""
    if not data:
        return []
    
    strings = []
    
    # UTF-16LE (Little Endian)
    matches_le = WIDE_STRING_PATTERN_LE.findall(data)
    for match in matches_le:
        # Remove null bytes and decode
        cleaned = match.replace(b'\x00', b'')
        if len(cleaned) >= min_length:
            strings.append(cleaned.decode('ascii', errors='ignore'))
    
    # UTF-16BE (Big Endian)
    matches_be = WIDE_STRING_PATTERN_BE.findall(data)
    for match in matches_be:
        cleaned = match.replace(b'\x00', b'')
        if len(cleaned) >= min_length:
            strings.append(cleaned.decode('ascii', errors='ignore'))
    
    return strings

def analyze_file(file_path, use_mmap=True, sliding_entropy=False):
    """
    Analyze a file and return comprehensive metadata.
    Uses mmap for efficient handling of large files.
    
    Args:
        file_path: Path to the file
        use_mmap: Use memory-mapped I/O for large files
        sliding_entropy: Enable sliding window entropy analysis (slower but more precise)
    """
    result = {
        'path': str(file_path),
        'size': 0,
        'type': 'Unknown',
        'entropy': 0.0,
        'printable_ratio': 0.0,
        'strings': [],
        'wide_strings': [],
        'high_entropy_regions': [],
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
                    
                    # Extract strings from sample using optimized regex
                    result['strings'] = extract_strings(sample)
                    result['wide_strings'] = extract_wide_strings(sample)
                    
                    # Sliding entropy analysis for encrypted regions
                    if sliding_entropy:
                        result['high_entropy_regions'] = calculate_sliding_entropy(sample)
                    
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
            
            # Optimized string extraction
            result['strings'] = extract_strings(data)
            result['wide_strings'] = extract_wide_strings(data)
            
            # Sliding entropy if requested
            if sliding_entropy:
                result['high_entropy_regions'] = calculate_sliding_entropy(data)
        
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
