"""
Recursive Archive Extraction Engine for FlagHound v2.0
Handles nested .zip, .tar, .gz, .bz2, .xz up to 10 layers deep with zip-bomb protection.
"""
import os
import zipfile
import tarfile
import gzip
import bz2
import lzma
import tempfile
import shutil
from pathlib import Path

# Safety limits to prevent zip-bombs
MAX_EXTRACTED_SIZE = 100 * 1024 * 1024  # 100 MB total extracted size
MAX_FILE_COUNT = 1000  # Maximum number of files to extract
MAX_DEPTH = 10  # Maximum recursion depth

SUPPORTED_ARCHIVES = {
    '.zip': 'zip',
    '.tar': 'tar',
    '.gz': 'gzip',
    '.tgz': 'gzip',
    '.tar.gz': 'gzip',
    '.bz2': 'bzip2',
    '.tar.bz2': 'bzip2',
    '.xz': 'xz',
    '.tar.xz': 'xz',
}

def detect_archive_type(file_path):
    """Detect archive type by extension and magic bytes."""
    path = Path(file_path)
    suffix = path.suffix.lower()
    name_lower = path.name.lower()
    
    # Check multi-part extensions first
    if name_lower.endswith('.tar.gz'):
        return 'gzip'
    if name_lower.endswith('.tar.bz2'):
        return 'bzip2'
    if name_lower.endswith('.tar.xz'):
        return 'xz'
    
    # Check single extension
    if suffix in SUPPORTED_ARCHIVES:
        return SUPPORTED_ARCHIVES[suffix]
    
    # Magic byte detection
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
            if header[:4] == b'PK\x03\x04':
                return 'zip'
            if header[:2] == b'\x1f\x8b':
                return 'gzip'
            if header[:3] == b'BZh':
                return 'bzip2'
            if header[:6] == b'\xfd7zXZ\x00':
                return 'xz'
            if header[:263] or header[:8] == b'ustar\x00':
                return 'tar'
    except Exception:
        pass
    
    return None

def safe_extract_zip(archive_path, extract_dir):
    """Safely extract ZIP file with size limits."""
    extracted_files = []
    total_size = 0
    
    try:
        with zipfile.ZipFile(archive_path, 'r') as zf:
            for info in zf.infolist():
                if len(extracted_files) >= MAX_FILE_COUNT:
                    break
                
                # Skip directories
                if info.is_dir():
                    continue
                
                # Check for zip-slip vulnerability
                target_path = os.path.normpath(os.path.join(extract_dir, info.filename))
                if not target_path.startswith(extract_dir):
                    continue
                
                # Check uncompressed size limit
                if info.file_size > MAX_EXTRACTED_SIZE:
                    continue
                
                total_size += info.file_size
                if total_size > MAX_EXTRACTED_SIZE:
                    break
                
                try:
                    zf.extract(info, extract_dir)
                    extracted_files.append(target_path)
                except Exception:
                    continue
    except Exception:
        pass
    
    return extracted_files

def safe_extract_tar(archive_path, extract_dir, mode='r:*'):
    """Safely extract TAR file with size limits."""
    extracted_files = []
    total_size = 0
    
    try:
        with tarfile.open(archive_path, mode) as tf:
            for member in tf.getmembers():
                if len(extracted_files) >= MAX_FILE_COUNT:
                    break
                
                # Skip directories
                if not member.isfile():
                    continue
                
                # Check size limit
                if member.size > MAX_EXTRACTED_SIZE:
                    continue
                
                total_size += member.size
                if total_size > MAX_EXTRACTED_SIZE:
                    break
                
                # Check for zip-slip
                target_path = os.path.normpath(os.path.join(extract_dir, member.name))
                if not target_path.startswith(extract_dir):
                    continue
                
                try:
                    tf.extract(member, extract_dir)
                    extracted_files.append(target_path)
                except Exception:
                    continue
    except Exception:
        pass
    
    return extracted_files

def safe_extract_gzip(archive_path, extract_dir):
    """Extract GZIP file."""
    extracted_files = []
    try:
        # Get original filename from gzip header if available
        with gzip.open(archive_path, 'rb') as f:
            data = f.read()
        
        if len(data) > 0 and len(data) < MAX_EXTRACTED_SIZE:
            # Use original name without .gz extension
            base_name = os.path.basename(archive_path)
            if base_name.endswith('.gz'):
                out_name = base_name[:-3]
            else:
                out_name = base_name + '.out'
            
            out_path = os.path.join(extract_dir, out_name)
            with open(out_path, 'wb') as f:
                f.write(data)
            extracted_files.append(out_path)
    except Exception:
        pass
    
    return extracted_files

def safe_extract_bzip2(archive_path, extract_dir):
    """Extract BZIP2 file."""
    extracted_files = []
    try:
        with bz2.open(archive_path, 'rb') as f:
            data = f.read()
        
        if len(data) > 0 and len(data) < MAX_EXTRACTED_SIZE:
            base_name = os.path.basename(archive_path)
            if base_name.endswith('.bz2'):
                out_name = base_name[:-4]
            else:
                out_name = base_name + '.out'
            
            out_path = os.path.join(extract_dir, out_name)
            with open(out_path, 'wb') as f:
                f.write(data)
            extracted_files.append(out_path)
    except Exception:
        pass
    
    return extracted_files

def safe_extract_xz(archive_path, extract_dir):
    """Extract XZ file."""
    extracted_files = []
    try:
        with lzma.open(archive_path, 'rb') as f:
            data = f.read()
        
        if len(data) > 0 and len(data) < MAX_EXTRACTED_SIZE:
            base_name = os.path.basename(archive_path)
            if base_name.endswith('.xz'):
                out_name = base_name[:-3]
            else:
                out_name = base_name + '.out'
            
            out_path = os.path.join(extract_dir, out_name)
            with open(out_path, 'wb') as f:
                f.write(data)
            extracted_files.append(out_path)
    except Exception:
        pass
    
    return extracted_files

def recursive_extract(file_path, max_depth=MAX_DEPTH, current_depth=0, base_extract_dir=None):
    """
    Recursively extract nested archives up to max_depth layers.
    Returns dict with list of all extracted file paths.
    """
    if current_depth >= max_depth:
        return {'files': [], 'error': 'Max depth reached'}
    
    if not os.path.exists(file_path):
        return {'files': [], 'error': 'File not found'}
    
    # Create temp directory for extraction
    if base_extract_dir is None:
        base_extract_dir = tempfile.mkdtemp(prefix='flaghound_')
    
    all_files = []
    
    # Detect archive type
    archive_type = detect_archive_type(file_path)
    if not archive_type:
        return {'files': [], 'error': 'Not a supported archive'}
    
    # Extract based on type
    extracted = []
    if archive_type == 'zip':
        extracted = safe_extract_zip(file_path, base_extract_dir)
    elif archive_type == 'tar':
        extracted = safe_extract_tar(file_path, base_extract_dir)
    elif archive_type == 'gzip':
        extracted = safe_extract_gzip(file_path, base_extract_dir)
    elif archive_type == 'bzip2':
        extracted = safe_extract_bzip2(file_path, base_extract_dir)
    elif archive_type == 'xz':
        extracted = safe_extract_xz(file_path, base_extract_dir)
    
    all_files.extend(extracted)
    
    # Recursively extract any archives found
    for extracted_file in extracted:
        if os.path.exists(extracted_file):
            sub_type = detect_archive_type(extracted_file)
            if sub_type:
                sub_result = recursive_extract(
                    extracted_file, 
                    max_depth=max_depth, 
                    current_depth=current_depth + 1,
                    base_extract_dir=base_extract_dir
                )
                all_files.extend(sub_result.get('files', []))
    
    return {'files': all_files, 'extract_dir': base_extract_dir}

def extract_all_archives(file_paths, output_dir=None):
    """
    Extract multiple archive files.
    Returns dict mapping original files to their extracted contents.
    """
    results = {}
    for file_path in file_paths:
        result = recursive_extract(file_path)
        results[file_path] = result
    return results
