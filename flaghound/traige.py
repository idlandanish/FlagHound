import os
import math
from collections import Counter

def calculate_entropy(data):
    if not data: return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def analyze_file(file_path):
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Basic Magic Byte checks
    magic_bytes = {
        b'\x89PNG': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'PK\x03\x04': 'ZIP Archive',
        b'\x7fELF': 'Linux ELF Binary',
        b'MZ': 'Windows PE Binary',
        b'%PDF': 'PDF Document'
    }
    
    file_type = "Unknown"
    for magic, ftype in magic_bytes.items():
        if data.startswith(magic):
            file_type = ftype
            break
            
    entropy = calculate_entropy(data)
    printable_ratio = sum(1 for b in data if 32 <= b <= 126) / len(data) if data else 0
    
    return {
        "size": len(data),
        "type": file_type,
        "entropy": round(entropy, 2),
        "printable_ratio": round(printable_ratio, 2),
        "raw_data": data
    }