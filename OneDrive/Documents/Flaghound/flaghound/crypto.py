import base64
import binascii
import string

def auto_decode(data_str):
    results = {}
    
    # Try Base64
    try:
        # Check if it looks like base64
        if all(c in string.ascii_letters + string.digits + '+/=' for c in data_str):
            decoded = base64.b64decode(data_str).decode('utf-8', errors='ignore')
            if decoded.isprintable():
                results['Base64'] = decoded
    except Exception:
        pass

    # Try Hex
    try:
        decoded = bytes.fromhex(data_str).decode('utf-8', errors='ignore')
        if decoded.isprintable():
            results['Hex'] = decoded
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

    return results