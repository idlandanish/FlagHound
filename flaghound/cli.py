import argparse
import sys
from . import triage, crypto, utils

def print_banner():
    print(r"""
  ___ _ _   ___ _                  _ 
 / __(_) |_|   \ |__ _ __ _  _ _ _| |
| (_ | |  _| |) | '_ \ '_ \ || | ' \ |
 \___|_|\__|___/|_.__/ .__/\_,_|_||_|
                     |_|    v1.0.0 - CTF Quick-Strike
    """)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="FlagHound: CTF Triage & Quick-Strike")
    parser.add_argument("target", help="File path or URL to analyze")
    args = parser.parse_args()
    
    target = args.target
    print(f"[*] Targeting: {target}\n")

    # 1. File Triage
    print("[*] Phase 1: Deep Triage...")
    analysis = triage.analyze_file(target)
    if "error" in analysis:
        print(f"[-] {analysis['error']}")
        # If it's not a file, maybe it's a URL? (Web module goes here)
        return
        
    print(f"    -> Type: {analysis['type']} | Size: {analysis['size']} bytes")
    print(f"    -> Entropy: {analysis['entropy']} (High = Encrypted/Packed)")
    print(f"    -> Printable: {analysis['printable_ratio']*100:.1f}%")

    # 2. Auto-Decoding (If it's text-like)
    if analysis['printable_ratio'] > 0.8:
        print("\n[*] Phase 2: Crypto Auto-Decode...")
        text_data = analysis['raw_data'].decode('utf-8', errors='ignore').strip()
        decodes = crypto.auto_decode(text_data)
        if decodes:
            for method, result in decodes.items():
                print(f"    -> {method}: {result[:100]}...") # Truncate for display
        else:
            print("    -> No standard encodings detected.")

    # 3. Flag Extraction
    print("\n[*] Phase 3: Flag Extraction...")
    # Scan raw data and all decoded outputs
    all_text = analysis['raw_data'].decode('utf-8', errors='ignore')
    for dec in decodes.values() if 'decodes' in locals() else []:
        all_text += dec
        
    flags = utils.extract_flags(all_text)
    if flags:
        print("    🚩 FLAGS FOUND:")
        for flag in flags:
            print(f"       -> {flag}")
    else:
        print("    -> No flags found in initial scan.")

if __name__ == "__main__":
    main()