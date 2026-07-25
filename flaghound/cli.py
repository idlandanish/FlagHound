import argparse
import sys
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from . import triage, crypto, archives, web, utils, crypto_kpa


def print_banner():
    print(r"""
  ___ _ _   ___ _                  _ 
 / __(_) |_|   \|__ _ __ _  _ _ _ _| |
| (_ | |  _| |) | '_ \| '_ \ || | ' \ |
 \___|_|\__|___/|_.__/ .__/\_,_|_||_|
                     |_|    v2.0 - CTF Automation Tool
    """)

def scan_for_flags(data, verbose=False):
    """Scan data for flags and return list of found flags."""
    if isinstance(data, bytes):
        text = data.decode('utf-8', errors='ignore')
    else:
        text = data
    
    # Also try decoding
    decodes = crypto.auto_decode(text.strip())
    for decoded in decodes.values():
        text += '\n' + decoded
    
    return utils.extract_flags(text)

def process_single_target(target, verbose=False):
    """Process a single target (file or URL) and return results."""
    results = {
        'target': target,
        'triage': None,
        'decodes': {},
        'flags': [],
        'extracted_files': [],
        'errors': []
    }
    
    temp_dir = None
    
    try:
        # Check if target is a directory - if so, skip triage and go straight to KPA
        if os.path.isdir(target):
            if verbose:
                print(f"[*] Directory detected: {target}")
                print(f"[*] Skipping file triage, running Known Plaintext Attack scan...")
            
            # Phase 6: Known Plaintext Attack (KPA) for directory scans
            kpa_results = crypto_kpa.scan_directory_for_kpa(target)
            if kpa_results:
                for kpa in kpa_results:
                    results['flags'].extend(kpa['flags'])
                    if verbose:
                        print(f"    🚩 KPA SUCCESS! Flags found using {kpa['method']}:")
                        for flag in kpa['flags']:
                            print(f"       -> {flag}")
                        print(f"       Source: {kpa['source']}")
                        print(f"       Ciphertext files: {kpa['file']}")
            
            if not results['flags'] and verbose:
                print("    -> No flags found via KPA.")
            
            # Deduplicate flags
            results['flags'] = list(set(results['flags']))
            return results
        
        # Check if target is URL
        if target.startswith(('http://', 'https://')):
            if verbose:
                print(f"[*] Fetching URL: {target}")
            fetch_result = web.fetch_url(target)
            if 'error' in fetch_result:
                results['errors'].append(f"URL fetch failed: {fetch_result['error']}")
                return results
            
            # Save to temp file for processing
            import tempfile
            fd, temp_path = tempfile.mkdtemp(prefix='flaghound_url_')
            temp_dir = temp_path
            temp_file = os.path.join(temp_path, fetch_result.get('filename', 'downloaded'))
            with open(temp_file, 'wb') as f:
                f.write(fetch_result['content'])
            target = temp_file
        
        # Phase 1: File Triage
        if verbose:
            print(f"[*] Phase 1: Deep Triage for {target}...")
        analysis = triage.analyze_file(target)
        if analysis.get("error"):
            results['errors'].append(analysis['error'])
            return results
        results['triage'] = analysis
        
        if verbose:
            print(f"    -> Type: {analysis['type']} | Size: {analysis['size']} bytes")
            print(f"    -> Entropy: {analysis['entropy']} (High = Encrypted/Packed)")
            print(f"    -> Printable: {analysis['printable_ratio']*100:.1f}%")
        
        # Scan original file for flags
        original_flags = scan_for_flags(analysis['raw_data'], verbose)
        if original_flags:
            results['flags'].extend(original_flags)
            if verbose:
                print("    🚩 FLAGS FOUND in original file:")
                for flag in original_flags:
                    print(f"       -> {flag}")
        
        # Phase 2: Archive Extraction
        if analysis['type'] in ['ZIP Archive', 'TAR Archive', 'GZIP Compressed', 'BZIP2 Compressed', 'XZ Compressed']:
            if verbose:
                print("\n[*] Phase 2: Recursive Archive Extraction...")
            extract_results = archives.recursive_extract(target, max_depth=10)
            extracted = extract_results.get('files', [])
            temp_dir = extract_results.get('extract_dir', temp_dir)
            results['extracted_files'] = extracted
            if verbose:
                print(f"    -> Extracted {len(extracted)} files")
            
            # Scan each extracted file for flags
            for extracted_file in extracted:
                if os.path.exists(extracted_file):
                    try:
                        with open(extracted_file, 'rb') as f:
                            content = f.read()
                        file_flags = scan_for_flags(content, verbose=False)
                        if file_flags:
                            results['flags'].extend(file_flags)
                            if verbose:
                                print(f"    🚩 FLAGS FOUND in {os.path.basename(extracted_file)}:")
                                for flag in file_flags:
                                    print(f"       -> {flag}")
                    except Exception as e:
                        if verbose:
                            print(f"    [-] Error reading {extracted_file}: {e}")
        
        # Phase 3: Auto-Decoding (If text-like)
        if analysis['printable_ratio'] > 0.5:
            if verbose:
                print("\n[*] Phase 3: Crypto Auto-Decode...")
            text_data = analysis['raw_data'].decode('utf-8', errors='ignore').strip()
            decodes = crypto.auto_decode(text_data)
            results['decodes'] = decodes
            if decodes and verbose:
                for method, result in decodes.items():
                    print(f"    -> {method}: {result[:100]}...")
                
                # Check decoded results for flags
                for method, decoded in decodes.items():
                    method_flags = scan_for_flags(decoded, verbose=False)
                    if method_flags:
                        results['flags'].extend(method_flags)
                        if verbose:
                            print(f"    🚩 FLAGS FOUND via {method}:")
                            for flag in method_flags:
                                print(f"       -> {flag}")
        
        # Phase 4: XOR Brute-Force (run on small files that aren't clearly plaintext)
        if len(analysis['raw_data']) < 10000 and analysis['printable_ratio'] < 0.95:
            if verbose:
                print("\n[*] Phase 4: XOR Brute-Force Analysis...")
            xor_results = crypto.xor_bruteforce(analysis['raw_data'])
            if xor_results:
                results['decodes'].update(xor_results)
                if verbose:
                    for key, decoded in list(xor_results.items())[:3]:
                        print(f"    -> XOR Key {repr(key)}: {decoded[:80]}...")
                    
                    # Check XOR results for flags
                    for key, decoded in xor_results.items():
                        xor_flags = scan_for_flags(decoded, verbose=False)
                        if xor_flags:
                            results['flags'].extend(xor_flags)
                            print(f"    🚩 FLAGS FOUND via XOR key {repr(key)}:")
                            for flag in xor_flags:
                                print(f"       -> {flag}")
        
        # Phase 5: Fallback XOR for text files with no flags found
        if not results['flags'] and len(analysis['raw_data']) < 10000:
            if verbose:
                print("\n[*] Phase 5: Fallback XOR Brute-Force (Text File Mode)...")
            xor_results = crypto.xor_bruteforce(analysis['raw_data'])
            if xor_results:
                results['decodes'].update(xor_results)
                for key, decoded in xor_results.items():
                    xor_flags = scan_for_flags(decoded, verbose=False)
                    if xor_flags:
                        results['flags'].extend(xor_flags)
                        if verbose:
                            print(f"    🚩 FLAGS FOUND via XOR key {repr(key)}:")
                            for flag in xor_flags:
                                print(f"       -> {flag}")
        
        # Phase 6: Known Plaintext Attack (KPA) for directory scans
        # Only run if scanning a directory and no flags found yet
        target_dir = None
        if os.path.isdir(target):
            target_dir = target
        elif temp_dir and os.path.exists(temp_dir):
            target_dir = temp_dir
            
        if target_dir and not results['flags']:
            if verbose:
                print(f"\n[*] Phase 6: Known Plaintext Attack (KPA) Scan in {target_dir}...")
            kpa_results = crypto_kpa.scan_directory_for_kpa(target_dir)
            if kpa_results:
                for kpa in kpa_results:
                    results['flags'].extend(kpa['flags'])
                    if verbose:
                        print(f"    🚩 KPA SUCCESS! Flags found using {kpa['method']}:")
                        for flag in kpa['flags']:
                            print(f"       -> {flag}")
                        print(f"       Source: {kpa['source']}")
                        print(f"       Ciphertext files: {kpa['file']}")
        
        # Final summary
        if verbose and not results['flags']:
            print("\n    -> No flags found in initial scan.")
            
    except Exception as e:
        results['errors'].append(f"Processing error: {e}")
        if verbose:
            print(f"[-] Error processing {target}: {e}")
    finally:
        # Cleanup temp directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
    
    # Deduplicate flags
    results['flags'] = list(set(results['flags']))
    
    return results

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="FlagHound v2.0: CTF Triage & Automation Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Main scan command (default behavior)
    scan_parser = subparsers.add_parser("scan", help="Scan files for flags (default)")
    scan_parser.add_argument("targets", nargs="+", help="File paths or URLs to analyze")
    
    # Affine cipher solver command
    affine_parser = subparsers.add_parser("affine", help="Bruteforce Affine Cipher")
    affine_parser.add_argument("file", help="File containing hex-encoded ciphertext")
    affine_parser.add_argument("--min-score", type=float, default=0.7, 
                               help="Minimum English frequency score threshold (default: 0.7)")
    
    # Legacy positional arguments for backward compatibility
    parser.add_argument("targets", nargs="*", help="File paths or URLs to analyze (legacy)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-j", "--jobs", type=int, default=1, help="Number of parallel jobs (default: 1)")
    parser.add_argument("-o", "--output", help="Output results to file")
    
    args = parser.parse_args()
    
    # Handle affine subcommand
    if args.command == "affine":
        handle_affine_command(args.file, args.min_score)
        return
    
    # Default to scan if no subcommand but targets provided (legacy mode)
    if args.command is None and args.targets:
        args.command = "scan"
    
    if args.command == "scan" or args.command is None:
        # Use targets from subparser if available, otherwise from legacy args
        targets = getattr(args, 'targets', None)
        if not targets:
            parser.print_help()
            print("\nError: No targets specified.")
            sys.exit(1)
        # Merge targets from both sources
        if hasattr(args, 'targets') and args.targets:
            targets = args.targets
        all_results = []
        
        if args.jobs > 1:
            # Parallel processing
            print(f"[*] Using {args.jobs} parallel workers...\n")
            with ProcessPoolExecutor(max_workers=args.jobs) as executor:
                future_to_target = {
                    executor.submit(process_single_target, target, args.verbose): target 
                    for target in targets
                }
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                        if not args.verbose:
                            # Minimal output mode
                            if result['flags']:
                                print(f"[+] {target}: Found {len(result['flags'])} flag(s)")
                            elif result['errors']:
                                print(f"[-] {target}: {result['errors'][0]}")
                    except Exception as e:
                        print(f"[-] {target} generated exception: {e}")
        else:
            # Sequential processing
            for target in targets:
                result = process_single_target(target, args.verbose)
                all_results.append(result)
                if not args.verbose:
                    # Minimal output mode
                    if result['flags']:
                        print(f"[+] {target}: Found {len(result['flags'])} flag(s)")
                    elif result['errors']:
                        print(f"[-] {target}: {result['errors'][0]}")
        
        # Output results to file if requested
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(all_results, f, indent=2, default=str)
            print(f"\n[*] Results saved to {args.output}")
        
        # Summary
        total_flags = sum(len(r['flags']) for r in all_results)
        print(f"\n[*] Scan complete. Total flags found: {total_flags}")
    else:
        parser.print_help()


def handle_affine_command(file_path: str, min_score: float) -> None:
    """
    Handle the affine cipher bruteforce subcommand.
    
    Args:
        file_path: Path to file containing hex-encoded ciphertext
        min_score: Minimum English frequency score threshold
    """
    # Import here to avoid circular imports
    from .crypto.affine import bruteforce_affine
    
    print("[*] Affine Cipher Bruteforce Solver")
    print(f"[*] Reading ciphertext from: {file_path}")
    
    # Read and parse the input file
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
    except FileNotFoundError:
        print(f"[-] Error: File not found: {file_path}")
        sys.exit(1)
    except IOError as e:
        print(f"[-] Error reading file: {e}")
        sys.exit(1)
    
    # Try to parse as hex first
    try:
        # Remove any whitespace and common prefixes
        clean_content = content.replace(' ', '').replace('\n', '').replace('\r', '')
        if clean_content.startswith('0x'):
            clean_content = clean_content[2:]
        
        data = bytes.fromhex(clean_content)
        print(f"[*] Loaded {len(data)} bytes of ciphertext (hex decoded)")
    except ValueError:
        # Not valid hex, try raw bytes
        try:
            data = content.encode('utf-8')
            print(f"[*] Loaded {len(data)} bytes of ciphertext (raw)")
        except Exception as e:
            print(f"[-] Error parsing input: {e}")
            print("    Input should be hex-encoded bytes or plain text.")
            sys.exit(1)
    
    if len(data) == 0:
        print("[-] Error: Empty ciphertext.")
        sys.exit(1)
    
    print(f"[*] Bruteforcing affine cipher (a=odd 1-255, b=0-255)...")
    print(f"[*] Minimum score threshold: {min_score}")
    
    # Run the bruteforce
    results = bruteforce_affine(data, min_score=min_score)
    
    if not results:
        print(f"\n[-] No valid candidates found with score >= {min_score}")
        print("    Try lowering --min-score threshold.")
        return
    
    print(f"\n[*] Found {len(results)} candidate(s). Top results:")
    print("=" * 70)
    
    # Display top results (limit to 10 for readability)
    for i, result in enumerate(results[:10], 1):
        a = result['a']
        b = result['b']
        score = result['score']
        plaintext = result['result']
        
        # Truncate long results for display
        display_text = plaintext[:100] + "..." if len(plaintext) > 100 else plaintext
        
        print(f"\n[#{i}] Key: (a={a}, b={b}) | Score: {score:.2f}")
        print(f"    Plaintext: {display_text}")
    
    # Show full plaintext for best result
    if results:
        best = results[0]
        print("\n" + "=" * 70)
        print(f"[*] Best candidate (a={best['a']}, b={best['b']}, score={best['score']:.2f}):")
        print("-" * 70)
        print(best['result'])
        print("-" * 70)

if __name__ == "__main__":
    main()
