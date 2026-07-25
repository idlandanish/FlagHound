import argparse
import sys
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from . import triage, crypto, archives, web, utils

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
    parser.add_argument("targets", nargs="+", help="File paths or URLs to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-j", "--jobs", type=int, default=1, help="Number of parallel jobs (default: 1)")
    parser.add_argument("-o", "--output", help="Output results to file")
    args = parser.parse_args()
    
    all_results = []
    
    if args.jobs > 1:
        # Parallel processing
        print(f"[*] Using {args.jobs} parallel workers...\n")
        with ProcessPoolExecutor(max_workers=args.jobs) as executor:
            future_to_target = {
                executor.submit(process_single_target, target, args.verbose): target 
                for target in args.targets
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
        for target in args.targets:
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

if __name__ == "__main__":
    main()
