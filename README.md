# 🚩 FlagHound v2.0 - CTF Triage Automation

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**The fastest CTF triage tool to secure #1 place.** FlagHound automates file analysis, nested archive extraction, and obfuscation breaking to find flags in seconds, not hours.

## 🏆 Key Features

- ** Recursive Archive Extraction**: Automatically unzips nested `.zip`, `.tar`, `.gz`, `.bz2`, `.xz` up to **10 layers deep**. Includes safe guards against zip-bombs.
- ** XOR Brute-Force Engine**: Auto-detects and cracks single-byte and short multi-byte XOR keys using frequency analysis and flag pattern heuristics (`flag{`, `CTF{`, etc.).
- ** Smart Triage**:
  - Extracts binary strings from ELF/Mach-O/PE files.
  - Entropy analysis to detect encrypted/compressed regions.
  - Memory mapping (`mmap`) for handling GB-sized files without RAM exhaustion.
- ** Parallel Processing**: Scans directories using all CPU cores via `ProcessPoolExecutor`.
- ** Web Support**: Directly analyze URLs (`http/https`) without manual download.
- ** Auto-Decoding**: Recursively decodes Base64, Hex, Rot13, and URL encoding until plaintext emerges.
- ** Robustness**: Global error recovery (skips corrupt files), verbose logging, and safe path handling.

##  Installation

### From Source
```bash
git clone https://github.com/yourusername/flaghound.git
cd flaghound
pip install -e .
```

### Dependencies
FlagHound requires Python 3.8+ and the following packages (installed automatically):
- `chardet` (Character encoding detection)
- `requests` (Web fetching)

```bash
pip install -r requirements.txt
```

## 🚀 Usage

### Basic Scan
Scan a single file or directory:
```bash
flaghound /path/to/challenge.zip
flaghound ./ctf_challenges/misc/
```

### Scan from URL
Analyze a remote file directly:
```bash
flaghound https://example.com/challenge.bin
```

### Verbose Mode
Enable detailed logging to see extraction layers and analysis steps:
```bash
flaghound -v ./nested_archives/
```

### Output Control
Save results to a file:
```bash
flaghound -o results.txt ./big_dataset/
```

### Help
```bash
flaghound --help
```

## 🔍 How It Works

1. **Ingestion**: Accepts local paths or URLs.
2. **Extraction Loop**: Recursively unpacks archives (max depth 10). Detects magic bytes, not just extensions.
3. **Triage**:
   - Calculates entropy to spot encryption.
   - Extracts strings based on file type (binary vs text).
   - Runs crypto-decoders (Base64/Hex/Rot13 chains).
4. **Crypto Attack**: If high entropy or XOR patterns are detected, runs brute-force against common flag formats.
5. **Reporting**: Outputs found flags with file paths and context.

## 📂 Project Structure

```text
flaghound/
├── __init__.py       # Package exports
├── cli.py            # Entry point, argument parsing, parallel orchestration
├── triage.py         # Core analysis logic (strings, entropy, file types)
├── crypto.py         # Decoding (Base64, Hex, Rot13) + XOR brute-forcer
├── archives.py       # Recursive extraction logic (zip, tar, gz, etc.)
├── web.py            # URL fetching and content handling
├── utils.py          # Helper functions (flag regex, formatting)
├── setup.py          # Installation script
└── requirements.txt  # Python dependencies
```

## 🧪 Examples

### Nested Archive Challenge
```bash
$ flaghound -v challenge.zip
[+] Scanning: challenge.zip
[+] Detected: ZIP Archive
[+] Extracting layer 1: data.tar.gz
[+] Extracting layer 2: payload.xz
[+] Extracting layer 3: secret.txt
[+] Found Flag: flag{x0r_brut3_f0rc3_w0rk5}
```

### XOR Encrypted Binary
```bash
$ flaghound encrypted.bin
[+] Scanning: encrypted.bin
[+] High entropy detected (7.98)
[+] Attempting XOR brute-force...
[+] Key found: 0x5A
[+] Found Flag: CTF{h1dd3n_1n_pl41n_s1ght}
```

## ⚡ Performance Tips

- **Use `-v`** for large datasets to track progress.
- **Parallelism** is automatic; FlagHound utilizes all available cores.
- **Memory Safety**: Large files are memory-mapped, ensuring stability even on low-RAM machines.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
1. Fork the repo.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## 🙏 Acknowledgments

- Built for CTF players who hate manual triage.
- Inspired by the need for speed in competition environments.

---
**FlagHound v2.0** - *Find the flag, win the game.*
