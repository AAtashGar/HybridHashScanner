# HybridHashScanner

HybridHashScanner is a powerful command-line tool designed for security researchers to analyze file hashes against multiple threat intelligence platforms, including MISP, CIRCL Hashlookup, OTX, Kaspersky, and VirusTotal. It offers flexible input options, caching for performance, multithreaded processing, and optional Tor support for anonymity.

## Features
- Analyze single hashes or process directories of CSV/TXT files
- Supports MD5, SHA1, SHA256, and SHA512 hash types
- Integrates with MISP, CIRCL Hashlookup, OTX, Kaspersky, and VirusTotal
- Caches results in an SQLite database to optimize repeated queries
- Multithreaded workers for OTX and VirusTotal with rate limit handling
- Optional Tor integration for anonymous VirusTotal lookups
- Multiple modes: normal, quick, and extra with user prompts
- Outputs results in JSON and displays summaries in the terminal

## Installation

### Prerequisites
- **Python 3.x**: Required to run the script.
- **Tor**: Optional, for anonymous VirusTotal queries.

### Dependencies
Install the required Python libraries using pip:
```
pip install pymisp requests tabulate pyfiglet colorama stem
```

### Steps
1. Clone the repository:
   ```
   git clone https://github.com/AAtashGar/HybridHashScanner.git
   cd HybridHashScanner
   ```
2. Install the dependencies as shown above.
3. (Optional) Install Tor and ensure it’s accessible in your PATH or specify its path during configuration.

## Usage
Run the tool with:
```
python HybridHashScanner.py [options]
```

### Command-Line Options
| Option              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `-directory <path>` | Path to a directory containing hash files (CSV or TXT)                     |
| `-file_type <type>` | File type to process: `csv` or `txt` (required with `-directory`)          |
| `-hash <hash>`      | Single hash to analyze directly                                            |
| `-output <file>`    | Output JSON file path (default: `results.json`)                            |
| `-v, --verbose`     | Enable verbose output for detailed logging                                 |
| `-service <name>`   | Service to query: `misp`, `hashlookup`, `otx`, `kaspersky`, `virustotal`, or `all` (default: `all`) |
| `--view <hash>`     | View cached results for a specific hash                                    |
| `--vt_view <hash>`  | View only VirusTotal cached results for a specific hash                    |
| `--vt_confirm11`     | Confirm found hashes in VirusTotal (used with normal/extra modes)          |
| `-q, --quick`       | Quick mode: sequential checks with VirusTotal confirmation via Tor         |
| `-e, --extra`       | Extra mode: multi-phase checks with user prompts                           |

### Examples
1. **Analyze a Single Hash:**
   ```
   python HybridHashScanner.py -hash 0123456789abcdef0123456789abcdef
   ```
   Checks the hash against all services and saves results to `results.json`.

2. **Process a Directory of CSV Files:**
   ```
   python HybridHashScanner.py -directory ./hashes -file_type csv
   ```
   Processes all CSV files in the `hashes` directory.

3. **Quick Mode with TXT Files:**
   ```
   python HybridHashScanner.py -directory ./hashes -file_type txt -q
   ```
   Sequentially checks hashes and confirms findings in VirusTotal via Tor.

4. **View Cached Results:**
   ```
   python HybridHashScanner.py --view 0123456789abcdef0123456789abcdef
   ```
   Displays cached results for the specified hash.

## Configuration
On first run, the tool prompts for:
- MISP URL and API Key
- OTX API Key
- VirusTotal API Keys (comma-separated for multiple)
- Kaspersky API Key
- SQLite cache database path (default: `cache.db`)
- Tor executable path (optional)

These are saved to `config.json` for subsequent runs.

## Wiki
For detailed technical documentation, code breakdowns, and advanced usage, see the [Wiki](https://github.com/AAtashGar/HybridHashScanner/wiki).