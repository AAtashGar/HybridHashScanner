import pymisp
import sqlite3
import json
import os
import requests
import urllib3
import argparse
import glob
import csv
import re
import random
import threading
import queue
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = 'config.json'

# Define queues for each service
otx_queue = queue.Queue()
hybrid_queue = queue.Queue()
kaspersky_queue = queue.Queue()
vt_queue = queue.Queue()

# Dictionary to store results
results_dict = {}
results_lock = threading.Lock()  # Lock for thread-safe access to results_dict

def load_config():
    """Load configuration from file if it exists, otherwise return None."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def save_config(config):
    """Save configuration to file."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def get_user_input():
    """Prompt user for configuration details."""
    print("Please enter the following configuration details:")
    misp_url = input("MISP URL (default: https://127.0.0.1/): ") or "https://localhost/"
    misp_key = input("MISP API Key: ")
    otx_key = input("OTX API Key: ")
    vt_keys = input("VirusTotal API Keys (comma-separated if multiple): ")
    kaspersky_key = input("Kaspersky API Key: ")
    hybrid_key = input("Hybrid Analysis API Key: ")
    cache_db = input("SQLite cache database path (default: cache.db): ") or "cache.db"
    return {
        "misp_url": misp_url,
        "misp_key": misp_key,
        "otx_key": otx_key,
        "vt_keys": vt_keys.split(',') if vt_keys else [],
        "kaspersky_key": kaspersky_key,
        "hybrid_key": hybrid_key,
        "cache_db": cache_db
    }

def initialize_config():
    """Check and initialize configuration if file doesn't exist."""
    config = load_config()
    if not config:
        config = get_user_input()
        save_config(config)
    return config

def detect_hash_type(hash_str):
    """Detect the type of hash based on its length and content."""
    hash_str = hash_str.strip()
    if not hash_str:
        return 'empty'
    if not re.match(r'^[0-9a-fA-F]+$', hash_str):
        return 'invalid'
    length = len(hash_str)
    if length == 32:
        return 'md5'
    elif length == 40:
        return 'sha1'
    elif length == 64:
        return 'sha256'
    elif length == 128:
        return 'sha512'
    else:
        return 'unknown'

def extract_hashes_from_directory(directory, file_type):
    """Extract hashes from files in the directory based on file_type."""
    pattern = '*.csv' if file_type == 'csv' else '*.txt'
    files = glob.glob(os.path.join(directory, pattern))
    hashes = []
    for file in files:
        with open(file, 'r', encoding='utf-8-sig') as f:
            if file_type == 'csv':
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    for value in row:
                        hash_type = detect_hash_type(value)
                        if hash_type not in ['empty', 'invalid', 'unknown']:
                            hashes.append((value, hash_type))
            elif file_type == 'txt':
                for line in f:
                    hash_str = line.strip()
                    hash_type = detect_hash_type(hash_str)
                    if hash_type not in ['empty', 'invalid', 'unknown']:
                        hashes.append((hash_str, hash_type))
    return hashes

def check_cache(hash_value, hash_type):
    """Check if the hash exists in the SQLite cache and return (found, result)."""
    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT result FROM cache WHERE hash = ? AND hash_type = ?', (hash_value, hash_type))
    row = cursor.fetchone()
    conn.close()
    if row is not None:
        return True, json.loads(row[0])
    return False, None

def save_to_cache(hash_value, hash_type, result):
    """Save the result to the SQLite cache."""
    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO cache (hash, hash_type, result) VALUES (?, ?, ?)',
                   (hash_value, hash_type, json.dumps(result)))
    conn.commit()
    conn.close()

def search_misp(hash_value, hash_type):
    """Search for the hash in MISP. Return attributes if found, else None."""
    try:
        search_result = misp.search(controller='attributes', value=hash_value, type_attribute=hash_type)
        if search_result and 'Attribute' in search_result:
            attributes = search_result['Attribute']
            return attributes if attributes else None
        return None
    except Exception as e:
        print(f"Error searching MISP for {hash_value}: {e}")
        return None

def search_circl_hashlookup(hash_value, hash_type):
    """Search for the hash in CIRCL Hashlookup. Return result if found, else None."""
    url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_value}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error searching CIRCL Hashlookup for {hash_value}: {e}")
        return None

def search_otx(hash_value, hash_type):
    """Search for the hash in OTX. Return result if found, else None."""
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data.get('pulse_info', {}).get('count', 0) > 0:
                return data
            return None
        return None
    except Exception as e:
        print(f"Error searching OTX for {hash_value}: {e}")
        return None

def search_hybrid_analysis(hash_value, hash_type):
    """Search for the hash in Hybrid Analysis. Return result if found, else None."""
    url = f"https://www.hybrid-analysis.com/api/v2/search/hash?hash={hash_value}"
    headers = {"api-key": HYBRID_ANALYSIS_API_KEY, "User-Agent": "Falcon Sandbox"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error searching Hybrid Analysis for {hash_value}: {e}")
        return None

def search_kaspersky(hash_value, hash_type):
    """Search for the hash in Kaspersky Threat Intelligence Portal. Return result if found, else None."""
    url = f"https://opentip.kaspersky.com/api/v1/search/hash?request={hash_value}"
    headers = {"x-api-key": KASPERSKY_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error searching Kaspersky for {hash_value}: {e}")
        return None

def search_virustotal(hash_value, hash_type):
    """Search for the hash in VirusTotal. Return result if found, else None."""
    if not VT_API_KEYS:
        print("No VirusTotal API keys provided.")
        return None
    vt_api_key = random.choice(VT_API_KEYS)
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": vt_api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error searching VirusTotal for {hash_value}: {e}")
        return None

def otx_worker():
    """Worker thread for processing OTX requests with rate limiting."""
    while True:
        try:
            hash_value, hash_type = otx_queue.get()
            in_cache, cached_result = check_cache(hash_value, hash_type)
            if in_cache:
                with results_lock:
                    results_dict[hash_value] = cached_result
            else:
                result = search_otx(hash_value, hash_type)
                with results_lock:
                    results_dict[hash_value] = result
                save_to_cache(hash_value, hash_type, result)
            otx_queue.task_done()
            time.sleep(3600 / 10000)  # 0.36 seconds delay for 10,000 requests per hour
        except Exception as e:
            print(f"Error in OTX worker for {hash_value}: {e}")
            otx_queue.task_done()

def hybrid_worker():
    """Worker thread for processing Hybrid Analysis requests with rate limiting."""
    while True:
        try:
            hash_value, hash_type = hybrid_queue.get()
            in_cache, cached_result = check_cache(hash_value, hash_type)
            if in_cache:
                with results_lock:
                    results_dict[hash_value] = cached_result
            else:
                result = search_hybrid_analysis(hash_value, hash_type)
                with results_lock:
                    results_dict[hash_value] = result
                save_to_cache(hash_value, hash_type, result)
            hybrid_queue.task_done()
            time.sleep(60 / 5)  # 12 seconds delay for 5 requests per minute
        except Exception as e:
            print(f"Error in Hybrid Analysis worker for {hash_value}: {e}")
            hybrid_queue.task_done()

def kaspersky_worker():
    """Worker thread for processing Kaspersky requests with rate limiting."""
    while True:
        try:
            hash_value, hash_type = kaspersky_queue.get()
            in_cache, cached_result = check_cache(hash_value, hash_type)
            if in_cache:
                with results_lock:
                    results_dict[hash_value] = cached_result
            else:
                result = search_kaspersky(hash_value, hash_type)
                with results_lock:
                    results_dict[hash_value] = result
                save_to_cache(hash_value, hash_type, result)
            kaspersky_queue.task_done()
            time.sleep(60 / 1)  # 60 seconds delay for 1 request per minute
        except Exception as e:
            print(f"Error in Kaspersky worker for {hash_value}: {e}")
            kaspersky_queue.task_done()

def vt_worker():
    """Worker thread for processing VirusTotal requests with rate limiting."""
    while True:
        try:
            hash_value, hash_type = vt_queue.get()
            in_cache, cached_result = check_cache(hash_value, hash_type)
            if in_cache:
                with results_lock:
                    results_dict[hash_value] = cached_result
            else:
                result = search_virustotal(hash_value, hash_type)
                with results_lock:
                    results_dict[hash_value] = result
                save_to_cache(hash_value, hash_type, result)
            vt_queue.task_done()
            time.sleep(60 / 4)  # 15 seconds delay for 4 requests per minute
        except Exception as e:
            print(f"Error in VirusTotal worker for {hash_value}: {e}")
            vt_queue.task_done()

def process_hashes(hash_list, verbose=False):
    """Process a list of (hash_value, hash_type) tuples using multithreading."""
    for hash_value, hash_type in hash_list:
        hash_value = hash_value.strip()
        if not hash_value:
            continue
        
        if verbose:
            print(f"Processing {hash_value} ({hash_type})")
        
        # Check cache for MISP and CIRCL which do not require rate limiting
        in_cache, cached_result = check_cache(hash_value, hash_type)
        if in_cache:
            if verbose:
                print(f"Found in cache")
            with results_lock:
                results_dict[hash_value] = cached_result
            continue
        
        if verbose:
            print(f"Searching in MISP...")
        misp_result = search_misp(hash_value, hash_type)
        if misp_result is not None:
            if verbose:
                print(f"Found in MISP")
            with results_lock:
                results_dict[hash_value] = misp_result
            save_to_cache(hash_value, hash_type, misp_result)
            continue
        
        if verbose:
            print(f"Searching in CIRCL Hashlookup...")
        circl_result = search_circl_hashlookup(hash_value, hash_type)
        if circl_result is not None:
            if verbose:
                print(f"Found in CIRCL Hashlookup")
            with results_lock:
                results_dict[hash_value] = circl_result
            save_to_cache(hash_value, hash_type, circl_result)
            continue
        
        # Add to queues for rate-limited services
        if verbose:
            print(f"Adding to queues for OTX, Hybrid, Kaspersky, VirusTotal...")
        otx_queue.put((hash_value, hash_type))
        hybrid_queue.put((hash_value, hash_type))
        kaspersky_queue.put((hash_value, hash_type))
        vt_queue.put((hash_value, hash_type))

    # Wait for all queues to be processed
    otx_queue.join()
    hybrid_queue.join()
    kaspersky_queue.join()
    vt_queue.join()
    
    return results_dict

def save_to_json(results, filename='results.json'):
    """Save results to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Check hashes against various threat intelligence services.")
        parser.add_argument('-directory', help="Path to the directory containing files with hashes")
        parser.add_argument('-file_type', choices=['csv', 'txt'], help="Type of files to process (csv or txt)")
        parser.add_argument('-hash', help="A single hash to check directly")
        parser.add_argument('-output', default='results.json', help="Output JSON file (default: results.json)")
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
        args = parser.parse_args()

        config = initialize_config()
        MISP_URL = config['misp_url']
        MISP_KEY = config['misp_key']
        OTX_API_KEY = config['otx_key']
        VT_API_KEYS = config['vt_keys']
        KASPERSKY_API_KEY = config['kaspersky_key']
        HYBRID_ANALYSIS_API_KEY = config['hybrid_key']
        CACHE_DB = config['cache_db']

        if args.hash and (args.directory or args.file_type):
            print("Error: Cannot provide both -hash and -directory/-file_type")
            exit(1)
        elif args.hash:
            hash_value = args.hash
            hash_type = detect_hash_type(hash_value)
            if hash_type in ['empty', 'invalid', 'unknown']:
                print(f"Invalid hash: {hash_value}")
                exit(1)
            hash_list = [(hash_value, hash_type)]
        elif args.directory and args.file_type:
            hash_list = extract_hashes_from_directory(args.directory, args.file_type)
            if not hash_list:
                print("No valid hashes found in the directory.")
                exit(0)
        else:
            print("Error: Provide either -hash or both -directory and -file_type")
            parser.print_help()
            exit(1)

        # Connect to MISP
        misp = pymisp.PyMISP(MISP_URL, MISP_KEY, ssl=False)

        # Create the cache table if it doesn't exist
        conn = sqlite3.connect(CACHE_DB)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                hash TEXT,
                hash_type TEXT,
                result TEXT,
                PRIMARY KEY (hash, hash_type)
            )
        ''')
        conn.commit()
        conn.close()

        # Start worker threads
        threading.Thread(target=otx_worker, daemon=True).start()
        threading.Thread(target=hybrid_worker, daemon=True).start()
        threading.Thread(target=kaspersky_worker, daemon=True).start()
        threading.Thread(target=vt_worker, daemon=True).start()

        print(f"Processing {len(hash_list)} hash(es)...")
        results = process_hashes(hash_list, args.verbose)
        save_to_json(results, args.output)
        print(f"Results saved to '{args.output}' and cached in '{CACHE_DB}'.")
    except Exception as e:
        print(f"An error occurred: {e}")