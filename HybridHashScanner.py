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
from tabulate import tabulate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = 'config.json'
CACHE_DB = 'cache.db'

# Define queues for each service
otx_queue = queue.Queue()
kaspersky_queue = queue.Queue()
vt_queue = queue.Queue()

# Dictionary to store results
results_dict = {}
results_lock = threading.Lock()

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
    misp_url = input("MISP URL (default: https://127.0.0.1/): ") or "https://127.0.0.1/"
    misp_key = input("MISP API Key: ")
    otx_key = input("OTX API Key: ")
    vt_keys = input("VirusTotal API Keys (comma-separated if multiple): ")
    kaspersky_key = input("Kaspersky API Key: ")
    malwarebazaar_key = input("MalwareBazaar API Key (optional): ") or ""
    cache_db = input("SQLite cache database path (default: cache.db): ") or "cache.db"
    return {
        "misp_url": misp_url,
        "misp_key": misp_key,
        "otx_key": otx_key,
        "vt_keys": vt_keys.split(',') if vt_keys else [],
        "kaspersky_key": kaspersky_key,
        "malwarebazaar_key": malwarebazaar_key,
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
    """Check if the hash exists in the SQLite cache and return the results dictionary."""
    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT result FROM cache WHERE hash = ? AND hash_type = ?', (hash_value, hash_type))
    row = cursor.fetchone()
    conn.close()
    if row is not None:
        return json.loads(row[0])
    return {}

def save_to_cache(hash_value, hash_type, results):
    """Save the results dictionary to the SQLite cache."""
    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO cache (hash, hash_type, result) VALUES (?, ?, ?)',
                   (hash_value, hash_type, json.dumps(results)))
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
    if hash_type not in ['md5', 'sha1', 'sha256']:
        return None
    url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_value}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return None
        else:
            print(f"Error querying CIRCL Hashlookup for {hash_value}: {response.status_code}")
            return None
    except requests.exceptions.Timeout:
        print(f"Timeout searching CIRCL Hashlookup for {hash_value}")
        return None
    except Exception as e:
        print(f"Error querying CIRCL Hashlookup for {hash_value}: {e}")
        return None

def search_otx(hash_value, hash_type):
    """Search for the hash in OTX. Return result if found, else None."""
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('pulse_info', {}).get('count', 0) > 0:
                return data
            return None
        return None
    except requests.exceptions.Timeout:
        print(f"Timeout searching OTX for {hash_value}")
        return None
    except Exception as e:
        print(f"Error searching OTX for {hash_value}: {e}")
        return None

def search_kaspersky(hash_value, hash_type):
    """Search for the hash in Kaspersky Threat Intelligence Portal. Return result if not Clean, else None."""
    url = f"https://opentip.kaspersky.com/api/v1/search/hash?request={hash_value}"
    headers = {"x-api-key": KASPERSKY_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            file_status = result.get('FileGeneralInfo', {}).get('FileStatus')
            if file_status and file_status != 'Clean':
                return result
            return None
        return None
    except requests.exceptions.Timeout:
        print(f"Timeout searching Kaspersky for {hash_value}")
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
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except requests.exceptions.Timeout:
        print(f"Timeout searching VirusTotal for {hash_value}")
        return None
    except Exception as e:
        print(f"Error searching VirusTotal for {hash_value}: {e}")
        return None

def otx_worker():
    """Worker thread for processing OTX requests with rate limiting."""
    print("OTX worker started!")
    while True:
        try:
            hash_value, hash_type = otx_queue.get()
            print(f"OTX worker processing {hash_value}")
            cached_results = check_cache(hash_value, hash_type)
            if 'otx' not in cached_results or cached_results['otx'] is None:
                result = search_otx(hash_value, hash_type)
                cached_results['otx'] = result
                save_to_cache(hash_value, hash_type, cached_results)
                print(f"OTX result saved for {hash_value}")
            otx_queue.task_done()
            time.sleep(3600 / 10000)
        except Exception as e:
            print(f"Error in OTX worker for {hash_value}: {e}")
            otx_queue.task_done()

def kaspersky_worker():
    """Worker thread for processing Kaspersky requests with rate limiting."""
    print("Kaspersky worker started!")
    while True:
        try:
            hash_value, hash_type = kaspersky_queue.get()
            print(f"Kaspersky worker processing {hash_value}")
            cached_results = check_cache(hash_value, hash_type)
            if 'kaspersky' not in cached_results or cached_results['kaspersky'] is None:
                result = search_kaspersky(hash_value, hash_type)
                cached_results['kaspersky'] = result
                save_to_cache(hash_value, hash_type, cached_results)
                print(f"Kaspersky result saved for {hash_value}")
            kaspersky_queue.task_done()
            time.sleep(60 / 1)
        except Exception as e:
            print(f"Error in Kaspersky worker for {hash_value}: {e}")
            kaspersky_queue.task_done()

def vt_worker():
    """Worker thread for processing VirusTotal requests with rate limiting."""
    print("VirusTotal worker started!")
    while True:
        try:
            hash_value, hash_type = vt_queue.get()
            print(f"VT worker processing {hash_value}")
            cached_results = check_cache(hash_value, hash_type)
            if 'virustotal' not in cached_results or cached_results['virustotal'] is None:
                result = search_virustotal(hash_value, hash_type)
                cached_results['virustotal'] = result
                save_to_cache(hash_value, hash_type, cached_results)
                print(f"VT result saved for {hash_value}")
            vt_queue.task_done()
            time.sleep(60 / 4)
        except Exception as e:
            print(f"Error in VT worker for {hash_value}: {e}")
            vt_queue.task_done()

def process_hashes(hash_list, verbose=False, two_phase=False):
    """Process a list of (hash_value, hash_type) tuples based on selected service."""
    if two_phase:
        initial_services = ['misp', 'hashlookup', 'otx', 'kaspersky']
        for hash_value, hash_type in hash_list:
            hash_value = hash_value.strip()
            if not hash_value:
                continue
            if verbose:
                print(f"Processing {hash_value} ({hash_type})")
            cached_results = check_cache(hash_value, hash_type)
            for service in initial_services:
                if service not in cached_results or cached_results[service] is None:
                    if service == 'misp':
                        if verbose:
                            print(f"Searching in MISP...")
                        result = search_misp(hash_value, hash_type)
                        cached_results[service] = result
                        print(f"MISP search done for {hash_value}")
                    elif service == 'hashlookup':
                        if verbose:
                            print(f"Searching in CIRCL Hashlookup...")
                        result = search_circl_hashlookup(hash_value, hash_type)
                        cached_results[service] = result
                        print(f"Hashlookup search done for {hash_value}")
                    elif service == 'otx':
                        otx_queue.put((hash_value, hash_type))
                        print(f"Added {hash_value} to OTX queue")
                    elif service == 'kaspersky':
                        kaspersky_queue.put((hash_value, hash_type))
                        print(f"Added {hash_value} to Kaspersky queue")
            save_to_cache(hash_value, hash_type, cached_results)

        print(f"OTX queue size before join: {otx_queue.qsize()}")
        print("Waiting for OTX queue to finish...")
        otx_queue.join()
        print("OTX queue finished!")
        print(f"OTX queue size after join: {otx_queue.qsize()}")

        print(f"Kaspersky queue size before join: {kaspersky_queue.qsize()}")
        print("Waiting for Kaspersky queue to finish...")
        kaspersky_queue.join()
        print("Kaspersky queue finished!")
        print(f"Kaspersky queue size after join: {kaspersky_queue.qsize()}")

        unfound_hashes = []
        for hash_value, hash_type in hash_list:
            cached_results = check_cache(hash_value, hash_type)
            if all(cached_results.get(service) is None for service in initial_services):
                unfound_hashes.append((hash_value, hash_type))

        total_hashes = len(hash_list)
        found_in_misp = sum(1 for (h, t) in hash_list if check_cache(h, t).get('misp') is not None)
        found_in_hashlookup = sum(1 for (h, t) in hash_list if check_cache(h, t).get('hashlookup') is not None)
        found_in_otx = sum(1 for (h, t) in hash_list if check_cache(h, t).get('otx') is not None)
        found_in_kaspersky = sum(1 for (h, t) in hash_list if check_cache(h, t).get('kaspersky') is not None)
        not_found = len(unfound_hashes)

        print(f"\nProcessed {total_hashes} hashes:")
        print(f"Found in MISP: {found_in_misp}")
        print(f"Found in CIRCL Hashlookup: {found_in_hashlookup}")
        print(f"Found in OTX: {found_in_otx}")
        print(f"Found in Kaspersky: {found_in_kaspersky}")
        print(f"Not found in any service: {not_found}")

        if not_found > 0:
            answer = input(f"Do you want to check the {not_found} not found hashes in VirusTotal? (yes/no): ").strip().lower()
            if answer == 'yes':
                for hash_value, hash_type in unfound_hashes:
                    vt_queue.put((hash_value, hash_type))
                print(f"VT queue size before join: {vt_queue.qsize()}")
                print("Waiting for VT queue to finish...")
                vt_queue.join()
                print("VT queue finished!")
                print(f"VT queue size after join: {vt_queue.qsize()}")

    else:
        services_to_search = [args.service] if args.service != 'all' else ['misp', 'hashlookup', 'otx', 'kaspersky', 'virustotal']
        for hash_value, hash_type in hash_list:
            hash_value = hash_value.strip()
            if not hash_value:
                continue
            if verbose:
                print(f"Processing {hash_value} ({hash_type})")
            cached_results = check_cache(hash_value, hash_type)
            for service in services_to_search:
                if service not in cached_results or cached_results[service] is None:
                    if service == 'misp':
                        if verbose:
                            print(f"Searching in MISP...")
                        result = search_misp(hash_value, hash_type)
                        cached_results[service] = result
                        print(f"MISP search done for {hash_value}")
                    elif service == 'hashlookup':
                        if verbose:
                            print(f"Searching in CIRCL Hashlookup...")
                        result = search_circl_hashlookup(hash_value, hash_type)
                        cached_results[service] = result
                        print(f"Hashlookup search done for {hash_value}")
                    elif service == 'otx':
                        otx_queue.put((hash_value, hash_type))
                        print(f"Added {hash_value} to OTX queue")
                    elif service == 'kaspersky':
                        kaspersky_queue.put((hash_value, hash_type))
                        print(f"Added {hash_value} to Kaspersky queue")
                    elif service == 'virustotal':
                        vt_queue.put((hash_value, hash_type))
                        print(f"Added {hash_value} to VT queue")
            save_to_cache(hash_value, hash_type, cached_results)

        if 'otx' in services_to_search:
            print(f"OTX queue size before join: {otx_queue.qsize()}")
            print("Waiting for OTX queue to finish...")
            otx_queue.join()
            print("OTX queue finished!")
            print(f"OTX queue size after join: {otx_queue.qsize()}")
        if 'kaspersky' in services_to_search:
            print(f"Kaspersky queue size before join: {kaspersky_queue.qsize()}")
            print("Waiting for Kaspersky queue to finish...")
            kaspersky_queue.join()
            print("Kaspersky queue finished!")
            print(f"Kaspersky queue size after join: {kaspersky_queue.qsize()}")
        if 'virustotal' in services_to_search:
            print(f"VT queue size before join: {vt_queue.qsize()}")
            print("Waiting for VT queue to finish...")
            vt_queue.join()
            print("VT queue finished!")
            print(f"VT queue size after join: {vt_queue.qsize()}")

    results = {}
    for hash_value, hash_type in hash_list:
        results[hash_value] = check_cache(hash_value, hash_type)
    return results

def save_to_json(results, filename='results.json'):
    """Save results to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)

def print_summary_table(results):
    """Print a summary table of the results with grid lines."""
    table = []
    for hash_value, data in results.items():
        found_services = [service for service, result in data.items() if result is not None]
        if found_services:
            found_in = ", ".join(found_services)
            hits = len(found_services)
        else:
            found_in = "Not found in any service"
            hits = 0
        table.append([hash_value, found_in, hits])
    headers = ["Hash", "Found in", "Hits"]
    print(tabulate(table, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Check hashes against various threat intelligence services.")
        parser.add_argument('-directory', help="Path to the directory containing files with hashes")
        parser.add_argument('-file_type', choices=['csv', 'txt'], help="Type of files to process (csv or txt)")
        parser.add_argument('-hash', help="A single hash to check directly")
        parser.add_argument('-output', default='results.json', help="Output JSON file (default: results.json)")
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
        parser.add_argument('-service', choices=['misp', 'hashlookup', 'otx', 'kaspersky', 'virustotal', 'all'],
                            default='all', help="Service to search the hash in (default: all)")
        parser.add_argument('--view', help="View full details of a specific hash from the cache")
        args = parser.parse_args()

        config = initialize_config()
        MISP_URL = config['misp_url']
        MISP_KEY = config['misp_key']
        OTX_API_KEY = config['otx_key']
        VT_API_KEYS = config['vt_keys']
        KASPERSKY_API_KEY = config['kaspersky_key']
        MALWAREBAZAAR_API_KEY = config['malwarebazaar_key']
        CACHE_DB = config['cache_db']

        if args.view:
            hash_value = args.view
            hash_type = detect_hash_type(hash_value)
            if hash_type in ['empty', 'invalid', 'unknown']:
                print(f"Invalid hash: {hash_value}")
                exit(1)
            cached_result = check_cache(hash_value, hash_type)
            if cached_result:
                print("\nDetailed results for hash:", hash_value)
                print(json.dumps(cached_result, indent=4))
            else:
                print(f"Hash {hash_value} not found in cache.")
            exit(0)

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

        if args.service in ['misp', 'all']:
            misp = pymisp.PyMISP(MISP_URL, MISP_KEY, ssl=False)
        else:
            misp = None

        conn = sqlite3.connect(CACHE_DB)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS cache (
                            hash TEXT,
                            hash_type TEXT,
                            result TEXT,
                            PRIMARY KEY (hash, hash_type)
                          )''')
        conn.commit()
        conn.close()

        threading.Thread(target=otx_worker, daemon=True).start()
        threading.Thread(target=kaspersky_worker, daemon=True).start()
        threading.Thread(target=vt_worker, daemon=True).start()

        if args.verbose:
            N = len(hash_list)
            estimated_seconds = N * 60
            if estimated_seconds < 60:
                print(f"Estimated completion time: {estimated_seconds} seconds")
            elif estimated_seconds < 3600:
                minutes = estimated_seconds // 60
                seconds = estimated_seconds % 60
                print(f"Estimated completion time: {minutes} minutes {seconds} seconds")
            else:
                hours = estimated_seconds // 3600
                minutes = (estimated_seconds % 3600) // 60
                print(f"Estimated completion time: {hours} hours {minutes} minutes")

        print(f"Processing {len(hash_list)} hash(es)...")
        two_phase = args.directory and args.file_type and args.service == 'all'
        results = process_hashes(hash_list, args.verbose, two_phase=two_phase)
        save_to_json(results, args.output)
        print(f"Results saved to '{args.output}' and cached in '{CACHE_DB}'.")

        print("\nSummary of results:")
        print_summary_table(results)
    except Exception as e:
        print(f"An error occurred: {e}")