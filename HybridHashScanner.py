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
import shutil
from pyfiglet import Figlet
from colorama import init, Fore
from stem import Signal
from stem.control import Controller
from stem.process import launch_tor_with_config

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for colored terminal output
init()

# Get terminal width for formatting
terminal_width = shutil.get_terminal_size().columns

# Set box width to a fixed value of 60 characters
box_width = 60

# Create Figlet object with 'small' font for logo
f = Figlet(font='small')

# Render the logo
logo = f.renderText('HybridHashScanner')

# Print the logo in white
print(Fore.WHITE + logo + Fore.RESET)

# Define the information lines
info_lines = [
    "Version: 1.0.0",
    "HybridHashScanner - Hash Analysis Tool",
    " MISP, VirusTotal, OTX, CycleWorks, OpenTip",
    " A.AtashGar (atashgar7@gmail.com)",
    " Licensed under MIT License",
    "> https://github.com/AAtashGar/HybridHashScanner",
    "> https://www.linkedin.com/in/ali-atashgar/"
]

# Function to center text within the box
def center_text(text, width):
    return text.center(width)

# Create and print the top border
top_border = '┌' + '─' * (box_width) + '┐'
print(Fore.WHITE + top_border + Fore.RESET)

# Print each info line centered within the box
for line in info_lines:
    centered_line = center_text(line, box_width)
    print(Fore.WHITE + '│' + centered_line + '│' + Fore.RESET)

# Create and print the bottom border
bottom_border = '└' + '─' * (box_width) + '┘'
print(Fore.WHITE + bottom_border + Fore.RESET)

# Configuration file and cache database paths
CONFIG_FILE = 'config.json'
CACHE_DB = 'cache.db'

# Define queues for OTX and VirusTotal workers
otx_queue = queue.Queue()
vt_queue = queue.Queue()

# Dictionary to store results with thread safety
results_dict = {}
results_lock = threading.Lock()

# Global variables to track worker status
otx_worker_started = False
vt_worker_started = False

# Global variables for Tor
tor_controller = None
tor_process = None

def load_config():
    # Load configuration from file if it exists, otherwise return None
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def save_config(config):
    # Save configuration to file
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def get_user_input():
    # Prompt user for configuration details
    print("Please enter the following configuration details:")
    misp_url = input("MISP URL (default: https://127.0.0.1/): ") or "https://127.0.0.1/"
    misp_key = input("MISP API Key: ")
    otx_key = input("OTX API Key: ")
    vt_keys = input("VirusTotal API Keys (comma-separated if multiple): ")
    kaspersky_key = input("Kaspersky API Key: ")
    cache_db = input("SQLite cache database path (default: cache.db): ") or "cache.db"
    tor_path = input("Path to Tor executable (leave empty to use system PATH): ") or ""
    return {
        "misp_url": misp_url,
        "misp_key": misp_key,
        "otx_key": otx_key,
        "vt_keys": vt_keys.split(',') if vt_keys else [],
        "kaspersky_key": kaspersky_key,
        "cache_db": cache_db,
        "tor_path": tor_path
    }

def initialize_config():
    # Check and initialize configuration if file doesn't exist
    config = load_config()
    if not config:
        config = get_user_input()
        save_config(config)
    return config

def detect_hash_type(hash_str):
    # Detect the type of hash based on its length and content
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
    # Extract hashes from files in the directory based on file_type
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
    # Check if the hash exists in the SQLite cache and return the results dictionary
    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT result FROM cache WHERE hash = ? AND hash_type = ?', (hash_value, hash_type))
    row = cursor.fetchone()
    conn.close()
    if row is not None:
        return json.loads(row[0])
    return {}

def save_to_cache(hash_value, hash_type, results):
    # Save the results dictionary to the SQLite cache
    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO cache (hash, hash_type, result) VALUES (?, ?, ?)',
                   (hash_value, hash_type, json.dumps(results)))
    conn.commit()
    conn.close()

def search_misp(hash_value, hash_type, verbose=False):
    # Search for the hash in MISP. Return attributes if found, else None
    try:
        if verbose:
            print(Fore.BLUE + f"[+] Searching in MISP for {hash_value}..." + Fore.RESET)
        search_result = misp.search(controller='attributes', value=hash_value, type_attribute=hash_type)
        if search_result and 'Attribute' in search_result:
            attributes = search_result['Attribute']
            if verbose:
                print(Fore.GREEN + f"[+] MISP search done for {hash_value}" + Fore.RESET)
            return attributes if attributes else None
        if verbose:
            print(Fore.GREEN + f"[+] MISP search done for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        if verbose:
            print(Fore.RED + f"[+] Error searching MISP for {hash_value}: {e}" + Fore.RESET)
        return None

def search_circl_hashlookup(hash_value, hash_type, verbose=False):
    # Search for the hash in CIRCL Hashlookup. Return result if found, else None
    if hash_type not in ['md5', 'sha1', 'sha256']:
        return None
    url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_value}"
    try:
        if verbose:
            print(Fore.BLUE + f"[+] Searching in CIRCL Hashlookup for {hash_value}..." + Fore.RESET)
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            if verbose:
                print(Fore.GREEN + f"[+] CIRCL Hashlookup search done for {hash_value}" + Fore.RESET)
            return response.json()
        elif response.status_code == 404:
            if verbose:
                print(Fore.GREEN + f"[+] CIRCL Hashlookup search done for {hash_value}" + Fore.RESET)
            return None
        else:
            if verbose:
                print(Fore.RED + f"[+] Error querying CIRCL Hashlookup for {hash_value}: {response.status_code}" + Fore.RESET)
            return None
    except requests.exceptions.Timeout:
        if verbose:
            print(Fore.RED + f"[+] Timeout searching CIRCL Hashlookup for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        if verbose:
            print(Fore.RED + f"[+] Error querying CIRCL Hashlookup for {hash_value}: {e}" + Fore.RESET)
        return None

def search_otx(hash_value, hash_type, verbose=False):
    # Search for the hash in OTX. Return result if found, else None
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        if verbose:
            print(Fore.BLUE + f"[+] Searching in OTX for {hash_value}..." + Fore.RESET)
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('pulse_info', {}).get('count', 0) > 0:
                if verbose:
                    print(Fore.GREEN + f"[+] OTX search done for {hash_value}" + Fore.RESET)
                return data
            if verbose:
                print(Fore.GREEN + f"[+] OTX search done for {hash_value}" + Fore.RESET)
            return None
        if verbose:
            print(Fore.GREEN + f"[+] OTX search done for {hash_value}" + Fore.RESET)
        return None
    except requests.exceptions.Timeout:
        if verbose:
            print(Fore.RED + f"[+] Timeout searching OTX for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        if verbose:
            print(Fore.RED + f"[+] Error searching OTX for {hash_value}: {e}" + Fore.RESET)
        return None

def search_kaspersky(hash_value, hash_type, verbose=False):
    # Search for the hash in Kaspersky Threat Intelligence Portal. Return result if not Clean, else None
    url = f"https://opentip.kaspersky.com/api/v1/search/hash?request={hash_value}"
    headers = {"x-api-key": KASPERSKY_API_KEY}
    try:
        if verbose:
            print(Fore.BLUE + f"[+] Searching in Kaspersky for {hash_value}..." + Fore.RESET)
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            file_status = result.get('FileGeneralInfo', {}).get('FileStatus')
            if file_status and file_status != 'Clean':
                if verbose:
                    print(Fore.GREEN + f"[+] Kaspersky search done for {hash_value}" + Fore.RESET)
                return result
            if verbose:
                print(Fore.GREEN + f"[+] Kaspersky search done for {hash_value}" + Fore.RESET)
            return None
        if verbose:
            print(Fore.GREEN + f"[+] Kaspersky search done for {hash_value}" + Fore.RESET)
        return None
    except requests.exceptions.Timeout:
        if verbose:
            print(Fore.RED + f"[+] Timeout searching Kaspersky for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        if verbose:
            print(Fore.RED + f"[+] Error searching Kaspersky for {hash_value}: {e}" + Fore.RESET)
        return None

def start_tor():
    # Start a Tor instance
    global tor_controller, tor_process
    try:
        print(f"[+] Using Tor path: {TOR_PATH}")
        print("[+] Starting Tor...")
        tor_config = {'SocksPort': '9150', 'ControlPort': '9151'}
        if TOR_PATH:
            tor_process = launch_tor_with_config(
                config=tor_config,
                tor_cmd=TOR_PATH,
                take_ownership=True
            )
        else:
            tor_process = launch_tor_with_config(
                config=tor_config,
                take_ownership=True
            )
        tor_controller = Controller.from_port(port=9151)
        tor_controller.authenticate()
        
        while True:
            progress = tor_controller.get_info("status/bootstrap-phase")
            if "PROGRESS=100" in progress:
                print("[+] Tor is fully bootstrapped!")
                break
            time.sleep(1)
    except Exception as e:
        print(f"[+] Error starting Tor: {e}")
        tor_controller = None
        tor_process = None

def stop_tor():
    # Stop the Tor instance
    global tor_controller, tor_process
    if tor_controller:
        tor_controller.close()
    if tor_process:
        tor_process.terminate()
        print("[+] Tor stopped.")

def search_virustotal(hash_value, hash_type, verbose=False, use_tor=False):
    # Search for the hash in VirusTotal with or without Tor, returning only specific fields
    if not VT_API_KEYS:
        if verbose:
            print(Fore.RED + "[+] No VirusTotal API keys provided." + Fore.RESET)
        return None
    vt_api_key = random.choice(VT_API_KEYS)
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": vt_api_key}
    proxies = {'http': 'socks5://127.0.0.1:9150', 'https': 'socks5://127.0.0.1:9150'} if use_tor else None
    
    try:
        if verbose:
            print(Fore.BLUE + f"[+] Searching in VirusTotal for {hash_value} {'via Tor' if use_tor else ''}..." + Fore.RESET)
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
        if response.status_code == 200:
            if verbose:
                print(Fore.GREEN + f"[+] VirusTotal search done for {hash_value}" + Fore.RESET)
            # Extract only last_analysis_stats, tags, and names
            full_result = response.json()
            filtered_result = {
                "last_analysis_stats": full_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
                "tags": full_result.get("data", {}).get("attributes", {}).get("tags", []),
                "names": full_result.get("data", {}).get("attributes", {}).get("names", [])
            }
            return filtered_result
        if verbose:
            print(Fore.GREEN + f"[+] VirusTotal search done for {hash_value}" + Fore.RESET)
        return None
    except requests.exceptions.Timeout:
        if verbose:
            print(Fore.RED + f"[+] Timeout searching VirusTotal for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        if verbose:
            print(Fore.RED + f"[+] Error searching VirusTotal for {hash_value}: {e}" + Fore.RESET)
        return None

def otx_worker():
    # Worker thread for processing OTX requests with rate limiting
    while True:
        hash_value, hash_type, verbose = otx_queue.get()
        if verbose:
            print(Fore.YELLOW + f"[+] OTX worker processing {hash_value}" + Fore.RESET)
        cached_results = check_cache(hash_value, hash_type)
        if 'otx' not in cached_results or cached_results['otx'] is None:
            result = search_otx(hash_value, hash_type, verbose)
            cached_results['otx'] = result
            save_to_cache(hash_value, hash_type, cached_results)
            if verbose:
                print(Fore.GREEN + f"[+] OTX result saved for {hash_value}" + Fore.RESET)
        otx_queue.task_done()
        time.sleep(3600 / 10000)  # Rate limit for OTX

def vt_worker():
    # Worker thread for processing VirusTotal requests with rate limiting
    while True:
        hash_value, hash_type, verbose = vt_queue.get()
        if verbose:
            print(Fore.YELLOW + f"[+] VT worker processing {hash_value}" + Fore.RESET)
        cached_results = check_cache(hash_value, hash_type)
        if 'virustotal' not in cached_results or cached_results['virustotal'] is None:
            result = search_virustotal(hash_value, hash_type, verbose)
            cached_results['virustotal'] = result
            save_to_cache(hash_value, hash_type, cached_results)
            if verbose:
                print(Fore.GREEN + f"[+] VT result saved for {hash_value}" + Fore.RESET)
        vt_queue.task_done()
        time.sleep(60 / 4)  # Rate limit for VirusTotal

def start_otx_worker():
    # Start the OTX worker thread if not already started
    global otx_worker_started
    if not otx_worker_started:
        threading.Thread(target=otx_worker, daemon=True).start()
        otx_worker_started = True

def start_vt_worker():
    # Start the VirusTotal worker thread if not already started
    global vt_worker_started
    if not vt_worker_started:
        threading.Thread(target=vt_worker, daemon=True).start()
        vt_worker_started = True

def save_to_json(results, output_file):
    # Save results to a JSON file
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)

def print_summary_table(results):
    # Print a summary table of the results with full hash values
    headers = ["Hash", "MISP", "Hashlookup", "OTX", "Kaspersky", "VirusTotal"]
    table = []
    for hash_value, data in results.items():
        row = [
            hash_value,  # Display full hash value
            "Yes" if data.get('misp') else "No",
            "Yes" if data.get('hashlookup') else "No",
            "Yes" if data.get('otx') else "No",
            "Yes" if data.get('kaspersky') else "No",
            "Yes" if data.get('virustotal') else "No"
        ]
        table.append(row)
    print(tabulate(table, headers=headers, tablefmt="grid"))

def calculate_estimated_time(mode, hash_list, services_to_search=None):
    # Calculate estimated time for processing hashes based on mode and services
    N = len(hash_list)
    if mode == 'quick':
        # Sequential checks with rate limits for OTX and Kaspersky
        time_per_hash = 10  # OTX rate limit
        estimated_seconds = N * time_per_hash
    elif mode == 'extra':
        # Phase 1: MISP, Hashlookup, OTX
        # Phase 2: Kaspersky for unfound hashes
        # Phase 3: VirusTotal for unfound hashes
        time_phase1 = N * (3600 / 10000)  # OTX rate limit
        time_phase2 = N * 60  # Kaspersky rate limit (assuming all hashes checked)
        time_phase3 = N * (60 / 4)  # VirusTotal rate limit (assuming all hashes checked)
        estimated_seconds = time_phase1 + time_phase2 + time_phase3
    else:
        # Normal mode: linear based on selected services
        estimated_seconds = 0
        for service in services_to_search:
            if service == 'otx':
                estimated_seconds += N * (3600 / 10000)
            elif service == 'kaspersky':
                estimated_seconds += N * 60
            elif service == 'virustotal':
                estimated_seconds += N * (60 / 4)
            # MISP and Hashlookup are fast, so negligible
    return estimated_seconds

def format_time(seconds):
    # Format seconds into hours, minutes, and seconds
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    seconds = int(seconds % 60)
    return f"{hours} hours {minutes} minutes {seconds} seconds"

def process_hashes(hash_list, verbose=False, mode='normal', vt_confirm=False, use_tor=False):
    # Process a list of (hash_value, hash_type) tuples based on mode and service
    if mode == 'quick':
        # Quick mode: sequential check in cache, MISP, Hashlookup, OTX, Kaspersky
        found_counts = {'cache': 0, 'misp': 0, 'hashlookup': 0, 'otx': 0, 'kaspersky': 0}
        found_hashes = []
        for hash_value, hash_type in hash_list:
            cached_results = check_cache(hash_value, hash_type)
            found = False
            for service in ['misp', 'hashlookup', 'otx', 'kaspersky']:
                if service in cached_results and cached_results[service] is not None:
                    found_counts[service] += 1
                    found = True
                    found_hashes.append((hash_value, hash_type))
                    break
                elif service == 'misp':
                    result = search_misp(hash_value, hash_type, verbose)
                    if result is not None:
                        cached_results[service] = result
                        found_counts[service] += 1
                        found = True
                        found_hashes.append((hash_value, hash_type))
                        break
                elif service == 'hashlookup':
                    result = search_circl_hashlookup(hash_value, hash_type, verbose)
                    if result is not None:
                        cached_results[service] = result
                        found_counts[service] += 1
                        found = True
                        found_hashes.append((hash_value, hash_type))
                        break
                elif service == 'otx':
                    result = search_otx(hash_value, hash_type, verbose)
                    if result is not None:
                        cached_results[service] = result
                        found_counts[service] += 1
                        found = True
                        found_hashes.append((hash_value, hash_type))
                        break
                    time.sleep(10)  # Rate limit for OTX
                elif service == 'kaspersky':
                    result = search_kaspersky(hash_value, hash_type, verbose)
                    if result is not None:
                        cached_results[service] = result
                        found_counts[service] += 1
                        found = True
                        found_hashes.append((hash_value, hash_type))
                        break
            save_to_cache(hash_value, hash_type, cached_results)

        # Display statistics
        print(Fore.CYAN + "\n[+] Quick mode results:" + Fore.RESET)
        for service, count in found_counts.items():
            print(Fore.CYAN + f"[+] Found in {service}: {count}" + Fore.RESET)
        print(Fore.CYAN + f"[+] Not found: {len(hash_list) - len(found_hashes)}" + Fore.RESET)

        # Check found hashes in VirusTotal, using Tor if specified
        if found_hashes:
            if use_tor:
                start_tor()
                try:
                    if tor_controller:
                        for hash_value, hash_type in found_hashes:
                            cached_results = check_cache(hash_value, hash_type)
                            if 'virustotal' not in cached_results or cached_results['virustotal'] is None:
                                result = search_virustotal(hash_value, hash_type, verbose, use_tor=True)
                                cached_results['virustotal'] = result
                                save_to_cache(hash_value, hash_type, cached_results)
                    else:
                        print("[+] Tor not available, skipping VirusTotal check.")
                finally:
                    stop_tor()
            else:
                # Use normal VirusTotal worker without Tor
                start_vt_worker()
                for hash_value, hash_type in found_hashes:
                    vt_queue.put((hash_value, hash_type, verbose))
                vt_queue.join()

    elif mode == 'extra':
        # Extra mode: multi-phase with user prompts
        initial_services = ['misp', 'hashlookup', 'otx']
        for hash_value, hash_type in hash_list:
            cached_results = check_cache(hash_value, hash_type)
            for service in initial_services:
                if service not in cached_results or cached_results[service] is None:
                    if service == 'misp':
                        result = search_misp(hash_value, hash_type, verbose)
                        cached_results[service] = result
                    elif service == 'hashlookup':
                        result = search_circl_hashlookup(hash_value, hash_type, verbose)
                        cached_results[service] = result
                    elif service == 'otx':
                        start_otx_worker()
                        otx_queue.put((hash_value, hash_type, verbose))
            save_to_cache(hash_value, hash_type, cached_results)

        # Wait for OTX queue to finish
        otx_queue.join()

        # Identify hashes not found in phase 1
        unfound_phase1 = []
        for hash_value, hash_type in hash_list:
            cached_results = check_cache(hash_value, hash_type)
            if all(cached_results.get(service) is None for service in initial_services):
                unfound_phase1.append((hash_value, hash_type))

        total_hashes = len(hash_list)
        found_in_misp = sum(1 for (h, t) in hash_list if check_cache(h, t).get('misp') is not None)
        found_in_hashlookup = sum(1 for (h, t) in hash_list if check_cache(h, t).get('hashlookup') is not None)
        found_in_otx = sum(1 for (h, t) in hash_list if check_cache(h, t).get('otx') is not None)
        not_found_phase1 = len(unfound_phase1)

        print(Fore.CYAN + f"\n[+] Processed {total_hashes} hashes in phase 1:" + Fore.RESET)
        print(Fore.CYAN + f"[+] Found in MISP: {found_in_misp}" + Fore.RESET)
        print(Fore.CYAN + f"[+] Found in CIRCL Hashlookup: {found_in_hashlookup}" + Fore.RESET)
        print(Fore.CYAN + f"[+] Found in OTX: {found_in_otx}" + Fore.RESET)
        print(Fore.CYAN + f"[+] Not found in any service (phase 1): {not_found_phase1}" + Fore.RESET)

        if not_found_phase1:
            answer = input(f"[+] Do you want to check the {not_found_phase1} not found hashes in OpenTIP Kaspersky? (yes/no): ").strip().lower()
            if answer == 'yes':
                for hash_value, hash_type in unfound_phase1:
                    cached_results = check_cache(hash_value, hash_type)
                    if 'kaspersky' not in cached_results or cached_results['kaspersky'] is None:
                        result = search_kaspersky(hash_value, hash_type, verbose)
                        cached_results['kaspersky'] = result
                        save_to_cache(hash_value, hash_type, cached_results)

                # Identify hashes not found in Kaspersky
                unfound_phase2 = []
                for hash_value, hash_type in unfound_phase1:
                    cached_results = check_cache(hash_value, hash_type)
                    if cached_results.get('kaspersky') is None:
                        unfound_phase2.append((hash_value, hash_type))

                found_in_kaspersky = len(unfound_phase1) - len(unfound_phase2)
                print(Fore.CYAN + f"[+] Found in Kaspersky: {found_in_kaspersky}" + Fore.RESET)
                print(Fore.CYAN + f"[+] Not found in Kaspersky: {len(unfound_phase2)}" + Fore.RESET)

                if unfound_phase2:
                    answer = input(f"[+] Do you want to check the {len(unfound_phase2)} not found hashes in VirusTotal? (yes/no): ").strip().lower()
                    if answer == 'yes':
                        start_vt_worker()
                        for hash_value, hash_type in unfound_phase2:
                            vt_queue.put((hash_value, hash_type, verbose))
                        vt_queue.join()

        if vt_confirm:
            found_hashes = [h for h in hash_list if any(check_cache(h[0], h[1]).get(s) is not None for s in initial_services + ['kaspersky'])]
            if found_hashes:
                start_vt_worker()
                for hash_value, hash_type in found_hashes:
                    cached_results = check_cache(hash_value, hash_type)
                    if 'virustotal' not in cached_results or cached_results['virustotal'] is None:
                        vt_queue.put((hash_value, hash_type, verbose))
                vt_queue.join()

    else:
        # Normal mode: check in specified services
        services_to_search = [args.service] if args.service != 'all' else ['misp', 'hashlookup', 'otx', 'kaspersky', 'virustotal']
        for hash_value, hash_type in hash_list:
            cached_results = check_cache(hash_value, hash_type)
            for service in services_to_search:
                if service not in cached_results or cached_results[service] is None:
                    if service == 'misp':
                        result = search_misp(hash_value, hash_type, verbose)
                        cached_results[service] = result
                    elif service == 'hashlookup':
                        result = search_circl_hashlookup(hash_value, hash_type, verbose)
                        cached_results[service] = result
                    elif service == 'otx':
                        start_otx_worker()
                        otx_queue.put((hash_value, hash_type, verbose))
                    elif service == 'kaspersky':
                        result = search_kaspersky(hash_value, hash_type, verbose)
                        cached_results[service] = result
                    elif service == 'virustotal':
                        start_vt_worker()
                        vt_queue.put((hash_value, hash_type, verbose))
            save_to_cache(hash_value, hash_type, cached_results)

        if 'otx' in services_to_search:
            otx_queue.join()
        if 'virustotal' in services_to_search:
            vt_queue.join()

    results = {}
    for hash_value, hash_type in hash_list:
        results[hash_value] = check_cache(hash_value, hash_type)
    return results

def display_vt_results(hash_value, vt_results):
    # Display VirusTotal results in a dynamic table
    if not vt_results:
        print(Fore.RED + f"[+] No VirusTotal results found for hash {hash_value}" + Fore.RESET)
        return

    stats = vt_results.get('last_analysis_stats', {})
    tags = ', '.join(vt_results.get('tags', []))
    names = ', '.join(vt_results.get('names', []))

    table = [
        ["Hash", hash_value],
        ["Malicious", stats.get('malicious', 0)],
        ["Suspicious", stats.get('suspicious', 0)],
        ["Harmless", stats.get('harmless', 0)],
        ["Undetected", stats.get('undetected', 0)],
        ["Tags", tags],
        ["Names", names]
    ]

    print(Fore.CYAN + "\n[+] VirusTotal Results:" + Fore.RESET)
    print(tabulate(table, headers=["Field", "Value"], tablefmt="grid"))

if __name__ == "__main__":
    try:
        # Set up argument parser
        parser = argparse.ArgumentParser(description="Check hashes against various threat intelligence services.")
        parser.add_argument('-directory', help="Path to the directory containing files with hashes")
        parser.add_argument('-file_type', choices=['csv', 'txt'], help="Type of files to process (csv or txt)")
        parser.add_argument('-hash', help="A single hash to check directly")
        parser.add_argument('-output', default='results.json', help="Output JSON file (default: results.json)")
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
        parser.add_argument('-service', choices=['misp', 'hashlookup', 'otx', 'kaspersky', 'virustotal', 'all'],
                            default='all', help="Service to search the hash in (default: all)")
        parser.add_argument('--view', help="View full details of a specific hash from the cache")
        parser.add_argument('--vt_view', help="View only VirusTotal results of a specific hash from the cache")
        parser.add_argument('--vt_confirm', action='store_true', help="Check found hashes in VirusTotal")
        parser.add_argument('-q', '--quick', action='store_true', help="Quick mode: sequential check and VT confirmation")
        parser.add_argument('-e', '--extra', action='store_true', help="Extra mode: multi-phase with user prompts")
        parser.add_argument('-tor', action='store_true', help="Use Tor for VirusTotal requests in Quick mode (optional)")
        args = parser.parse_args()

        # Check for mutually exclusive modes
        if args.quick and args.extra:
            print(Fore.RED + "[+] Error: Cannot use -q and -e together" + Fore.RESET)
            exit(1)
        if args.view and args.vt_view:
            print(Fore.RED + "[+] Error: Cannot use --view and --vt_view together" + Fore.RESET)
            exit(1)

        # Initialize configuration
        config = initialize_config()
        MISP_URL = config['misp_url']
        MISP_KEY = config['misp_key']
        OTX_API_KEY = config['otx_key']
        VT_API_KEYS = config['vt_keys']
        KASPERSKY_API_KEY = config['kaspersky_key']
        CACHE_DB = config['cache_db']
        TOR_PATH = config.get('tor_path', '')

        # Handle view cache option
        if args.view:
            hash_value = args.view
            hash_type = detect_hash_type(hash_value)
            if hash_type in ['empty', 'invalid', 'unknown']:
                print(Fore.RED + f"[+] Invalid hash: {hash_value}" + Fore.RESET)
                exit(1)
            cached_result = check_cache(hash_value, hash_type)
            if cached_result:
                print(Fore.CYAN + "\n[+] Detailed results for hash:" + Fore.RESET, hash_value)
                print(json.dumps(cached_result, indent=4))
            else:
                print(Fore.RED + f"[+] Hash {hash_value} not found in cache." + Fore.RESET)
            exit(0)

        # Handle VirusTotal view cache option
        if args.vt_view:
            hash_value = args.vt_view
            hash_type = detect_hash_type(hash_value)
            if hash_type in ['empty', 'invalid', 'unknown']:
                print(Fore.RED + f"[+] Invalid hash: {hash_value}" + Fore.RESET)
                exit(1)
            cached_result = check_cache(hash_value, hash_type)
            if cached_result and 'virustotal' in cached_result and cached_result['virustotal']:
                display_vt_results(hash_value, cached_result['virustotal'])
            else:
                print(Fore.RED + f"[+] No VirusTotal results found for hash {hash_value} in cache." + Fore.RESET)
            exit(0)

        # Validate input options
        if args.hash and (args.directory or args.file_type):
            print(Fore.RED + "[+] Error: Cannot provide both -hash and -directory/-file_type" + Fore.RESET)
            exit(1)
        elif args.hash:
            hash_value = args.hash
            hash_type = detect_hash_type(hash_value)
            if hash_type in ['empty', 'invalid', 'unknown']:
                print(Fore.RED + f"[+] Invalid hash: {hash_value}" + Fore.RESET)
                exit(1)
            hash_list = [(hash_value, hash_type)]
        elif args.directory and args.file_type:
            hash_list = extract_hashes_from_directory(args.directory, args.file_type)
            if not hash_list:
                print(Fore.RED + "[+] No valid hashes found in the directory." + Fore.RESET)
                exit(0)
        else:
            print(Fore.RED + "[+] Error: Provide either -hash or both -directory and -file_type" + Fore.RESET)
            parser.print_help()
            exit(1)

        # Initialize MISP if needed
        if args.service in ['misp', 'all'] or args.quick or args.extra:
            misp = pymisp.PyMISP(MISP_URL, MISP_KEY, ssl=False)
        else:
            misp = None

        # Initialize SQLite cache database
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

        # Determine mode and VT confirmation
        if args.quick:
            mode = 'quick'
            vt_confirm = True
            use_tor = args.tor  # Use Tor only if -tor flag is provided in Quick mode
        elif args.extra:
            mode = 'extra'
            vt_confirm = args.vt_confirm
            use_tor = False  # Tor is not used in Extra mode
        else:
            mode = 'normal'
            vt_confirm = args.vt_confirm
            use_tor = False  # Tor is not used in Normal mode

        # Calculate and display estimated time
        if mode == 'normal':
            services_to_search = [args.service] if args.service != 'all' else ['misp', 'hashlookup', 'otx', 'kaspersky', 'virustotal']
            estimated_seconds = calculate_estimated_time(mode, hash_list, services_to_search)
        else:
            estimated_seconds = calculate_estimated_time(mode, hash_list)
        print(Fore.CYAN + f"[+] Estimated time to complete: {format_time(estimated_seconds)}" + Fore.RESET)

        # Process hashes
        print(Fore.CYAN + f"[+] Processing {len(hash_list)} hash(es) in {mode} mode..." + Fore.RESET)
        results = process_hashes(hash_list, args.verbose, mode=mode, vt_confirm=vt_confirm, use_tor=use_tor)
        save_to_json(results, args.output)
        print(Fore.GREEN + f"[+] Results saved to '{args.output}' and cached in '{CACHE_DB}'." + Fore.RESET)

        # Print summary
        print(Fore.CYAN + "\n[+] Summary of results:" + Fore.RESET)
        print_summary_table(results)
    except Exception as e:
        print(Fore.RED + f"[+] An error occurred: {e}" + Fore.RESET)