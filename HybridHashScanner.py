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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

# Get terminal width
terminal_width = shutil.get_terminal_size().columns

# Set box width to a fixed value of 60 characters
box_width = 60

# Create Figlet object with 'small' font to prevent line breaks
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

# Create the top border
top_border = '┌' + '─' * (box_width) + '┐'
print(Fore.WHITE + top_border + Fore.RESET)

# Print each info line centered within the box
for line in info_lines:
    centered_line = center_text(line, box_width)
    print(Fore.WHITE + '│' + centered_line + '│' + Fore.RESET)

# Create the bottom border
bottom_border = '└' + '─' * (box_width) + '┘'
print(Fore.WHITE + bottom_border + Fore.RESET)

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
        print(Fore.BLUE + f"[+] Searching in MISP for {hash_value}..." + Fore.RESET)
        search_result = misp.search(controller='attributes', value=hash_value, type_attribute=hash_type)
        if search_result and 'Attribute' in search_result:
            attributes = search_result['Attribute']
            print(Fore.GREEN + f"[+] MISP search done for {hash_value}" + Fore.RESET)
            return attributes if attributes else None
        print(Fore.GREEN + f"[+] MISP search done for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        print(Fore.RED + f"[+] Error searching MISP for {hash_value}: {e}" + Fore.RESET)
        return None

def search_circl_hashlookup(hash_value, hash_type):
    """Search for the hash in CIRCL Hashlookup. Return result if found, else None."""
    if hash_type not in ['md5', 'sha1', 'sha256']:
        return None
    url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_value}"
    try:
        print(Fore.BLUE + f"[+] Searching in CIRCL Hashlookup for {hash_value}..." + Fore.RESET)
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] CIRCL Hashlookup search done for {hash_value}" + Fore.RESET)
            return response.json()
        elif response.status_code == 404:
            print(Fore.GREEN + f"[+] CIRCL Hashlookup search done for {hash_value}" + Fore.RESET)
            return None
        else:
            print(Fore.RED + f"[+] Error querying CIRCL Hashlookup for {hash_value}: {response.status_code}" + Fore.RESET)
            return None
    except requests.exceptions.Timeout:
        print(Fore.RED + f"[+] Timeout searching CIRCL Hashlookup for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        print(Fore.RED + f"[+] Error querying CIRCL Hashlookup for {hash_value}: {e}" + Fore.RESET)
        return None

def search_otx(hash_value, hash_type):
    """Search for the hash in OTX. Return result if found, else None."""
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        print(Fore.BLUE + f"[+] Searching in OTX for {hash_value}..." + Fore.RESET)
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('pulse_info', {}).get('count', 0) > 0:
                print(Fore.GREEN + f"[+] OTX search done for {hash_value}" + Fore.RESET)
                return data
            print(Fore.GREEN + f"[+] OTX search done for {hash_value}" + Fore.RESET)
            return None
        print(Fore.GREEN + f"[+] OTX search done for {hash_value}" + Fore.RESET)
        return None
    except requests.exceptions.Timeout:
        print(Fore.RED + f"[+] Timeout searching OTX for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        print(Fore.RED + f"[+] Error searching OTX for {hash_value}: {e}" + Fore.RESET)
        return None

def search_kaspersky(hash_value, hash_type):
    """Search for the hash in Kaspersky Threat Intelligence Portal. Return result if not Clean, else None."""
    url = f"https://opentip.kaspersky.com/api/v1/search/hash?request={hash_value}"
    headers = {"x-api-key": KASPERSKY_API_KEY}
    try:
        print(Fore.BLUE + f"[+] Searching in Kaspersky for {hash_value}..." + Fore.RESET)
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            file_status = result.get('FileGeneralInfo', {}).get('FileStatus')
            if file_status and file_status != 'Clean':
                print(Fore.GREEN + f"[+] Kaspersky search done for {hash_value}" + Fore.RESET)
                return result
            print(Fore.GREEN + f"[+] Kaspersky search done for {hash_value}" + Fore.RESET)
            return None
        print(Fore.GREEN + f"[+] Kaspersky search done for {hash_value}" + Fore.RESET)
        return None
    except requests.exceptions.Timeout:
        print(Fore.RED + f"[+] Timeout searching Kaspersky for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        print(Fore.RED + f"[+] Error searching Kaspersky for {hash_value}: {e}" + Fore.RESET)
        return None

def search_virustotal(hash_value, hash_type):
    """Search for the hash in VirusTotal. Return result if found, else None."""
    if not VT_API_KEYS:
        print(Fore.RED + "[+] No VirusTotal API keys provided." + Fore.RESET)
        return None
    vt_api_key = random.choice(VT_API_KEYS)
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": vt_api_key}
    try:
        print(Fore.BLUE + f"[+] Searching in VirusTotal for {hash_value}..." + Fore.RESET)
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] VirusTotal search done for {hash_value}" + Fore.RESET)
            return response.json()
        print(Fore.GREEN + f"[+] VirusTotal search done for {hash_value}" + Fore.RESET)
        return None
    except requests.exceptions.Timeout:
        print(Fore.RED + f"[+] Timeout searching VirusTotal for {hash_value}" + Fore.RESET)
        return None
    except Exception as e:
        print(Fore.RED + f"[+] Error searching VirusTotal for {hash_value}: {e}" + Fore.RESET)
        return None

def otx_worker():
    """Worker thread for processing OTX requests with rate limiting."""
    print(Fore.YELLOW + "[+] OTX worker started!" + Fore.RESET)
    while True:
        try:
            hash_value, hash_type = otx_queue.get()
            print(Fore.YELLOW + f"[+] OTX worker processing {hash_value}" + Fore.RESET)
            cached_results = check_cache(hash_value, hash_type)
            if 'otx' not in cached_results or cached_results['otx'] is None:
                result = search_otx(hash_value, hash_type)
                cached_results['otx'] = result
                save_to_cache(hash_value, hash_type, cached_results)
                print(Fore.GREEN + f"[+] OTX result saved for {hash_value}" + Fore.RESET)
            otx_queue.task_done()
            time.sleep(3600 / 10000)
        except Exception as e:
            print(Fore.RED + f"[+] Error in OTX worker for {hash_value}: {e}" + Fore.RESET)
            otx_queue.task_done()

def kaspersky_worker():
    """Worker thread for processing Kaspersky requests with rate limiting."""
    print(Fore.YELLOW + "[+] Kaspersky worker started!" + Fore.RESET)
    while True:
        try:
            hash_value, hash_type = kaspersky_queue.get()
            print(Fore.YELLOW + f"[+] Kaspersky worker processing {hash_value}" + Fore.RESET)
            cached_results = check_cache(hash_value, hash_type)
            if 'kaspersky' not in cached_results or cached_results['kaspersky'] is None:
                result = search_kaspersky(hash_value, hash_type)
                cached_results['kaspersky'] = result
                save_to_cache(hash_value, hash_type, cached_results)
                print(Fore.GREEN + f"[+] Kaspersky result saved for {hash_value}" + Fore.RESET)
            kaspersky_queue.task_done()
            time.sleep(60 / 1)
        except Exception as e:
            print(Fore.RED + f"[+] Error in Kaspersky worker for {hash_value}: {e}" + Fore.RESET)
            kaspersky_queue.task_done()

def vt_worker():
    """Worker thread for processing VirusTotal requests with rate limiting."""
    print(Fore.YELLOW + "[+] VirusTotal worker started!" + Fore.RESET)
    while True:
        try:
            hash_value, hash_type = vt_queue.get()
            print(Fore.YELLOW + f"[+] VT worker processing {hash_value}" + Fore.RESET)
            cached_results = check_cache(hash_value, hash_type)
            if 'virustotal' not in cached_results or cached_results['virustotal'] is None:
                result = search_virustotal(hash_value, hash_type)
                cached_results['virustotal'] = result
                save_to_cache(hash_value, hash_type, cached_results)
                print(Fore.GREEN + f"[+] VT result saved for {hash_value}" + Fore.RESET)
            vt_queue.task_done()
            time.sleep(60 / 4)
        except Exception as e:
            print(Fore.RED + f"[+] Error in VT worker for {hash_value}: {e}" + Fore.RESET)
            vt_queue.task_done()

def process_hashes(hash_list, verbose=False, multi_phase=False):
    """Process a list of (hash_value, hash_type) tuples based on selected service."""
    if multi_phase:
        # Phase 1: Check in MISP, Hashlookup, OTX
        initial_services = ['misp', 'hashlookup', 'otx']
        for hash_value, hash_type in hash_list:
            hash_value = hash_value.strip()
            if not hash_value:
                continue
            if verbose:
                print(Fore.CYAN + f"[+] Processing {hash_value} ({hash_type}) in phase 1" + Fore.RESET)
            cached_results = check_cache(hash_value, hash_type)
            for service in initial_services:
                if service not in cached_results or cached_results[service] is None:
                    if service == 'misp':
                        if verbose:
                            print(Fore.BLUE + "[+] Searching in MISP..." + Fore.RESET)
                        result = search_misp(hash_value, hash_type)
                        cached_results[service] = result
                    elif service == 'hashlookup':
                        if verbose:
                            print(Fore.BLUE + "[+] Searching in CIRCL Hashlookup..." + Fore.RESET)
                        result = search_circl_hashlookup(hash_value, hash_type)
                        cached_results[service] = result
                    elif service == 'otx':
                        otx_queue.put((hash_value, hash_type))
                        print(Fore.YELLOW + f"[+] Added {hash_value} to OTX queue" + Fore.RESET)
            save_to_cache(hash_value, hash_type, cached_results)

        # Wait for OTX queue to finish
        print(Fore.YELLOW + f"[+] OTX queue size before join: {otx_queue.qsize()}" + Fore.RESET)
        print(Fore.YELLOW + "[+] Waiting for OTX queue to finish..." + Fore.RESET)
        otx_queue.join()
        print(Fore.GREEN + "[+] OTX queue finished!" + Fore.RESET)
        print(Fore.YELLOW + f"[+] OTX queue size after join: {otx_queue.qsize()}" + Fore.RESET)

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
            # Calculate estimated time for Kaspersky
            N_kaspersky = len(unfound_phase1)
            estimated_seconds_kaspersky = N_kaspersky * 60  # 1 request per minute
            if estimated_seconds_kaspersky < 60:
                estimated_time_str = f"{estimated_seconds_kaspersky} seconds"
            elif estimated_seconds_kaspersky < 3600:
                minutes = estimated_seconds_kaspersky // 60
                seconds = estimated_seconds_kaspersky % 60
                estimated_time_str = f"{minutes} minutes {seconds} seconds"
            else:
                hours = estimated_seconds_kaspersky // 3600
                minutes = (estimated_seconds_kaspersky % 3600) // 60
                estimated_time_str = f"{hours} hours {minutes} minutes"
            answer = input(f"[+] Do you want to check the {not_found_phase1} not found hashes in OpenTIP Kaspersky? (yes/no): ").strip().lower()
            if answer == 'yes':
                print(Fore.CYAN + f"[+] Estimated time for Kaspersky search: {estimated_time_str}" + Fore.RESET)
                for hash_value, hash_type in unfound_phase1:
                    kaspersky_queue.put((hash_value, hash_type))
                print(Fore.YELLOW + f"[+] Kaspersky queue size before join: {kaspersky_queue.qsize()}" + Fore.RESET)
                print(Fore.YELLOW + "[+] Waiting for Kaspersky queue to finish..." + Fore.RESET)
                kaspersky_queue.join()
                print(Fore.GREEN + "[+] Kaspersky queue finished!" + Fore.RESET)
                print(Fore.YELLOW + f"[+] Kaspersky queue size after join: {kaspersky_queue.qsize()}" + Fore.RESET)

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
                    # Calculate estimated time for VirusTotal
                    N_vt = len(unfound_phase2)
                    estimated_seconds_vt = N_vt * 15  # 4 requests per minute
                    if estimated_seconds_vt < 60:
                        estimated_time_str = f"{estimated_seconds_vt:.1f} seconds"
                    elif estimated_seconds_vt < 3600:
                        minutes = estimated_seconds_vt // 60
                        seconds = estimated_seconds_vt % 60
                        estimated_time_str = f"{minutes} minutes {seconds:.1f} seconds"
                    else:
                        hours = estimated_seconds_vt // 3600
                        minutes = (estimated_seconds_vt % 3600) // 60
                        estimated_time_str = f"{hours} hours {minutes} minutes"
                    answer = input(f"[+] Do you want to check the {len(unfound_phase2)} not found hashes in VirusTotal? (yes/no): ").strip().lower()
                    if answer == 'yes':
                        print(Fore.CYAN + f"[+] Estimated time for VirusTotal search: {estimated_time_str}" + Fore.RESET)
                        for hash_value, hash_type in unfound_phase2:
                            vt_queue.put((hash_value, hash_type))
                        print(Fore.YELLOW + f"[+] VT queue size before join: {vt_queue.qsize()}" + Fore.RESET)
                        print(Fore.YELLOW + "[+] Waiting for VT queue to finish..." + Fore.RESET)
                        vt_queue.join()
                        print(Fore.GREEN + "[+] VT queue finished!" + Fore.RESET)
                        print(Fore.YELLOW + f"[+] VT queue size after join: {vt_queue.qsize()}" + Fore.RESET)

    else:
        # Current logic for when multi_phase=False
        services_to_search = [args.service] if args.service != 'all' else ['misp', 'hashlookup', 'otx', 'kaspersky', 'virustotal']
        for hash_value, hash_type in hash_list:
            hash_value = hash_value.strip()
            if not hash_value:
                continue
            if verbose:
                print(Fore.CYAN + f"[+] Processing {hash_value} ({hash_type})" + Fore.RESET)
            cached_results = check_cache(hash_value, hash_type)
            for service in services_to_search:
                if service not in cached_results or cached_results[service] is None:
                    if service == 'misp':
                        if verbose:
                            print(Fore.BLUE + "[+] Searching in MISP..." + Fore.RESET)
                        result = search_misp(hash_value, hash_type)
                        cached_results[service] = result
                    elif service == 'hashlookup':
                        if verbose:
                            print(Fore.BLUE + "[+] Searching in CIRCL Hashlookup..." + Fore.RESET)
                        result = search_circl_hashlookup(hash_value, hash_type)
                        cached_results[service] = result
                    elif service == 'otx':
                        otx_queue.put((hash_value, hash_type))
                        print(Fore.YELLOW + f"[+] Added {hash_value} to OTX queue" + Fore.RESET)
                    elif service == 'kaspersky':
                        kaspersky_queue.put((hash_value, hash_type))
                        print(Fore.YELLOW + f"[+] Added {hash_value} to Kaspersky queue" + Fore.RESET)
                    elif service == 'virustotal':
                        vt_queue.put((hash_value, hash_type))
                        print(Fore.YELLOW + f"[+] Added {hash_value} to VT queue" + Fore.RESET)
            save_to_cache(hash_value, hash_type, cached_results)

        if 'otx' in services_to_search:
            print(Fore.YELLOW + f"[+] OTX queue size before join: {otx_queue.qsize()}" + Fore.RESET)
            print(Fore.YELLOW + "[+] Waiting for OTX queue to finish..." + Fore.RESET)
            otx_queue.join()
            print(Fore.GREEN + "[+] OTX queue finished!" + Fore.RESET)
            print(Fore.YELLOW + f"[+] OTX queue size after join: {otx_queue.qsize()}" + Fore.RESET)
        if 'kaspersky' in services_to_search:
            print(Fore.YELLOW + f"[+] Kaspersky queue size before join: {kaspersky_queue.qsize()}" + Fore.RESET)
            print(Fore.YELLOW + "[+] Waiting for Kaspersky queue to finish..." + Fore.RESET)
            kaspersky_queue.join()
            print(Fore.GREEN + "[+] Kaspersky queue finished!" + Fore.RESET)
            print(Fore.YELLOW + f"[+] Kaspersky queue size after join: {kaspersky_queue.qsize()}" + Fore.RESET)
        if 'virustotal' in services_to_search:
            print(Fore.YELLOW + f"[+] VT queue size before join: {vt_queue.qsize()}" + Fore.RESET)
            print(Fore.YELLOW + "[+] Waiting for VT queue to finish..." + Fore.RESET)
            vt_queue.join()
            print(Fore.GREEN + "[+] VT queue finished!" + Fore.RESET)
            print(Fore.YELLOW + f"[+] VT queue size after join: {vt_queue.qsize()}" + Fore.RESET)

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
                print(Fore.RED + f"[+] Invalid hash: {hash_value}" + Fore.RESET)
                exit(1)
            cached_result = check_cache(hash_value, hash_type)
            if cached_result:
                print(Fore.CYAN + "\n[+] Detailed results for hash:" + Fore.RESET, hash_value)
                print(json.dumps(cached_result, indent=4))
            else:
                print(Fore.RED + f"[+] Hash {hash_value} not found in cache." + Fore.RESET)
            exit(0)

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
                print(Fore.CYAN + f"[+] Estimated completion time: {estimated_seconds} seconds" + Fore.RESET)
            elif estimated_seconds < 3600:
                minutes = estimated_seconds // 60
                seconds = estimated_seconds % 60
                print(Fore.CYAN + f"[+] Estimated completion time: {minutes} minutes {seconds} seconds" + Fore.RESET)
            else:
                hours = estimated_seconds // 3600
                minutes = (estimated_seconds % 3600) // 60
                print(Fore.CYAN + f"[+] Estimated completion time: {hours} hours {minutes} minutes" + Fore.RESET)

        print(Fore.CYAN + f"[+] Processing {len(hash_list)} hash(es)..." + Fore.RESET)
        multi_phase = args.directory and args.file_type and args.service == 'all'
        results = process_hashes(hash_list, args.verbose, multi_phase=multi_phase)
        save_to_json(results, args.output)
        print(Fore.GREEN + f"[+] Results saved to '{args.output}' and cached in '{CACHE_DB}'." + Fore.RESET)

        print(Fore.CYAN + "\n[+] Summary of results:" + Fore.RESET)
        print_summary_table(results)
    except Exception as e:
        print(Fore.RED + f"[+] An error occurred: {e}" + Fore.RESET)