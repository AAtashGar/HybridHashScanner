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

# Disable insecure request warnings for HTTP requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for colored terminal output
init()

# Get terminal width for formatting logo and info box
terminal_width = shutil.get_terminal_size().columns

# Set a fixed width for the info box
box_width = 60

# Create a Figlet object with 'small' font for the logo
f = Figlet(font='small')

# Render the tool's logo
logo = f.renderText('HybridHashScanner')

# Print the logo in white
print(Fore.WHITE + logo + Fore.RESET)

# Define information lines to display after the logo
info_lines = [
    "Version: 1.0.0",
    "HybridHashScanner - Hash Analysis Tool",
    " MISP, VirusTotal, OTX, hashlookup, OpenTip",
    " A.AtashGar (atashgar7@gmail.com)",
    " Licensed under MIT License",
    "> https://github.com/AAtashGar/HybridHashScanner",
    "> https://www.linkedin.com/in/ali-atashgar/"
]

# Function to center text within a specified width
def center_text(text, width):
    return text.center(width)

# Print the top border of the info box
top_border = '┌' + '─' * (box_width) + '┐'
print(Fore.WHITE + top_border + Fore.RESET)

# Print each info line centered within the box
for line in info_lines:
    centered_line = center_text(line, box_width)
    print(Fore.WHITE + '│' + centered_line + '│' + Fore.RESET)

# Print the bottom border of the info box
bottom_border = '└' + '─' * (box_width) + '┘'
print(Fore.WHITE + bottom_border + Fore.RESET)

# Configuration file and cache database paths
CONFIG_FILE = 'config.json'
CACHE_DB = 'cache.db'

# Define queues for OTX and VirusTotal workers to handle concurrent requests
otx_queue = queue.Queue()
vt_queue = queue.Queue()

# Dictionary to store results with thread safety
results_dict = {}
results_lock = threading.Lock()

# Global flags to track worker thread status
otx_worker_started = False
vt_worker_started = False

# Global variables for managing Tor process
tor_controller = None
tor_process = None

def load_config():
    """Load configuration settings from config.json file."""
    if not os.path.exists(CONFIG_FILE):
        print(Fore.RED + f"[+] Configuration file '{CONFIG_FILE}' not found. Please create and configure it." + Fore.RESET)
        exit(1)
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def detect_hash_type(hash_str):
    """Detect the hash type (md5, sha1, sha256, sha512) based on length and content."""
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
    """Extract valid hashes from files in a directory based on file type (csv or txt)."""
    pattern = '*.csv' if file_type == 'csv' else '*.txt'
    files = glob.glob(os.path.join(directory, pattern))
    hashes = []
    for file in files:
        with open(file, 'r', encoding='utf-8-sig') as f:
            if file_type == 'csv':
                reader = csv.reader(f)
                next(reader, None)  # Skip header row
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
    """Check if a hash exists in the SQLite cache and return its results."""
    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT result FROM cache WHERE hash = ? AND hash_type = ?', (hash_value, hash_type))
    row = cursor.fetchone()
    conn.close()
    if row is not None:
        return json.loads(row[0])
    return {}

def save_to_cache(hash_value, hash_type, results):
    """Save or update results for a hash in the SQLite cache."""
    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO cache (hash, hash_type, result) VALUES (?, ?, ?)',
                   (hash_value, hash_type, json.dumps(results)))
    conn.commit()
    conn.close()

def search_misp(hash_value, hash_type, verbose=False):
    """Search for a hash in MISP and return attributes if found, else None."""
    if not MISP_URL or not MISP_KEY:
        print(Fore.YELLOW + "[+] MISP is not configured in config.json. Skipping MISP search." + Fore.RESET)
        return None
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
    """Search for a hash in CIRCL Hashlookup and return results if found, else None."""
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
    """Search for a hash in OTX and return results if found, else None."""
    if not OTX_API_KEY:
        print(Fore.YELLOW + "[+] OTX is not configured in config.json. Skipping OTX search." + Fore.RESET)
        return None
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
                    print(Fore.GREEN + f"[+] OTX search done for {hash_value}" + Fare.RESET)
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
    """Search for a hash in Kaspersky OpenTIP and return results if not clean, else None."""
    if not KASPERSKY_API_KEY:
        print(Fore.YELLOW + "[+] Kaspersky is not configured in config.json. Skipping Kaspersky search." + Fore.RESET)
        return None
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
    """Start a Tor instance for anonymous requests."""
    global tor_controller, tor_process
    if not TOR_PATH:
        print(Fore.YELLOW + "[+] Tor path is not configured in config.json. Skipping Tor usage." + Fore.RESET)
        return
    try:
        print(f"[+] Using Tor path: {TOR_PATH}")
        print("[+] Starting Tor...")
        tor_config = {'SocksPort': '9150', 'ControlPort': '9151'}
        tor_process = launch_tor_with_config(
            config=tor_config,
            tor_cmd=TOR_PATH,
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
    """Stop the running Tor instance."""
    global tor_controller, tor_process
    if tor_controller:
        tor_controller.close()
    if tor_process:
        tor_process.terminate()
        print("[+] Tor stopped.")

def search_virustotal(hash_value, hash_type, verbose=False, use_tor=False):
    """Search for a hash in VirusTotal with or without Tor, returning full response."""
    if not VT_API_KEYS:
        print(Fore.YELLOW + "[+] VirusTotal is not configured in config.json. Skipping VirusTotal search." + Fore.RESET)
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
            return response.json()
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
    """Worker thread for processing OTX requests with rate limiting."""
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
        time.sleep(3600 / 10000)  # Rate limit: 10,000 requests per hour

def vt_worker():
    """Worker thread for processing VirusTotal requests with rate limiting."""
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
        time.sleep(60 / 4)  # Rate limit: 4 requests per minute

def start_otx_worker():
    """Start the OTX worker thread if it hasn't been started yet."""
    global otx_worker_started
    if not otx_worker_started:
        threading.Thread(target=otx_worker, daemon=True).start()
        otx_worker_started = True

def start_vt_worker():
    """Start the VirusTotal worker thread if it hasn't治 hasn't been started yet."""
    global vt_worker_started
    if not vt_worker_started:
        threading.Thread(target=vt_worker, daemon=True).start()
        vt_worker_started = True

def get_summary_table(results):
    """Generate a summary table of results as a string."""
    headers = ["Hash", "MISP", "Hashlookup", "OTX", "Kaspersky", "VirusTotal"]
    table = []
    for hash_value, data in results.items():
        row = [
            hash_value,
            "Yes" if data.get('misp') else "No",
            "Yes" if data.get('hashlookup') else "No",
            "Yes" if data.get('otx') else "No",
            "Yes" if data.get('kaspersky') else "No",
            "Yes" if data.get('virustotal') else "No"
        ]
        table.append(row)
    return tabulate(table, headers=headers, tablefmt="grid")

def get_vt_results_table(hash_value, vt_results):
    """Generate VirusTotal results table for a hash as a string."""
    if not vt_results or 'data' not in vt_results:
        return f"[+] No VirusTotal results found for hash {hash_value}"
    attributes = vt_results.get('data', {}).get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    tags = ', '.join(attributes.get('tags', []))
    names = ', '.join(attributes.get('names', []))
    table = [
        ["Hash", hash_value],
        ["Malicious", stats.get('malicious', 0)],
        ["Suspicious", stats.get('suspicious', 0)],
        ["Harmless", stats.get('harmless', 0)],
        ["Undetected", stats.get('undetected', 0)],
        ["Tags", tags],
        ["Names", names]
    ]
    return tabulate(table, headers=["Field", "Value"], tablefmt="grid")

def calculate_estimated_time(mode, hash_list, services_to_search=None):
    """Calculate estimated time for processing hashes based on mode and services."""
    N = len(hash_list)
    if mode == 'quick':
        time_per_hash = 10  # seconds, based on OTX delay approximation
        estimated_seconds = N * time_per_hash
    elif mode == 'extra':
        # Assuming phases with different rate limits
        time_phase1 = N * (3600 / 10000)  # OTX rate limit: 10,000 per hour
        time_phase2 = N * 60  # Kaspersky rate limit: 1 per minute
        time_phase3 = N * (60 / 4)  # VirusTotal rate limit: 4 per minute
        estimated_seconds = time_phase1 + time_phase2 + time_phase3
    else:  # normal mode
        estimated_seconds = 0
        if services_to_search is None:
            services_to_search = ['misp', 'hashlookup', 'otx', 'kaspersky', 'virustotal']
        for service in services_to_search:
            if service == 'otx':
                estimated_seconds += N * (3600 / 10000)  # OTX rate limit
            elif service == 'kaspersky':
                estimated_seconds += N * 60  # Kaspersky rate limit
            elif service == 'virustotal':
                estimated_seconds += N * (60 / 4)  # VirusTotal rate limit
            # MISP and hashlookup assumed to have negligible time or parallel processing
    return estimated_seconds

def format_time(seconds):
    """Format seconds into a human-readable string (hours, minutes, seconds)."""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    seconds = int(seconds % 60)
    return f"{hours} hours {minutes} minutes {seconds} seconds"

def process_hashes(hash_list, verbose=False, mode='normal', use_tor=False):
    """Process a list of hashes based on the specified mode (normal, quick, extra)."""
    if mode == 'quick':
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
                    time.sleep(10)  # Respect OTX rate limit
                elif service == 'kaspersky':
                    result = search_kaspersky(hash_value, hash_type, verbose)
                    if result is not None:
                        cached_results[service] = result
                        found_counts[service] += 1
                        found = True
                        found_hashes.append((hash_value, hash_type))
                        break
            save_to_cache(hash_value, hash_type, cached_results)

        print(Fore.CYAN + "\n[+] Quick mode results:" + Fore.RESET)
        for service, count in found_counts.items():
            print(Fore.CYAN + f"[+] Found in {service}: {count}" + Fore.RESET)
        print(Fore.CYAN + f"[+] Not found: {len(hash_list) - len(found_hashes)}" + Fore.RESET)

        # Check found hashes in VirusTotal in quick mode
        if found_hashes and VT_API_KEYS:
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
                start_vt_worker()
                for hash_value, hash_type in found_hashes:
                    vt_queue.put((hash_value, hash_type, verbose))
                vt_queue.join()

    elif mode == 'extra':
        initial_services = ['misp', 'hashlookup', 'otx']
        for hash_value, hash_type in hash_list:
            cached_results = cached_results = check_cache(hash_value, hash_type)
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

        otx_queue.join()

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

        if not_found_phase1 and KASPERSKY_API_KEY:
            answer = input(f"[+] Do you want to check the {not_found_phase1} not found hashes in OpenTIP Kaspersky? (yes/no): ").strip().lower()
            if answer == 'yes':
                for hash_value, hash_type in unfound_phase1:
                    cached_results = check_cache(hash_value, hash_type)
                    if 'kaspersky' not in cached_results or cached_results['kaspersky'] is None:
                        result = search_kaspersky(hash_value, hash_type, verbose)
                        cached_results['kaspersky'] = result
                        save_to_cache(hash_value, hash_type, cached_results)

                unfound_phase2 = []
                for hash_value, hash_type in unfound_phase1:
                    cached_results = check_cache(hash_value, hash_type)
                    if cached_results.get('kaspersky') is None:
                        unfound_phase2.append((hash_value, hash_type))

                found_in_kaspersky = len(unfound_phase1) - len(unfound_phase2)
                print(Fore.CYAN + f"[+] Found in Kaspersky: {found_in_kaspersky}" + Fore.RESET)
                print(Fore.CYAN + f"[+] Not found in Kaspersky: {len(unfound_phase2)}" + Fore.RESET)

                if unfound_phase2 and VT_API_KEYS:
                    answer = input(f"[+] Do you want to check the {len(unfound_phase2)} not found hashes in VirusTotal? (yes/no): ").strip().lower()
                    if answer == 'yes':
                        start_vt_worker()
                        for hash_value, hash_type in unfound_phase2:
                            vt_queue.put((hash_value, hash_type, verbose))
                        vt_queue.join()

    else:  # Normal mode
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

    # Compile final results from cache
    results = {}
    for hash_value, hash_type in hash_list:
        results[hash_value] = check_cache(hash_value, hash_type)
    return results

if __name__ == "__main__":
    try:
        # Define command-line argument parser
        parser = argparse.ArgumentParser(description="Check hashes against various threat intelligence services.")
        parser.add_argument('-directory', help="Path to directory containing files with hashes")
        parser.add_argument('-file_type', choices=['csv', 'txt'], help="Type of files to process (csv or txt)")
        parser.add_argument('-hash', help="A single hash to check directly")
        parser.add_argument('-output', default='results.txt', help="Output text file for summary and VT results (default: results.txt)")
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
        parser.add_argument('-service', choices=['misp', 'hashlookup', 'otx', 'kaspersky', 'virustotal', 'all'],
                            default='all', help="Service to search the hash in (default: all)")
        parser.add_argument('--view', help="View full details of a specific hash from cache")
        parser.add_argument('--vt_view', help="View only VirusTotal results of a specific hash from cache")
        parser.add_argument('-q', '--quick', action='store_true', help="Quick mode: sequential check with VT confirmation")
        parser.add_argument('-e', '--extra', action='store_true', help="Extra mode: multi-phase with user prompts")
        parser.add_argument('-tor', action='store_true', help="Use Tor for VirusTotal requests in quick mode")
        args = parser.parse_args()

        # Validate mutually exclusive options
        if args.quick and args.extra:
            print(Fore.RED + "[+] Error: Cannot use -q and -e together" + Fore.RESET)
            exit(1)
        if args.view and args.vt_view:
            print(Fore.RED + "[+] Error: Cannot use --view and --vt_view together" + Fore.RESET)
            exit(1)

        # Load configuration from config.json
        config = load_config()
        MISP_URL = config.get('misp_url', '')
        MISP_KEY = config.get('misp_key', '')
        OTX_API_KEY = config.get('otx_key', '')
        VT_API_KEYS = config.get('vt_keys', [])
        KASPERSKY_API_KEY = config.get('kaspersky_key', '')
        CACHE_DB = config.get('cache_db', 'cache.db')
        TOR_PATH = config.get('tor_path', '')

        # Handle --view switch to display full cached results
        if args.view:
            hash_value = args.view
            hash_type = detect_hash_type(hash_value)
            if hash_type in ['empty', 'invalid', 'unknown']:
                print(Fore.RED + f"[+] Invalid hash: {hash_value}" + Fore.RESET)
                exit(1)
            cached_result = check_cache(hash_value, hash_type)
            if cached_result:
                print(Fore.CYAN + f"[+] Results for {hash_value}:" + Fore.RESET)
                for service, data in cached_result.items():
                    if data:
                        print(Fore.CYAN + f"[+] {service.capitalize()}:" + Fore.RESET)
                        print(json.dumps(data, indent=4))
            else:
                print(Fore.RED + f"[+] No cached results found for {hash_value}" + Fore.RESET)
            exit(0)

        # Handle --vt_view switch to display VirusTotal results from cache
        if args.vt_view:
            hash_value = args.vt_view
            hash_type = detect_hash_type(hash_value)
            if hash_type in ['empty', 'invalid', 'unknown']:
                print(Fore.RED + f"[+] Invalid hash: {hash_value}" + Fore.RESET)
                exit(1)
            cached_result = check_cache(hash_value, hash_type)
            if cached_result and 'virustotal' in cached_result and cached_result['virustotal']:
                vt_results = cached_result['virustotal']
                vt_table = get_vt_results_table(hash_value, vt_results)
                print(Fore.CYAN + "\n[+] VirusTotal Results:" + Fore.RESET)
                print(vt_table)
            else:
                print(Fore.RED + f"[+] No VirusTotal results found for hash {hash_value} in cache." + Fore.RESET)
            exit(0)

        # Validate input arguments
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

        # Initialize MISP if required by the selected mode or service
        if args.service in ['misp', 'all'] or args.quick or args.extra:
            if MISP_URL and MISP_KEY:
                misp = pymisp.PyMISP(MISP_URL, MISP_KEY, ssl=False)
            else:
                print(Fore.YELLOW + "[+] MISP is not configured in config.json. Skipping MISP-related operations." + Fore.RESET)
                misp = None
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

        # Determine processing mode based on arguments
        if args.quick:
            mode = 'quick'
            use_tor = args.tor
        elif args.extra:
            mode = 'extra'
            use_tor = False
        else:
            mode = 'normal'
            use_tor = False

        # Calculate and display estimated time before processing
        if mode == 'normal':
            services_to_search = [args.service] if args.service != 'all' else ['misp', 'hashlookup', 'otx', 'kaspersky', 'virustotal']
            estimated_seconds = calculate_estimated_time(mode, hash_list, services_to_search)
        else:
            estimated_seconds = calculate_estimated_time(mode, hash_list)
        print(Fore.CYAN + f"[+] Estimated time to complete: {format_time(estimated_seconds)}" + Fore.RESET)

        # Process hashes and get results
        print(Fore.CYAN + f"[+] Processing {len(hash_list)} hash(es) in {mode} mode..." + Fore.RESET)
        results = process_hashes(hash_list, args.verbose, mode=mode, use_tor=use_tor)

        # Generate summary table string
        summary_str = get_summary_table(results)

        # Write summary to output file
        with open(args.output, 'w') as f:
            f.write("[+] Summary of results:\n")
            f.write(summary_str + "\n")

        # If verbose is enabled, print summary to console
        if args.verbose:
            print(Fore.CYAN + "[+] Summary of results:" + Fore.RESET)
            print(summary_str)

        # In quick mode, handle VirusTotal results for found hashes
        if mode == 'quick':
            found_hashes = [h for h in hash_list if any(results[h[0]].get(s) for s in ['misp', 'hashlookup', 'otx', 'kaspersky'])]
            for hash_value, hash_type in found_hashes:
                vt_results = results[hash_value].get('virustotal')
                if vt_results:
                    vt_str = get_vt_results_table(hash_value, vt_results)
                    with open(args.output, 'a') as f:
                        f.write("\n[+] VirusTotal Results:\n")
                        f.write(vt_str + "\n")
                    if args.verbose:
                        print(Fore.CYAN + f"[+] VirusTotal Results for {hash_value}:" + Fore.RESET)
                        print(vt_str)
                else:
                    no_vt_str = f"[+] No VirusTotal results for {hash_value}"
                    with open(args.output, 'a') as f:
                        f.write(no_vt_str + "\n")
                    if args.verbose:
                        print(Fore.YELLOW + no_vt_str + Fore.RESET)

        # Print completion messages
        print(Fore.GREEN + f"[+] Summary and VirusTotal results saved to '{args.output}'." + Fore.RESET)
        print(Fore.GREEN + f"[+] Results cached in '{CACHE_DB}'." + Fore.RESET)
    except Exception as e:
        print(Fore.RED + f"[+] An error occurred: {e}" + Fore.RESET)