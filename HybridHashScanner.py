import pymisp
import sqlite3
import json
import os
import requests

# MISP settings (update these with your local MISP details)
MISP_URL = 'YOUR LOCAL MISP URL'  # Local MISP instance URL
MISP_KEY = 'YOUR LOCAL MISP API KEY'  # Replace with your MISP API key

# OTX API Key (replace with your OTX API key)
OTX_API_KEY = 'YOUR OTX API KEY'

# SQLite database path
CACHE_DB = 'cache.db'

# Connect to MISP
misp = pymisp.PyMISP(MISP_URL, MISP_KEY, ssl=False)

# Connect to SQLite and create cache table if it doesn't exist
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

def check_cache(hash_value, hash_type):
    """Check if the hash exists in the SQLite cache and return (found, result)."""
    cursor.execute('SELECT result FROM cache WHERE hash = ? AND hash_type = ?', (hash_value, hash_type))
    row = cursor.fetchone()
    if row is not None:
        return True, json.loads(row[0])
    else:
        return False, None

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
        else:
            return None
    except Exception as e:
        print(f"Error searching CIRCL Hashlookup for {hash_value}: {e}")
        return None

def search_otx(hash_value, hash_type):
    """Search for the hash in OTX. Return result if found, else None."""
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}"
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data.get('pulse_info', {}).get('count', 0) > 0:
                return data
            else:
                return None
        else:
            return None
    except Exception as e:
        print(f"Error searching OTX for {hash_value}: {e}")
        return None

def save_to_cache(hash_value, hash_type, result):
    """Save the result to the SQLite cache."""
    cursor.execute('INSERT OR REPLACE INTO cache (hash, hash_type, result) VALUES (?, ?, ?)',
                   (hash_value, hash_type, json.dumps(result)))
    conn.commit()

def save_to_json(results, filename='results.json'):
    """Save results to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)

def process_hashes(hashes, hash_type='md5'):
    """Process a list of hashes, checking cache first, then MISP, then CIRCL Hashlookup, then OTX."""
    results = {}
    for hash_value in hashes:
        hash_value = hash_value.strip()
        if not hash_value:
            continue
        
        # Check cache first
        in_cache, cached_result = check_cache(hash_value, hash_type)
        if in_cache:
            results[hash_value] = cached_result
            print(f"Found {hash_value} in cache: {cached_result}")
            continue
        
        # Search in MISP if not in cache
        print(f"Searching {hash_value} in MISP...")
        misp_result = search_misp(hash_value, hash_type)
        if misp_result is not None:
            results[hash_value] = misp_result
            save_to_cache(hash_value, hash_type, misp_result)
            continue
        
        # Search in CIRCL Hashlookup if not in MISP
        print(f"Searching {hash_value} in CIRCL Hashlookup...")
        circl_result = search_circl_hashlookup(hash_value, hash_type)
        if circl_result is not None:
            results[hash_value] = circl_result
            save_to_cache(hash_value, hash_type, circl_result)
            continue
        
        # Search in OTX if not in CIRCL Hashlookup
        print(f"Searching {hash_value} in OTX...")
        otx_result = search_otx(hash_value, hash_type)
        results[hash_value] = otx_result
        save_to_cache(hash_value, hash_type, otx_result)
    
    # Save all results to JSON
    save_to_json(results)
    return results

def get_user_input():
    """Get hashes and optional hash type from the user."""
    print("Enter hashes (comma-separated or a file path containing one hash per line):")
    hashes_input = input().strip()
    
    if os.path.isfile(hashes_input):
        with open(hashes_input, 'r') as f:
            hashes = [line.strip() for line in f.readlines()]
    else:
        hashes = [h.strip() for h in hashes_input.split(',')]
    
    hash_type = input("Enter hash type (e.g., md5, sha1, sha256) [optional, default is md5]: ").strip() or 'md5'
    return hashes, hash_type

# Main execution
if __name__ == "__main__":
    try:
        hashes, hash_type = get_user_input()
        print(f"Processing {len(hashes)} hashes with type {hash_type}...")
        results = process_hashes(hashes, hash_type)
        print("Results saved to 'results.json' and cached in 'cache.db'.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()  # Close the database connection