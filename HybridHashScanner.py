import pymisp
import sqlite3
import json
import os

# MISP settings (update these with your local MISP details)
MISP_URL = 'https://192.168.85.128/'  # Local MISP instance URL
MISP_KEY = 'az4QuQZ73pdy8naWjQE5YrrsbVTnExt2xHhjO1Nz'  # Replace with your MISP API key

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
    """Check if the hash exists in the SQLite cache."""
    cursor.execute('SELECT result FROM cache WHERE hash = ? AND hash_type = ?', (hash_value, hash_type))
    result = cursor.fetchone()
    return json.loads(result[0]) if result else None

def search_misp(hash_value, hash_type):
    """Search for the hash in MISP."""
    try:
        search_result = misp.search(controller='attributes', value=hash_value, type_attribute=hash_type)
        return search_result['Attribute'] if search_result and 'Attribute' in search_result else None
    except Exception as e:
        print(f"Error searching MISP for {hash_value}: {e}")
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
    """Process a list of hashes, checking cache first, then MISP."""
    results = {}
    for hash_value in hashes:
        hash_value = hash_value.strip()
        if not hash_value:
            continue
        
        # Check cache first
        cached_result = check_cache(hash_value, hash_type)
        if cached_result is not None:
            results[hash_value] = cached_result
            print(f"Found {hash_value} in cache")
            continue
        
        # Search in MISP if not in cache
        print(f"Searching {hash_value} in MISP...")
        misp_result = search_misp(hash_value, hash_type)
        results[hash_value] = misp_result
        
        # Save to cache
        save_to_cache(hash_value, hash_type, misp_result)
    
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