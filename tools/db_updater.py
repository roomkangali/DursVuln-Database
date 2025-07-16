"""
db_updater.py

Author: Kang Ali
Version: 0.1.0

This script is responsible for fetching Common Vulnerabilities and Exposures (CVE)
data from the NVD (National Vulnerability Database) API and updating the individual,
category-based JSON files in the `cves/` directory.

Key Features:
- Reads product configurations from `config/product.json` as the single source of truth.
- For each product, it fetches relevant CVEs from the NVD API.
- Determines the correct destination file for the CVEs using a priority system:
  1. An explicit `target_file` path in the product's configuration.
  2. A file named after the product's `standard_name` (e.g., mysql.json).
  3. A fallback file, `misc/others.json`, if no specific file is found.
- Enriches CVE data with Nmap script info from `config/script_mapping.json`.
- Ensures no duplicate CVEs are added to any single file.
"""

import requests
import json
import os
import re
import sys

# Define base directories for script, project root, and database.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
# The DATABASE_DIR now points to the new Repo-Database structure
DATABASE_DIR = PROJECT_ROOT

def fetch_cves_for_product(search_term: str, api_key: str = None) -> list:
    """
    Fetches CVE data from the NVD API based on a search term.
    The search can be performed using a CPE string or a keyword.

    @param search_term (str): The CPE string (e.g., "cpe:2.3:a:apache:http_server")
                              or keyword (e.g., "Exim") to search for.
    @param api_key (str, optional): Your NVD API key for authenticated requests.
                                     Defaults to None.
    @return list: A list of vulnerability dictionaries from the NVD API response.
                  Returns an empty list if an error occurs or no vulnerabilities are found.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {'apiKey': api_key} if api_key else {}
    params = {'resultsPerPage': 2000}
    if search_term.startswith("cpe:2.3"):
        print(f"INFO: Fetching data using CPE: {search_term}...")
        params['virtualMatchString'] = search_term
    else:
        print(f"INFO: Fetching data using Keyword: {search_term}...")
        params['keywordSearch'] = search_term
        params['keywordExactMatch'] = ""
    try:
        response = requests.get(base_url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        total_results = data.get('totalResults', 0)
        print(f"INFO: Found {total_results} vulnerabilities.")
        return data.get('vulnerabilities', [])
    except requests.exceptions.HTTPError as e:
        print(f"ERROR: HTTP Error for {search_term}: {e.response.status_code} {e.response.reason}")
    except requests.exceptions.ConnectionError as e:
        print(f"ERROR: Connection Error for {search_term}: Could not connect to NVD API.")
    except requests.exceptions.Timeout as e:
        print(f"ERROR: Timeout Error for {search_term}: The request to NVD API timed out.")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: An unexpected request error occurred for {search_term}: {e}")
    return []

def clean_string(text: str) -> str:
    """
    Cleans a given string by removing control characters and normalizing
    curly quotes to straight quotes.

    @param text (str): The input string to clean.
    @return str: The cleaned string. Returns the original input if it's not a string.
    """
    if not isinstance(text, str): return text
    text = re.sub(r'[\x00-\x1f]', '', text)
    text = text.replace('\u201c', '"').replace('\u201d', '"')
    text = text.replace('\u2018', "'").replace('\u2019', "'")
    return text

def transform_api_cve_to_custom_format(api_cve_item: dict, product_name: str) -> dict:
    """
    @param api_cve_item (dict): A single CVE entry dictionary from the NVD API.
    @param product_name (str): The name of the product associated with this CVE.
    @return dict: A dictionary representing the CVE in the custom format.
    """
    cve = api_cve_item.get('cve', {}); cve_id = cve.get('id')
    description = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), None)
    references = [ref.get('url') for ref in cve.get('references', [])][:3]
    severity = "UNKNOWN"; metrics = cve.get('metrics', {})
    if 'cvssMetricV31' in metrics: severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', severity)
    elif 'cvssMetricV30' in metrics: severity = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity', severity)
    elif 'cvssMetricV2' in metrics: severity = metrics['cvssMetricV2'][0].get('severity', severity)
    version_match = "*"
    return {"id": clean_string(cve_id or "N/A"), "product": clean_string(product_name or "Unknown Product"), "version_match": version_match, "summary": clean_string(description or "No summary available."), "details": clean_string(description or "No details available."), "references": [clean_string(ref) for ref in (references or [])], "severity": clean_string((severity or "UNKNOWN").upper())}

def transform_and_enrich_cve(api_cve_item: dict, product_name: str, script_map: dict) -> dict:
    """
    @param api_cve_item (dict): A single CVE entry dictionary from the NVD API.
    @param product_name (str): The name of the product associated with this CVE.
    @param script_map (dict): A dictionary mapping CVE IDs to Nmap script names.
    @return dict: A dictionary representing the CVE in the custom, enriched format.
    """
    cve = api_cve_item.get('cve', {}); cve_id = cve.get('id')
    description = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), "No summary available.")
    references = [ref.get('url') for ref in cve.get('references', [])][:3]
    severity = "UNKNOWN"; metrics = cve.get('metrics', {})
    if 'cvssMetricV31' in metrics: severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', severity)
    elif 'cvssMetricV30' in metrics: severity = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity', severity)
    elif 'cvssMetricV2' in metrics: severity = metrics['cvssMetricV2'][0].get('severity', severity)
    
    match_type = "product_only"; confidence = "low"; version_match = None; required_script = None
    
    if cve_id in script_map:
        match_type = "active_check"; confidence = "high"; required_script = script_map[cve_id]
    else:
        # Group version conditions by their major version number
        version_groups = {}
        found_versions = []
        for config in cve.get('configurations', []):
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable'):
                        conditions = []
                        start_inc = cpe_match.get('versionStartIncluding')
                        end_exc = cpe_match.get('versionEndExcluding')
                        start_exc = cpe_match.get('versionStartExcluding')
                        end_inc = cpe_match.get('versionEndIncluding')
                        
                        if start_inc: conditions.append(f">={start_inc}")
                        if end_exc: conditions.append(f"<{end_exc}")
                        if start_exc: conditions.append(f">{start_exc}")
                        if end_inc: conditions.append(f"<={end_inc}")
                        
                        if conditions:
                            # Determine the major version key for grouping
                            version_str = start_inc or start_exc or end_inc or end_exc or ""
                            major_version = version_str.split('.')[0]
                            
                            if major_version not in version_groups:
                                version_groups[major_version] = []
                            version_groups[major_version].extend(conditions)

        if version_groups:
            match_type = "version_range"; confidence = "high"
            # Convert the grouped dictionary to a list of lists
            final_groups = [list(set(v)) for v in version_groups.values()]
            version_match = final_groups[0] if len(final_groups) == 1 else final_groups

    custom_cve = {"id": clean_string(cve_id), "product": clean_string(product_name), "summary": clean_string(description), "details": clean_string(description), "references": [clean_string(ref) for ref in references], "severity": clean_string(severity.upper()), "match_type": match_type, "confidence": confidence}
    if version_match: custom_cve["version_match"] = version_match
    if required_script: custom_cve["required_script"] = required_script
    return custom_cve

def update_individual_product_file(product_config: dict, script_map: dict, api_key: str = None):
    """
    Finds the correct product-specific JSON file based on standard_name.
    If not found, falls back to 'misc/others.json'.
    Updates the file with new CVEs from NVD.
    """
    product_name = product_config.get("standard_name")
    search_term = product_config.get("search_term")

    print(f"\n{'='*20}\nProcessing product: {product_name}\n{'='*20}")
    
    product_file_path = None
    cves_dir = os.path.join(DATABASE_DIR, 'cves')

    # Search for a matching {standard_name}.json file
    for root, _, files in os.walk(cves_dir):
        for file in files:
            if file == f"{product_name}.json":
                product_file_path = os.path.join(root, file)
                break
        if product_file_path:
            break

    # Fallback to misc/others.json if no specific file was found
    if not product_file_path:
        print(f"INFO: No specific file for '{product_name}'. Falling back to 'misc/others.json'.")
        product_file_path = os.path.join(cves_dir, 'misc', 'others.json')
        if not os.path.exists(product_file_path):
            print(f"CRITICAL ERROR: Fallback file 'others.json' not found at '{product_file_path}'. Skipping.")
            return

    print(f"INFO: Updating target file: {product_file_path}")
    
    # Load existing data from the specific product file
    product_db_data = []
    try:
        with open(product_file_path, 'r', encoding='utf-8') as f:
            product_db_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"INFO: Product file '{product_file_path}' not found or invalid. Starting fresh.")

    existing_ids = {cve.get('id') for cve in product_db_data if cve.get('id')}
    print(f"INFO: Loaded {len(existing_ids)} existing CVEs from this file.")

    api_data = fetch_cves_for_product(search_term, api_key)
    if not api_data:
        return

    new_cves_added = 0
    for item in api_data:
        cve_entry = transform_and_enrich_cve(item, product_name, script_map)
        if cve_entry['id'] and cve_entry['id'] not in existing_ids:
            product_db_data.append(cve_entry)
            existing_ids.add(cve_entry['id'])
            new_cves_added += 1

    if new_cves_added > 0 or not os.path.exists(product_file_path):
        product_db_data.sort(key=lambda x: x.get('id', ''))
        # Replicate the exact writing format from the original function
        with open(product_file_path, 'w', encoding='utf-8') as f:
            f.write('[\n')
            for i, entry in enumerate(product_db_data):
                # Use separators to keep it compact on one line, but write line by line
                line = json.dumps(entry, ensure_ascii=False, separators=(',', ':'))
                f.write('  ' + line)
                if i < len(product_db_data) - 1:
                    f.write(',\n')
                else:
                    f.write('\n')
            f.write(']\n')
        print(f"SUCCESS: Added {new_cves_added} new CVEs to {product_name}.json. Total now: {len(product_db_data)}.")
    else:
        print(f"INFO: No new CVEs to add for {product_name}. File is up-to-date.")


def update_main_cve_database(product_name: str, search_term: str, script_map: dict, api_key: str = None):
    """
    DEPRECATED in the new architecture, but kept for compatibility.
    Updates the main CVE database (`cve-main.json`) with new CVEs fetched from NVD.
    """
    print(f"\n{'='*20}\nProcessing product: {product_name}\n{'='*20}")
    main_db_path = os.path.join(DATABASE_DIR, 'cve-main.json')
    main_db_data = []
    try:
        with open(main_db_path, 'r', encoding='utf-8') as f:
            main_db_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"INFO: Main database '{main_db_path}' not found or invalid. Starting fresh.")
    
    existing_ids = {cve.get('id') for cve in main_db_data if cve.get('id')}
    print(f"INFO: Loaded {len(existing_ids)} existing CVEs.")
    api_data = fetch_cves_for_product(search_term, api_key)
    if not api_data: return
    new_cves_added = 0
    for item in api_data:
        cve_entry = transform_and_enrich_cve(item, product_name, script_map)
        if cve_entry['id'] and cve_entry['id'] not in existing_ids:
            main_db_data.append(cve_entry); existing_ids.add(cve_entry['id']); new_cves_added += 1
    if new_cves_added > 0 or not os.path.exists(main_db_path):
        main_db_data.sort(key=lambda x: x.get('id', ''))
        with open(main_db_path, 'w', encoding='utf-8') as f:
            f.write('[\n')
            for i, entry in enumerate(main_db_data):
                f.write('  ' + json.dumps(entry, ensure_ascii=False))
                if i < len(main_db_data) - 1:
                    f.write(',\n')
                else:
                    f.write('\n')
            f.write(']\n')
        print(f"SUCCESS: Added {new_cves_added} new CVEs. Total CVEs now: {len(main_db_data)}.")
    else:
        print(f"INFO: No new CVEs to add. Database is up-to-date.")

def add_single_cve_to_main_db(cve_id: str, product_name: str, script_map: dict, api_key: str = None):
    """
    Adds a single CVE entry to the main CVE database.
    This function reuses the `update_main_cve_database` logic by setting the
    search term to the specific CVE ID.

    @param cve_id (str): The ID of the single CVE to add (e.g., "CVE-2021-12345").
    @param product_name (str): The product name associated with this CVE.
    @param script_map (dict): A dictionary mapping CVE IDs to Nmap script names.
    @param api_key (str, optional): Your NVD API key. Defaults to None.
    """
    print(f"\n{'='*20}\nProcessing single CVE: {cve_id} for product {product_name}\n{'='*20}")
    update_main_cve_database(product_name=product_name, search_term=cve_id, script_map=script_map, api_key=api_key)

def load_json_config(path: str) -> list or dict:
    """
    Helper function to load a JSON configuration file.
    Exits the script if the file is not found or cannot be parsed.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"CRITICAL ERROR: Could not load or parse config file at '{path}'. Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    NVD_API_KEY = os.getenv("NVD_API_KEY")
    if not NVD_API_KEY:
        print("WARNING: NVD_API_KEY environment variable not set. API requests might be rate-limited.")
        try:
            NVD_API_KEY = input("Enter your NVD API Key (optional, press Enter to skip): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSkipping API key input.")
            NVD_API_KEY = None

    # Load product configurations as the "Single Source of Truth"
    products_config_path = os.path.join(DATABASE_DIR, 'product.json')
    products_to_update = load_json_config(products_config_path)
    print(f"INFO: Loaded {len(products_to_update)} product configurations from '{products_config_path}'.")

    # Load active script mappings (optional)
    script_map_path = os.path.join(DATABASE_DIR, 'script_mapping.json')
    try:
        script_map = load_json_config(script_map_path)
        print(f"INFO: Loaded {len(script_map)} active script mappings.")
    except SystemExit: # If file not found, proceed with an empty map
        script_map = {}

    print("\nStarting database update based on product.json configuration...")
    for product_config in products_to_update:
        if "standard_name" in product_config and "search_term" in product_config:
            # Call the new function, passing the whole product_config dictionary
            update_individual_product_file(
                product_config=product_config,
                script_map=script_map,
                api_key=NVD_API_KEY
            )
        else:
            print(f"WARNING: Skipping invalid product entry in config: {product_config}")

    # The logic for single CVEs should also be adapted or reviewed.
    # For now, we will comment it out to focus on the main product flow.
    # single_cves_to_add = [
    #     {
    #         "id": "CVE-2017-0144", # MS17-010
    #         "product": "microsoft-ds"
    #     },
    # ]
    # for cve_entry in single_cves_to_add:
    #     add_single_cve_to_main_db(
    #         cve_id=cve_entry["id"],
    #         product_name=cve_entry["product"],
    #         script_map=script_map,
    #         api_key=NVD_API_KEY
    #     )

    print("\nAll update processes finished.")
