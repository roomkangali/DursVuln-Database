"""
merger.py

Author: Kang Ali
Version: 0.1.0

This script is responsible for consolidating all the individual, category-based
CVE JSON files from the `cves/` directory into a single, unified `cve-main.json`
database file. This unified file is what the dursvuln.nse scanner consumes.

Key Features:
- Traverses all subdirectories within `cves/` to find all .json files.
- Gracefully handles empty JSON files without reporting errors.
- De-duplicates entries based on unique CVE IDs to ensure a clean database.
- Sorts the final list of CVEs by ID (e.g., CVE-2020-..., CVE-2021-...).
- Writes the final, unified database in the exact one-line-per-entry format
  required by the scanner.
"""

import os
import json
import sys

def merge_cve_files(cves_dir, output_file):
    """
    Reads all .json files from subdirectories within cves_dir,
    merges their contents, removes duplicates, sorts by CVE ID,
    and writes to output_file in the exact format required by dursvuln.nse.

    @param cves_dir (str): The path to the base 'cves' directory.
    @param output_file (str): The path to the final 'cve-main.json' file.
    """
    all_cves = {}  # Use a dictionary for automatic deduplication by CVE ID
    total_files_processed = 0
    
    print(f"\nStarting CVE merge process...")
    print(f"Reading from: {cves_dir}")

    for root, _, files in os.walk(cves_dir):
        for file in files:
            if file.endswith(".json"):
                total_files_processed += 1
                filepath = os.path.join(root, file)
                
                # Gracefully handle empty files
                if os.path.getsize(filepath) == 0:
                    print(f"INFO: Skipping empty file: {os.path.relpath(filepath, cves_dir)}")
                    continue

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            count = 0
                            for entry in data:
                                cve_id = entry.get('id')
                                if cve_id and cve_id not in all_cves:
                                    all_cves[cve_id] = entry
                                    count += 1
                            print(f"INFO: Processed '{os.path.relpath(filepath, cves_dir)}', added {count} new CVEs.")
                        else:
                            print(f"WARNING: Skipping non-list content in {filepath}")
                except json.JSONDecodeError as e:
                    print(f"ERROR: Decoding JSON from {filepath}: {e}")
                except Exception as e:
                    print(f"ERROR: Reading {filepath}: {e}")

    # Convert dictionary values to a list and sort by CVE ID
    sorted_cves = sorted(all_cves.values(), key=lambda x: x.get('id', ''))

    # Write to the output file with the exact required format
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('[\n')
            for i, entry in enumerate(sorted_cves):
                line = json.dumps(entry, ensure_ascii=False, separators=(',', ':'))
                f.write('  ' + line)
                if i < len(sorted_cves) - 1:
                    f.write(',\n')
                else:
                    f.write('\n')
            f.write(']\n')
        
        print(f"\n{'='*20}\nMerge Complete\n{'='*20}")
        print(f"Processed {total_files_processed} files.")
        print(f"Successfully merged and de-duplicated {len(sorted_cves)} unique CVEs into {output_file}")
    except Exception as e:
        print(f"CRITICAL ERROR: Could not write merged CVEs to {output_file}: {e}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cves_directory = os.path.join(base_dir, "cves")
    output_cve_main = os.path.join(base_dir, "cve-main.json")

    if not os.path.isdir(cves_directory):
        print(f"CRITICAL ERROR: CVEs directory not found at '{cves_directory}'")
        sys.exit(1)
    
    merge_cve_files(cves_directory, output_cve_main)
