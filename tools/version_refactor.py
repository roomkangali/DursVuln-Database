"""
version_refactor.py

Author: Kang Ali
Version: 0.1.0

Description:
This script is designed to standardize and improve the accuracy of `version_match`
fields within existing CVE entries across the database. It transforms flat lists
of version conditions into a more structured, grouped format, which enhances the
precision of vulnerability matching by the DursVulnNSE scanner.

Key Features:
- Automated Traversal: Recursively scans all `.json` files within the `cves/` directory.
- Intelligent Grouping: Identifies and groups related version conditions (e.g., conditions
  for the same major version) into nested lists.
- Format Standardization: Converts flat `version_match` arrays (e.g., `["<1.0", ">=2.0"]`)
  into a nested, OR-logic compatible format (e.g., `[["<1.0"], [">=2.0"]]`).
- In-place Update: Overwrites the original JSON files with the refactored content,
  maintaining the one-line-per-entry format.
"""

import os
import json
import re
import sys

def group_version_conditions(conditions: list) -> list:
    """
    Groups a flat list of version conditions into a nested list based on
    their major version number. This function is the core logic for transforming
    the `version_match` format.

    Example input: ["<10.0.16", "<11.0.16", ">=10.0.0", ">=11.0.0"]
    Example output: [["<10.0.16", ">=10.0.0"], ["<11.0.16", ">=11.0.0"]]

    @param conditions (list): A flat list of version condition strings.
    @return list: A refactored list of lists, or the original list if no grouping is applicable.
    """
    version_groups = {}
    
    for condition in conditions:
        # Extract version number from the condition string
        match = re.search(r'(\d[\d\.]*)', condition)
        if not match:
            # If no version number found, add to a generic group or skip
            # For now, we'll just skip conditions without a clear version number
            continue
            
        version_str = match.group(1)
        major_version = version_str.split('.')[0]
        
        if major_version not in version_groups:
            version_groups[major_version] = []
        version_groups[major_version].append(condition)
        
    if not version_groups:
        return conditions # Return original if no groups were made

    # Convert the grouped dictionary to a list of lists
    final_groups = [list(set(v)) for v in version_groups.values()]
    
    # If only one group was created, no need for nested list
    if len(final_groups) == 1:
        return final_groups[0]
        
    return final_groups

def refactor_cve_files(cves_dir: str):
    """
    Traverses all JSON files in the cves directory, finds entries with a
    flat 'version_match' list, and refactors them into grouped, nested lists.

    @param cves_dir (str): The path to the base 'cves' directory containing
                           the individual CVE JSON files.
    """
    print(f"Starting CVE version refactoring process in: {cves_dir}")

    for root, _, files in os.walk(cves_dir):
        for file in files:
            if file.endswith(".json"):
                filepath = os.path.join(root, file)
                
                try:
                    with open(filepath, 'r+', encoding='utf-8') as f:
                        # Handle empty files
                        content = f.read()
                        if not content:
                            continue
                        
                        data = json.loads(content)
                        
                        if not isinstance(data, list):
                            print(f"WARNING: Skipping non-list content in {filepath}")
                            continue

                        made_changes = False
                        for entry in data:
                            version_match = entry.get("version_match")
                            
                            # Check if it's a flat list of strings and not already nested
                            if isinstance(version_match, list) and version_match and isinstance(version_match[0], str):
                                print(f"INFO: Refactoring 'version_match' for {entry.get('id')} in {os.path.relpath(filepath, cves_dir)}")
                                new_version_match = group_version_conditions(version_match)
                                entry["version_match"] = new_version_match
                                made_changes = True
                        
                        if made_changes:
                            # Go back to the beginning of the file to overwrite it
                            f.seek(0)
                            # Write with the same compact, one-line-per-entry format
                            f.write('[\n')
                            for i, entry in enumerate(data):
                                line = json.dumps(entry, ensure_ascii=False, separators=(',', ':'))
                                f.write('  ' + line)
                                if i < len(data) - 1:
                                    f.write(',\n')
                                else:
                                    f.write('\n')
                            f.write(']\n')
                            f.truncate() # Truncate any remaining old content
                            print(f"SUCCESS: Updated {os.path.relpath(filepath, cves_dir)} with refactored version logic.")

                except json.JSONDecodeError as e:
                    print(f"ERROR: Decoding JSON from {filepath}: {e}")
                except Exception as e:
                    print(f"ERROR: Processing {filepath}: {e}")

    print("\nRefactoring process finished.")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cves_directory = os.path.join(base_dir, "cves")
    
    if not os.path.isdir(cves_directory):
        print(f"CRITICAL ERROR: CVEs directory not found at '{cves_directory}'")
        sys.exit(1)
        
    refactor_cve_files(cves_directory)
