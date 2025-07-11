# 🗄️ DursVuln - Community Database Repository

<p align="center">
  <img src="logo/dursvuln-logo.png" width="500">
</p>

<h3 align="center">📦 Repository Attributes</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Database-Community%20Driven-blue?style=for-the-badge&logo=github" alt="Community Driven">
  <img src="https://img.shields.io/badge/Automation-Ready-yellow?style=for-the-badge&logo=githubactions" alt="Automation Ready">
</p>

---

## 📝 Table of Contents
- ℹ️ [About This Repository](#about-this-repository)
- 🎯 [Purpose for End-Users](#purpose-for-end-users)
- 🏗️ [System Architecture](#system-architecture)
- ✨ [Key Features](#key-features)
- 🗂️ [Directory Structure](#directory-structure)
- 🤝 [How to Contribute](#how-to-contribute)
- 🔧 [Database Management Tools](#database-management-tools)
  - ⚪ [`db_updater.py`](#db_updaterpy)
  - ⚪ [`merger.py`](#mergerpy)
  - ⚪ [`version_refactor.py`](#version_refactorpy)
- 📄 [Configuration Files](#configuration-files)
  - ⚪ [`product.json`](#productjson)
  - ⚪ [`script_mapping.json`](#script_mappingjson)
- 🗺️ [Future Roadmap](#future-roadmap)

---

# ℹ️ About This Repository

This repository serves as the central, community-driven database for the **[`DursVulnNSE`](https://github.com/roomkangali/DursVulnNSE)**  project. It is designed to be a collaborative and scalable ecosystem for managing vulnerability information.

The core philosophy is to **separate the raw data sources from the final, distributable database**. This allows for easy contributions from the community without creating complex merge conflicts, while providing a single, optimized database file for end-users of the DursVulnNSE scanner.

## 🎯 Purpose for End-Users

The primary artifacts of this repository are the comprehensive and up-to-date vulnerability database files: `cve-main.json`, `product.json`, and `script_mapping.json`.

End-users of the DursVulnNSE scanner can download these generated files from this repository. These files are intended to replace the existing files within the `database/` directory of a standard DursVulnNSE installation, providing the scanner with the latest vulnerability data and configurations. Cloning the entire repository is not necessary for this purpose.

## 🏗️ System Architecture

This repository uses a two-phase workflow: **Contribution & Curation** and **Distribution**.

**Phase 1: Contribution & Curation (The Community Phase)**
This is where all additions and updates happen. Contributors work with small, manageable JSON files organized by category.

-   **Source of Truth**: The `product.json` file dictates which products are tracked.
-   **Updating**: The `tools/db_updater.py` script reads this configuration, fetches the latest CVEs from the NVD, and intelligently updates the small, corresponding JSON files in the `cves/` directory. If a specific file for a product is not found, CVEs will be added to `cves/misc/others.json`.
-   **Contribution**: Users can easily add new CVEs by editing these small, topic-specific files.

**Phase 2: Distribution (The End-User Phase)**
This phase produces the final database file that the DursVulnNSE scanner uses.

-   **Merging**: The `tools/merger.py` script is run. It traverses all the small JSON files in the `cves/` directory.
-   **Consolidation**: It de-duplicates, sorts, and merges all entries into a single, large `cve-main.json` file.
-   **Final Output**: The `cve-main.json` file is the final artifact. End-users of the scanner only need to download this one file to get the complete, up-to-date database.

```
+-------------------------------------------------------------------------+
| PHASE 1: CONTRIBUTION & CURATION                                        |
|                                                                         |
|  [+] Configuration Input                                                |
|   |                                                                     |
|   '--- [ product.json ]                                                 |
|        (Defines products to be tracked)                                 |
|                                                                         |
|       |                                                                 |
|       V                                                                 |
|                                                                         |
|  [>] Core Process: Data Updater                                         |
|   |                                                                     |
|   |    +---------------------+                                          |
|   |    |   db_updater.py     | <--- (Fetching data) ---- [ NVD API ]    |
|   |    +---------------------+                                          |
|   |           |                                                         |
|   |           V (Updates individual files, or falls back to others.json)|
|   |                                                                     |
|   '-> [>] Output: Curated CVE Files (Initial)                           |
|           |                                                             |
|           V                                                             |
|    +--------------------------------+                                   |
|    |  cves/{category}/{product}.json| (Small, manageable JSON files)    |
|    |  (e.g., cves/misc/others.json) |                                   |
|    +--------------------------------+                                   |
|           |                                                             |
|           V (Optional: Refactor Version Matches)                        |
|                                                                         |
|  [>] Core Process: Version Refactor                                     |
|   |                                                                     |
|   |    +-------------------------+                                      |
|   |    |   version_refactor.py   |                                      |
|   |    +-------------------------+                                      |
|   |           |                                                         |
|   |           V (Refactors 'version_match' field)                       |
|   |                                                                     |
|   '-> [>] Output: Curated CVE Files (Refactored)                        |
|           |                                                             |
|           V                                                             |
|    +--------------------------------+                                   |
|    |  cves/{category}/{product}.json| (Updated JSON files)              |
|    +--------------------------------+                                   |
|                                                                         |
+-------------------------------------------------------------------------+
```
```
+-------------------------------------------------------------------------+
| PHASE 2: DISTRIBUTION                                                   |
|                                                                         |
|  [+] Trigger: Manual or Automated Execution                             |
|   |                                                                     |
|   '--- > python3 tools/merger.py                                        |
|                                                                         |
|           |                                                             |
|           V                                                             |
|                                                                         |
|  [>] Core Process: Database Merger                                      |
|   |                                                                     |
|   |    +---------------------+                                          |
|   |    |     merger.py       | <--- (Reads all files from cves/)        |
|   |    +---------------------+                                          |
|   |           |                                                         |
|   |           V (De-duplicates, sorts, and merges)                      |
|   |                                                                     |
|   '-> [>] Output: Final Distributable Database                          |
|           |                                                             |
|           V                                                             |
|    +------------------+                                                 |
|    |  cve-main.json   | (Single, optimized file for the scanner)        |
|    +------------------+                                                 |
|                                                                         |
+-------------------------------------------------------------------------+
```


## ✨ Key Features
-   **Modular & Scalable**: The database is split into small, category-based files, making it easy to manage and scale.
-   **Contributor-Friendly**: Drastically reduces merge conflicts and simplifies the process of adding new vulnerabilities.
-   **Automated Tools**: Provides scripts to fetch, update, and merge CVE data, ensuring consistency and accuracy.
-   **Decoupled Architecture**: Separates the database management workflow from the scanner's operational logic. End-users only need the final `cve-main.json`.

## 🗂️ Directory Structure
```
Repo-Database/
│
├── cves/
│   ├── ad/
│   ├── database/
│   ├── http/
│   └── ... (other categories)
│
├── tools/
│   ├── db_updater.py
│   └── merger.py
│
├── cve-main.json
├── product.json
└── script_mapping.json
```

## 🤝 How to Contribute
Contributions to this database repository are highly welcome! This repository is specifically for managing and updating the vulnerability data.

*   **For Database Issues & Contributions**: For issues, updates, or contributions related to the vulnerability database (adding new CVEs, updating existing ones, etc.), please create pull requests or open issues in *this* repository.
    *   **How to Contribute Data**:
        1.  **Locate the Target File**: Navigate to the appropriate category within the `cves/` directory (e.g., `cves/http/` for a web server vulnerability).
        2.  **Edit the File**: Open the relevant JSON file (e.g., `nginx.json`).
        3.  **Add the CVE Data**: Append a new CVE object to the JSON array, ensuring it adheres to the established format.
        4.  **Submit a Pull Request**: A pull request should be submitted with the changes to the specific JSON file.
        Contributions will be reviewed and, upon merging, will be incorporated into the next build of `cve-main.json`.


## 🔧 Database Management Tools

This repository contains two primary Python scripts located in the `tools/` directory.

### `db_updater.py`
This script is used to populate the individual CVE files.
-   It reads `product.json` to determine which products to update.
-   It fetches the latest CVE data from the NVD API.
-   It intelligently finds the correct destination file (e.g., `cves/database/mysql.json`) or falls back to `cves/misc/others.json` if no specific file is found.
-   It enriches the data using `script_mapping.json`.

**Usage:**
```bash
# Install dependencies
pip install requests

# Run the updater
python3 tools/db_updater.py
```

### `merger.py`
This script consolidates all the individual files into the final database.
-   It recursively scans the `cves/` directory for all `.json` files.
-   It handles empty files gracefully.
-   It de-duplicates all entries by CVE ID.
-   It sorts the final list by CVE ID.
-   It overwrites the top-level `cve-main.json` with the fresh, unified data.

**Usage:**
```bash
# Run the merger after updating individual files
python3 tools/merger.py
```

### `version_refactor.py`

This script is designed to standardize and improve the accuracy of `version_match` fields within existing CVE entries across the database. It transforms flat lists of version conditions into a more structured, grouped format, which enhances the precision of vulnerability matching by the DursVulnNSE scanner.

**Key Features:**
-   **Automated Traversal**: Recursively scans all `.json` files within the `cves/` directory.
-   **Intelligent Grouping**: Identifies and groups related version conditions (e.g., conditions for the same major version) into nested lists.
-   **Format Standardization**: Converts flat `version_match` arrays (e.g., `["<1.0", ">=2.0"]`) into a nested, OR-logic compatible format (e.g., `[["<1.0"], [">=2.0"]]`).
-   **In-place Update**: Overwrites the original JSON files with the refactored content, maintaining the one-line-per-entry format.

**Functions:**

#### `group_version_conditions(conditions)`
-   **Purpose**: Takes a flat list of version condition strings and groups them into nested lists based on their major version number. This function is the core logic for transforming the `version_match` format.
-   **Parameters**:
    -   `conditions` (list): A list of version strings (e.g., `["<10.0.16", ">=10.0.0"]`).
-   **Returns**: A refactored list of lists (e.g., `[["<10.0.16", ">=10.0.0"]]`) or the original list if no grouping is applicable.

#### `refactor_cve_files(cves_dir)`
-   **Purpose**: The main function that orchestrates the refactoring process. It iterates through all JSON files, reads their content, applies `group_version_conditions` to relevant CVE entries, and writes the updated data back to the files.
-   **Parameters**:
    -   `cves_dir` (str): The path to the base `cves/` directory containing the individual CVE JSON files.

**Usage:**
```bash
# Run the version refactor script
python3 tools/version_refactor.py
```

### `version_refactor.py`

This script is designed to standardize and improve the accuracy of `version_match` fields within existing CVE entries across the database. It transforms flat lists of version conditions into a more structured, grouped format, which enhances the precision of vulnerability matching by the DursVulnNSE scanner.

**Key Features:**
-   **Automated Traversal**: Recursively scans all `.json` files within the `cves/` directory.
-   **Intelligent Grouping**: Identifies and groups related version conditions (e.g., conditions for the same major version) into nested lists.
-   **Format Standardization**: Converts flat `version_match` arrays (e.g., `["<1.0", ">=2.0"]`) into a nested, OR-logic compatible format (e.g., `[["<1.0"], [">=2.0"]]`).
-   **In-place Update**: Overwrites the original JSON files with the refactored content, maintaining the one-line-per-entry format.

**Functions:**

#### `group_version_conditions(conditions)`
-   **Purpose**: Takes a flat list of version condition strings and groups them into nested lists based on their major version number. This function is the core logic for transforming the `version_match` format.
-   **Parameters**:
    -   `conditions` (list): A list of version strings (e.g., `["<10.0.16", ">=10.0.0"]`).
-   **Returns**: A refactored list of lists (e.g., `[["<10.0.16", ">=10.0.0"]]`) or the original list if no grouping is applicable.

#### `refactor_cve_files(cves_dir)`
-   **Purpose**: The main function that orchestrates the refactoring process. It iterates through all JSON files, reads their content, applies `group_version_conditions` to relevant CVE entries, and writes the updated data back to the files.
-   **Parameters**:
    -   `cves_dir` (str): The path to the base `cves/` directory containing the individual CVE JSON files.

**Usage:**
```bash
# Run the version refactor script
python3 tools/version_refactor.py
```

## 📄 Configuration Files

The root directory contains the primary configuration files that drive the database generation tools.

### `product.json`
This is the central configuration file for the `db_updater.py` script. It defines which products to track and how to find their CVEs.

-   `standard_name`: The canonical name for the product. This should match the name of the corresponding `.json` file in the `cves/` directory.
-   `search_term`: The keyword or CPE string used to query the NVD API.
-   `aliases`: A list of other names for the product.

### `script_mapping.json`
This file maps critical CVEs to specific Nmap scripts that can be used for active verification.

-   **Key**: The CVE ID (e.g., `"CVE-2017-0144"`).
-   **Value**: The name of the Nmap script (e.g., `"smb-vuln-ms17-010"`).

## 🗺️ Future Roadmap
-   **GitHub Actions Integration**: Automate the `merger.py` script to run on every push to the main branch, ensuring `cve-main.json` is always up-to-date.
-   **Schema Validation**: Add a validation step to the tools to ensure all contributed CVEs adhere to the correct format.
-   **Enhanced Reporting**: Improve the console output of the tools for better readability and logging.

---
 