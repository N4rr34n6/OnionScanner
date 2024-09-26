# OnionScanner V3 - Enhanced Version

An enhanced version of the OnionScanner tool for scanning and analyzing .onion V3 domains on the Dark Web. This version features SQLite database integration, domain validation, persistence, and scalability for handling large datasets, optimized for efficient scanning of unique .onion V3 domains.

This project is an enhanced version of the `.onion` domain scanner for the Dark Web, designed to efficiently process and analyze unique `.onion` V3 domains. It includes databases, advanced validation, and optimization to handle large volumes of data.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Key Features](#key-features)
3. [Improvements Over the Original Version](#improvements-over-the-original-version)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Configuration](#configuration)
7. [Usage](#usage)
8. [Importing Domains from a Text File](#importing-domains-from-a-text-file)
9. [Project Structure](#project-structure)
10. [Security Considerations](#security-considerations)
11. [Contributions](#contributions)
12. [License](#license)
13. [Acknowledgments](#acknowledgments)

---

## Introduction

The OnionScanner project is an advanced modification of [Darkweb_OnionScan](https://github.com/4n6shetty/Darkweb_OnionScan), originally published by [4n6shetty](https://github.com/4n6shetty). Since the original project has not been updated since February 23, 2021, it was decided to create this new repository with significant improvements in functionality, efficiency, and scalability.

The main objective of this project is to provide a robust and efficient tool for scanning and analyzing hidden services on the Tor network, specifically focusing on `.onion` V3 domains.

---

## Key Features

- Specifically designed to process unique `.onion` V3 domains.
- Avoids duplicates and invalid domains, including V2.
- Utilizes SQLite databases to store scan results and lists of `.onion` domains.
- Implements validation for `.onion` domains to enhance data accuracy.
- Offers increased persistence and scalability to handle large volumes of information.
- Allows automatic discovery and storage of new `.onion` domains found during scanning.
- Implements error handling and timeout systems to manage connectivity issues.
- Utilizes multithreading to improve scanning efficiency.

---

## Improvements Over the Original Version

1. **Database Usage**: 
   - Implementation of SQLite to store results and domain lists.
   - Enables faster queries and better scalability.
   - Facilitates later analysis of collected data.

2. **Domain Validation**: 
   - Includes specific validation for `.onion` V3 domains.
   - Improves the accuracy of stored data.
   - Avoids unnecessary processing of invalid or outdated domains.

3. **Enhanced Persistence**: 
   - The database structure allows for more detailed and organized storage.
   - Facilitates later queries and analysis.
   - Maintains a history of scans for tracking and comparison.

4. **Optimization**: 
   - The use of SQLite significantly improves the efficiency in handling large volumes of data.
   - Implementation of multithreading for simultaneous scanning.
   - Tor identity change system to avoid blocking and improve anonymity.

5. **Scalability**: 
   - The new structure better supports the handling of large amounts of information.
   - Facilitates the implementation of new features and scanning modules.
   - Allows for future expansion to include more complex analyses.

---

## Requirements

- **Python 3.7+**
- **Tor** (configured to use control port 9051)
- **OnionScan** (modified version for V3 domains)
- **Python Libraries**: `stem`, `sqlite3`

For the proper functioning of this project, the OnionScan version from the repository [mhatta/onionscan](https://github.com/mhatta/onionscan), created by [mhatta](https://github.com/mhatta), should be used. This is a modification of the original project [s-rah/onionscan](https://github.com/s-rah/onionscan) by [s-rah](https://github.com/s-rah).

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/n4rr34n6/OnionScanner.git
   cd OnionScanner
   ```

2. Install the Python dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

3. Install the modified version of OnionScan:
   ```bash
   go get github.com/mhatta/onionscan
   ```

---

## Configuration

1. Ensure that Tor is installed and configured to use control port 9051.

2. Add the Go binaries directory to your PATH:
   ```bash
   export PATH=$PATH:~/go/bin
   ```

3. Configure the Tor control password in the script (replace `_n4rr34n6_` with your actual password):
   ```python
   torcontrol.authenticate("_n4rr34n6_")
   ```

---

## Usage

1. Run the main script:
   ```bash
   python3 OnionScanner.py
   ```

2. The script will begin scanning the `.onion` domains stored in the database.

3. The results will be stored in the SQLite database and also saved as individual JSON files in the `onionscan_results` directory.

4. To query the results, you can use the functions of the `OnionDatabase` class or query the SQLite database directly.

---

## Importing Domains from a Text File

An additional script, `migrate_from_file_to_db.py`, is provided to facilitate the migration of `.onion` domains from a text file into the SQLite database. This is particularly useful for users who may already have a list of domains and want to quickly import them without manual entry.

---

### Usage

1. Ensure you have your `.onion` domains listed in a text file, with each domain on a new line. For example, create a file named `onion_dir_list.txt`.

2. Run the migration script by specifying the path to your text file and the database path:
   ```bash
   python3 migrate_from_file_to_db.py

---

## Project Structure

- `OnionScanner.py`: Main script that manages the scanning process.
- `OnionStorage`: Class for handling storage of `.onion` domains.
- `OnionDatabase`: Class for handling storage of scan results.
- `run_onionscan()`: Function to run OnionScan on a specific domain.
- `process_results()`: Function to process and store the results of the scan.
- `add_new_onions()`: Function to add newly discovered domains during the scan.

---

## Security Considerations

- This script interacts with the Tor network and hidden services. Ensure you understand the security and privacy implications before using it.
- It is recommended to run this script in a virtual machine or an isolated environment.
- Using this tool to scan services without authorization may be illegal. Use it only for ethical and legal purposes.
- The Tor control password is hardcoded in the script. Consider implementing a more secure method to handle this sensitive information.

---

## Contributions

Contributions are welcome. Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature (`git checkout -b feature/AmazingFeature`).
3. Make your changes and commit (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

For significant changes, please open an issue first to discuss what you would like to change.

---

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the [LICENSE](LICENSE) file for more details.

---

## Acknowledgments

- [4n6shetty](https://github.com/4n6shetty) for the original Darkweb_OnionScan project.
- [mhatta](https://github.com/mhatta) for the modified version of OnionScan for V3 domains.
- [s-rah](https://github.com/s-rah) for the original OnionScan project.
- The open-source community for the various libraries and tools used in this project.

