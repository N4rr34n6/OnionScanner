from stem.control import Controller
from stem import Signal
from threading import Timer
from threading import Event
import codecs
import json
import os
import random
import subprocess
import sys
import time
import sqlite3
import re

# Global lists to hold onion domains
onions = []
session_onions = []
# Event to manage identity switching in Tor
identity_lock = Event()
identity_lock.set()

class OnionStorage:
    def __init__(self, db_name='onion_list.db'):
        # Initialize with the specified database name
        self.db_name = db_name
        self.conn = None
        self.create_database()  # Create the database upon initialization

    def create_database(self):
        # Connect to the SQLite database and create the onions table if it doesn't exist
        self.conn = sqlite3.connect(self.db_name)
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS onions
                     (onion TEXT PRIMARY KEY)''')
        self.conn.commit()

    def store_unique_onion(self, onion):
        # Store a unique onion in the database
        if not self.is_valid_v3_onion(onion):
            print(f"[!] Skipping invalid or v2 onion: {onion}")
            return  # Skip if the onion is not valid

        c = self.conn.cursor()
        try:
            # Insert the onion into the database, ignoring duplicates
            c.execute("INSERT OR IGNORE INTO onions (onion) VALUES (?)", (onion,))
            if c.rowcount > 0:
                print(f"[++] Storing {onion} in database.")
            else:
                print(f"[!] {onion} already exists in the database. Skipping.")
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"[!!!] An error occurred: {e}")  # Print any errors that occur

    def is_valid_v3_onion(self, onion):
        # Validate if the provided onion domain is a valid V3 onion
        return bool(re.match(r'^[a-z2-7]{56}\.onion$', onion))

    def get_all_onions(self):
        # Retrieve all onions from the database
        c = self.conn.cursor()
        c.execute("SELECT onion FROM onions")
        return [row[0] for row in c.fetchall()]

    def close_connection(self):
        # Close the database connection
        if self.conn:
            self.conn.close()

def get_onion_list(onion_storage):
    # Get the list of onions from storage and handle the case where there are none
    stored_onions = onion_storage.get_all_onions()
    if not stored_onions:
        print("[!] No onion dir list. Download it!")
        sys.exit(0)  # Exit if no onions are found
    print(f"[*] Total v3 onions for scanning: {len(stored_onions)}")
    return stored_onions

class OnionDatabase:
    def __init__(self, db_name):
        # Initialize with the specified database name
        self.db_name = db_name
        self.conn = None 
        self.create_database()  # Create the database upon initialization

    def create_database(self):
        # Connect to the SQLite database and create the combinedResults table if it doesn't exist
        self.conn = sqlite3.connect(self.db_name)
        c = self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS combinedResults (
            hiddenService TEXT PRIMARY KEY,
            dateScanned TEXT,
            online INTEGER,
            performedScans TEXT,
            webDetected INTEGER,
            tlsDetected INTEGER,
            sshDetected INTEGER,
            ricochetDetected INTEGER,
            ircDetected INTEGER,
            ftpDetected INTEGER,
            smtpDetected INTEGER,
            bitcoinDetected INTEGER,
            mongodbDetected INTEGER,
            vncDetected INTEGER,
            xmppDetected INTEGER,
            skynetDetected INTEGER,
            crawls TEXT,
            pgpKeys TEXT,
            certificates TEXT,
            bitcoinServices TEXT,
            sshKey TEXT,
            sshBanner TEXT,
            ftpFingerprint TEXT,
            ftpBanner TEXT,
            smtpFingerprint TEXT,
            smtpBanner TEXT,
            lastAction TEXT,
            timedOut INTEGER,
            error TEXT,
            privateKeyDetected INTEGER,
            foundApacheModStatus INTEGER,
            foundApacheModInfo INTEGER,
            serverVersion TEXT,
            relatedOnionServices TEXT,
            relatedOnionDomains TEXT,
            ipAddresses TEXT,
            emailAddresses TEXT,
            analyticsIDs TEXT,
            bitcoinAddresses TEXT,
            linkedOnions TEXT,
            openDirectories TEXT,
            exifImages TEXT,
            risks TEXT
        );""")
        self.conn.commit()

    def insert_data(self, onion, result):
        # Insert scan results into the combinedResults table
        c = self.conn.cursor()
        scan_result = json.loads(result.decode("utf8"))  # Decode and load the JSON result
        values = (
            onion,
            scan_result.get("dateScanned", ""),
            int(scan_result.get("online", False)),
            json.dumps(scan_result.get("performedScans", []), indent=2),
            int(scan_result.get("webDetected", False)),
            int(scan_result.get("tlsDetected", False)),
            int(scan_result.get("sshDetected", False)),
            int(scan_result.get("ricochetDetected", False)),
            int(scan_result.get("ircDetected", False)),
            int(scan_result.get("ftpDetected", False)),
            int(scan_result.get("smtpDetected", False)),
            int(scan_result.get("bitcoinDetected", False)),
            int(scan_result.get("mongodbDetected", False)),
            int(scan_result.get("vncDetected", False)),
            int(scan_result.get("xmppDetected", False)),
            int(scan_result.get("skynetDetected", False)),
            json.dumps(scan_result.get("crawls", {}), indent=2),
            json.dumps(scan_result.get("pgpKeys", [])),
            json.dumps(scan_result.get("certificates", [])),
            json.dumps(scan_result.get("bitcoinServices", {}), indent=2),
            scan_result.get("sshKey", ""),
            scan_result.get("sshBanner", ""),
            scan_result.get("ftpFingerprint", ""),
            scan_result.get("ftpBanner", ""),
            scan_result.get("smtpFingerprint", ""),
            scan_result.get("smtpBanner", ""),
            scan_result.get("lastAction", ""),
            int(scan_result.get("timedOut", False)),
            scan_result.get("error", ""),
            int(scan_result.get("identifierReport", {}).get("privateKeyDetected", False)),
            int(scan_result.get("identifierReport", {}).get("foundApacheModStatus", False)),
            int(scan_result.get("identifierReport", {}).get("foundApacheModInfo", False)),
            scan_result.get("identifierReport", {}).get("serverVersion", ""),
            json.dumps(scan_result.get("identifierReport", {}).get("relatedOnionServices", []), indent=2),
            json.dumps(scan_result.get("identifierReport", {}).get("relatedOnionDomains", []), indent=2),
            json.dumps(scan_result.get("identifierReport", {}).get("ipAddresses", []), indent=2),
            json.dumps(scan_result.get("identifierReport", {}).get("emailAddresses", []), indent=2),
            json.dumps(scan_result.get("identifierReport", {}).get("analyticsIDs", []), indent=2),
            json.dumps(scan_result.get("identifierReport", {}).get("bitcoinAddresses", []), indent=2),
            json.dumps(scan_result.get("identifierReport", {}).get("linkedOnions", []), indent=2),
            json.dumps(scan_result.get("identifierReport", {}).get("openDirectories", []), indent=2),
            json.dumps(scan_result.get("identifierReport", {}).get("exifImages", []), indent=2),
            json.dumps(scan_result.get("simpleReport", {}).get("risks", []), indent=2)
        )
        c.execute('''
        INSERT OR REPLACE INTO combinedResults VALUES (
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
        );
        ''', values)  # Insert or replace the data in the database
        self.conn.commit()

    def close_connection(self):
        # Close the database connection
        self.conn.close()

def run_onionscan(onion):
    # Execute the OnionScan tool on the specified onion
    print(f"[*] Onionscanning {onion}")
    process = subprocess.Popen(["onionscan","--webport=0","--jsonReport","--simpleReport=false",onion], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process_timer = Timer(300, handle_timeout, args=[process, onion])  # Set a timer for process timeout
    process_timer.start()
    stdout = process.communicate()[0]  # Get output from the process
    if process_timer.is_alive():
        process_timer.cancel()  # Cancel the timer if the process finishes in time
        return stdout
    print("[!!!] Process timed out!")    
    return None  # Return None if the process timed out

def handle_timeout(process, onion):
    # Handle the timeout of the OnionScan process
    global session_onions
    global identity_lock 
    identity_lock.clear()  # Clear the identity lock to prevent new scans
    try:
        process.kill()  # Kill the process if it is still running
        print("[!!!] Killed the onionscan process.")
    except:
        pass
    # Switch the Tor identity to maintain anonymity
    with Controller.from_port(port=9051) as torcontrol:
        torcontrol.authenticate("_n4rr34n6_")
        torcontrol.signal(Signal.NEWNYM)  # Signal Tor to get a new identity
        time.sleep(torcontrol.get_newnym_wait())  # Wait for the new identity to be active
        print("[!!!] Switched TOR identities.")
    session_onions.append(onion)  # Add the onion to the session list
    random.shuffle(session_onions)  # Shuffle the session onions
    identity_lock.set()  # Re-enable the identity lock for new scans
    return

def process_results(onion, json_response, onion_storage):
    # Process the results of the OnionScan
    global onions
    global session_onions
    if not os.path.exists("onionscan_results"):
        os.mkdir("onionscan_results")  # Create a results directory if it doesn't exist
    with open(f"onionscan_results/{onion}.json", "wb") as fd:
        fd.write(json_response)  # Write the JSON response to a file
    scan_result = json.loads(json_response.decode("utf8"))  # Load the scan results as JSON
    # Check for new linked onions and add them to storage
    if scan_result['identifierReport']['linkedOnions'] is not None:
        add_new_onions(onion_storage, scan_result['identifierReport']['linkedOnions'])        
    if scan_result['identifierReport']['relatedOnionDomains'] is not None:
        add_new_onions(onion_storage, scan_result['identifierReport']['relatedOnionDomains'])
    if scan_result['identifierReport']['relatedOnionServices'] is not None:
        add_new_onions(onion_storage, scan_result['identifierReport']['relatedOnionServices'])
    return

def add_new_onions(onion_storage, new_onion_list):
    # Add newly discovered onions to the storage
    for linked_onion in new_onion_list:
        if linked_onion.endswith(".onion"):
            print(f"[++] Discovered new .onion => {linked_onion}")
            onion_storage.store_unique_onion(linked_onion)  # Store the unique onion
    return

def main():
    global onions
    global session_onions

    onion_storage = OnionStorage()  # Initialize the OnionStorage
    onion_db = OnionDatabase('OnionScanner.db')  # Initialize the OnionDatabase

    onions = get_onion_list(onion_storage)  # Get the list of onions
    random.shuffle(onions)  # Shuffle the onions for scanning
    session_onions = list(onions)  # Create a session list of onions
    count = 0

    while count < len(onions):
        identity_lock.wait()  # Wait for the identity lock to be set
        print(f"[*] Running {count} of {len(onions)}.")
        onion = session_onions.pop()  # Get an onion from the session list
        if os.path.exists(f"onionscan_results/{onion}.json"):
            print(f"[!] Already retrieved {onion}. Skipping.")
            count += 1
            continue  # Skip if the results already exist
        result = run_onionscan(onion)  # Run the OnionScan
        if result is not None:
            if len(result):
                process_results(onion, result, onion_storage)  # Process the scan results        
                onion_db.insert_data(onion, result)  # Insert the results into the database
                count += 1

    onion_storage.close_connection()  # Close the storage connection
    onion_db.close_connection()  # Close the database connection

if __name__ == "__main__":
    main()  # Execute the main function
