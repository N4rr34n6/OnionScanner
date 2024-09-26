import sqlite3

def migrate_from_file_to_db(file_path, db_path):
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create the table if it does not exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS onions (
        onion TEXT PRIMARY KEY
    )
    ''')

    # Read the file and add each line to the database
    with open(file_path, 'r') as f:
        for line in f:
            onion = line.strip()  # Remove whitespace from the beginning and end
            cursor.execute('INSERT OR IGNORE INTO onions (onion) VALUES (?)', (onion,))

    # Save changes and close the connection
    conn.commit()
    conn.close()
    print("Migration completed.")

# Usage:
migrate_from_file_to_db("onion_dir_list.txt", "onion_list.db")
