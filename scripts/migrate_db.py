import sqlite3
import os

DB_FILES = ["exam_monitor.db", "exam_monitor_v2.db"]

def migrate_db(db_path):
    if not os.path.exists(db_path):
        print(f"Database {db_path} not found.")
        return

    print(f"Migrating {db_path}...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if column exists
        cursor.execute("PRAGMA table_info(log_entries)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if "source" in columns:
            print(f"Column 'source' already exists in {db_path}.")
        else:
            print(f"Adding column 'source' to {db_path}...")
            cursor.execute("ALTER TABLE log_entries ADD COLUMN source TEXT DEFAULT 'realtime'")
            conn.commit()
            print("Migration successful.")
            
    except Exception as e:
        print(f"Error migrating {db_path}: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    # Assuming script is run from project root or checks current dir
    for db_file in DB_FILES:
        # Check current dir
        if os.path.exists(db_file):
            migrate_db(db_file)
        # Check backend dir
        elif os.path.exists(os.path.join("backend", db_file)):
            migrate_db(os.path.join("backend", db_file))
        # Check project root if we are in scripts
        elif os.path.exists(os.path.join("..", db_file)):
             migrate_db(os.path.join("..", db_file))
        else:
            print(f"Could not find {db_file}")
