import sqlite3
import sys

db_paths = [
    r"C:\Users\Atharva\Desktop\project x\Secure-Token-Based-Malpractice-Prevention\exam_monitor_v2.db",
    r"C:\Users\Atharva\Desktop\project x\Secure-Token-Based-Malpractice-Prevention\exam_monitor.db"
]

for db_path in db_paths:
    print(f"Migrating {db_path}...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("ALTER TABLE exam_rooms ADD COLUMN end_time DATETIME")
        conn.commit()
        print(f"Migration successful for {db_path}")
    except sqlite3.OperationalError as e:
        print(f"Migration error for {db_path} (might already exist): {e}")
    except Exception as e:
        print(f"Error for {db_path}: {e}")
    finally:
        conn.close()
