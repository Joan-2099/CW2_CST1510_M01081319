import sqlite3
from pathlib import Path

# Absolute path to your database
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
db_path = project_root / "DATA" / "intelligence_platform.db"

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Add the resolved_at column
try:
    cursor.execute("ALTER TABLE cyber_incidents ADD COLUMN resolved_at TEXT;")
    conn.commit()
    print("Column 'resolved_at' added successfully.")
except sqlite3.OperationalError as e:
    # This happens if the column already exists
    print(f"Operation failed: {e}")
finally:
    conn.close()