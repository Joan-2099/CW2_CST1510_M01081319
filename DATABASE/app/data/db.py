import sys
from pathlib import Path
import sqlite3

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.data.schema import TableCreator

DB_PATH = Path("DATA") / "intelligence_platform.db"


#Connect to SQLite database.
def connect_database(db_path=DB_PATH,check_same_thread=False):
    """Connect to SQLite database."""
     # Convert to Path if it’s a string
    db_path = Path(db_path) if isinstance(db_path, str) else db_path
    
    # Ensure the folder exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(db_path))

#Initialize the database and create all tables.
def init_database():
    conn = connect_database()
    # First create an instance of TableCreator with the connection
    table_creator = TableCreator(conn)
    table_creator.create_all_tables(conn)
    conn.close()
    print("Database initialized and tables created.")

def alter_table(db_path: Path,table_name: str,new_col_name: str,new_col_type: str = "TEXT",backfill_func=None):
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # to access columns by name
    cursor = conn.cursor()

    # Add the column if it doesn't exist
    try:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {new_col_name} {new_col_type};")
        conn.commit()
        print(f"Column '{new_col_name}' added successfully to {table_name}.")
    except sqlite3.OperationalError as e:
        print(f"Operation skipped: {e}")

    # Backfill the column if a function is provided
    if backfill_func:
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        for row in rows:
            row_dict = dict(row)
            # Only backfill if column is NULL or empty
            if not row_dict.get(new_col_name):
                new_value = backfill_func(row_dict)
                cursor.execute(
                    f"UPDATE {table_name} SET {new_col_name} = ? WHERE rowid = ?",
                    (new_value, row_dict['rowid'])
                )
        conn.commit()
        print(f"Backfilled '{new_col_name}' for {len(rows)} rows in {table_name}.")

    conn.close()

#function to wipe table data
def wipe_table(table_name):
    conn = connect_database()  
    try:
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {table_name}")  # remove all rows
        cursor.execute(f"DELETE FROM sqlite_sequence WHERE name='{table_name}'")  # reset autoincrement IDs
        conn.commit()
        print(f"Table '{table_name}' has been wiped clean.")
    finally:
        cursor.close()
        conn.close()
        
#table_name = "cyber_incidents"
#wipe_table(table_name)
