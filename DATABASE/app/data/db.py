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
