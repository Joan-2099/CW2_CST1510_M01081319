import sqlite3
from pathlib import Path
from DATABASE.app.data.schema import TableCreator

DB_PATH = Path("DATA") / "intelligence_platform.db"


#Connect to SQLite database.
def connect_database(db_path=DB_PATH):
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





    
