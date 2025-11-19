import sqlite3
from pathlib import Path
from app.data.schema import create_all_tables


DB_PATH = Path("DATA") / "intelligence_platform.db"


def connect_database(db_path=DB_PATH):
    """Connect to SQLite database."""

    # Ensure the folder exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(db_path))


def init_database():
    """Initialize the database and create all tables."""
    conn = connect_database()
    create_all_tables(conn)
    conn.close()
    print("Database initialized and tables created.")
