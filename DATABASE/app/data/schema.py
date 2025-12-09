from pathlib import Path
# Path to outer DATA folder
# goes up two levels to CST1520_CS2
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "DATA"
DB_PATH = DATA_DIR / "intelligence_platform.db"

class TableCreator:
    def __init__(self,conn):
        self.conn = conn
        
    def create_users_table(self):
        """Create users table."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        self.conn.commit()


    def create_cyber_incidents_table(self):
        """Create cyber incidents table."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cyber_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                incident_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                description TEXT,
                reported_by TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        #TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        self.conn.commit()
        print("cyber_incidents table created successfully.")


    def create_datasets_metadata_table(self):
        #Create datasets metadata table.
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS datasets_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                source TEXT,
                date_created TEXT,
                last_updated TEXT,
                record_count INTEGER,
                file_size_mb REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()
        print("datasets_metadata table created successfully.")


    def create_it_tickets_table(self):
        #Create IT tickets table.
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS it_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT ,
                assigned_to TEXT,
                resolved_date TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()
        print("it_tickets table created successfully.")

   

    def create_all_tables(self):
        #Create all tables.
        self.create_users_table()
        self.create_cyber_incidents_table()
        self.create_datasets_metadata_table()
        self.create_it_tickets_table()
