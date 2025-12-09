import sys
from pathlib import Path
from .db import connect_database


project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

CSV_FILE = Path(__file__).resolve().parents[3] / "DATA" / "cyber_incidents.csv"


class Datasets:
    def __init__(self):
        self.csv_path = CSV_FILE

    def get_dataset_by_id(self,dataset_id):
        """Fetch a dataset by its ID."""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM datasets_metadata WHERE id = ?", (dataset_id,))
        dataset = cursor.fetchone()
        conn.close()
        return dataset


    def insert_dataset(self,name, description=None, source=None, date_created=None, last_updated=None, record_count=None, file_size_mb=None):
        """Insert a new dataset into datasets_metadata table."""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO datasets_metadata 
            (name, description, source, date_created, last_updated, record_count, file_size_mb) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, description, source, date_created, last_updated, record_count, file_size_mb))
        dataset_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return dataset_id


    def get_all_datasets(self):
        """Fetch all datasets."""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM datasets_metadata")
        datasets = cursor.fetchall()
        conn.close()
        return datasets
