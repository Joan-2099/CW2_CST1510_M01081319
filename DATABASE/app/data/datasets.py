import sys
from pathlib import Path
import csv
from .db import connect_database


project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

CSV_FILE = Path(__file__).resolve().parents[3] / "DATA" / "datasets_metadata.csv"


class Datasets:
    def __init__(self):
        self.csv_path = CSV_FILE

    #Save dataset data to a CSV file as a backup.
    def _write_to_csv(self, row_data):
    
        #Adds a header if the CSV is empty or doesn't exist.
        write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
        with open(self.csv_path, "a", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow([
                    "id","name", "date","description", "source",
                    "date_created", "last_updated","record_count","file_size_mb","created at"
                ])
            writer.writerow(row_data)


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
        # update CSV backup as well
        self._write_to_csv([
            dataset_id,name, description, source, date_created, last_updated, record_count, file_size_mb
        ])
        return dataset_id

    

    def get_dataset_by_id(self,dataset_id):
        """Fetch a dataset by its ID."""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM datasets_metadata WHERE id = ?", (dataset_id,))
        dataset = cursor.fetchone()
        conn.close()
        return dataset

    def get_all_datasets(self):
        """Fetch all datasets."""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM datasets_metadata")
        datasets = cursor.fetchall()
        conn.close()
        return datasets
