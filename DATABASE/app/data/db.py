import sys
from pathlib import Path
import sqlite3
import pandas as pd
import os

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

#load csv files from backend and skips duplicates
def load_csv_to_db(conn, csv_path, table_name, expected_columns=None):
    # Check if the CSV file exists
    if not os.path.isfile(csv_path):
        print(f"Error: CSV file '{csv_path}' does not exist.")
        return 0

    try:
        # Read the CSV into a DataFrame
        df = pd.read_csv(csv_path)

        # Stop if CSV is empty
        if df.empty:
            print(f"Warning: CSV file '{csv_path}' is empty.")
            return 0

        # Keep only the expected columns if provided
        if expected_columns:
            missing_cols = set(expected_columns) - set(df.columns)
            if missing_cols:
                print(f"Error: CSV is missing required columns: {missing_cols}")
                return 0
            df = df[expected_columns]

        # Fetch existing rows to prevent duplicates
        df_existing = pd.read_sql(
            f"SELECT {', '.join(expected_columns)} FROM {table_name}",
            conn
        ) if expected_columns else pd.read_sql(f"SELECT * FROM {table_name}", conn)

        # Compare CSV vs DB to identify new rows
        df_to_insert = pd.merge(
            df,
            df_existing,
            how="outer",
            indicator=True
        )
        df_to_insert = df_to_insert[df_to_insert['_merge'] == 'left_only'].drop(columns='_merge')

        # Exit if nothing new to add
        if df_to_insert.empty:
            print("No new rows to insert — all data already exists in the DB.")
            return 0

        # Insert new rows
        df_to_insert.to_sql(name=table_name, con=conn, if_exists='append', index=False)
        row_count = len(df_to_insert)
        print(f"Successfully loaded {row_count} rows into '{table_name}'.")
        return row_count

    except Exception as e:
        print(f"Error loading CSV to DB: {e}")
        return 0


        
#table_name = "datasets_metadata"
#wipe_table(table_name)
