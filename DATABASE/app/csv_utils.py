import os
import pandas as pd
import sqlite3
from DATABASE.app.data.db import connect_database

def load_csv_to_table(conn, csv_path, table_name):
    if not os.path.isfile(csv_path):
        print(f"Error: CSV file '{csv_path}' does not exist.")
        return 0

    try:
        df = pd.read_csv(csv_path)
        if df.empty:
            print(f"Warning: CSV file '{csv_path}' is empty.")
            return 0

        expected_columns = ["date", "incident_type", "severity", "status", "description", "reported_by"]
        df = df[expected_columns]

        # Read existing records
        df_existing = pd.read_sql(f"SELECT {', '.join(expected_columns)} FROM {table_name}", conn)

        # Keep only new rows
        df_to_insert = pd.merge(df, df_existing, on=expected_columns, how='outer', indicator=True)
        df_to_insert = df_to_insert[df_to_insert['_merge'] == 'left_only'].drop(columns='_merge')

        if df_to_insert.empty:
            print("No new incidents to add — all already exist in the DB.")
            return 0

        df_to_insert.to_sql(name=table_name, con=conn, if_exists='append', index=False)
        row_count = len(df_to_insert)
        print(f"Successfully loaded {row_count} rows into '{table_name}'.")
        return row_count

    except Exception as e:
        print(f"Error loading CSV to table: {e}")
        return 0

#have to run file from project root python -m DATABASE.app.data.csv_utils
# Connect to the database
conn = connect_database("DATA/intelligence_platform.db")

# Path to CSV file
csv_path = "DATA/cyber_test.csv"

# Name of the table in database
table_name = "cyber_incidents"

# Call the function
rows_added = load_csv_to_table(conn, csv_path, table_name)
print(f"Rows added: {rows_added}")