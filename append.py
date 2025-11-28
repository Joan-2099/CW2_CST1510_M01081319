import os
import pandas as pd
from DATABASE.app.data.db import connect_database
from DATABASE.app.data.csv_utils import load_csv_to_table
# --- DB connection ---
conn = connect_database("DATA/intelligence_platform.db")
table_name = "cyber_incidents"

# --- CSV path ---
csv_path = "DATA/cyber_test.csv"

conn = connect_database("DATA/intelligence_platform.db")
csv_path = "DATA/cyber_test.csv"
table_name = "cyber_incidents"
load_csv_to_table(conn, csv_path, table_name)