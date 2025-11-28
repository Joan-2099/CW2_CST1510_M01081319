def load_csv_to_table(conn, csv_path, table_name):
    # Check if CSV file exists
    if not os.path.isfile(csv_path):
        print(f"Error: CSV file '{csv_path}' does not exist.")
        return 0

    try:
        # Read CSV using pandas
        df = pd.read_csv(csv_path)
        if df.empty:
            print(f"Warning: CSV file '{csv_path}' is empty.")
            return 0

        # Keep only relevant columns for cyber_incidents table
        expected_columns = ["date", "incident_type", "severity", "status", "description", "reported_by"]
        df = df[expected_columns]

        # Read existing records from DB
        df_existing = pd.read_sql(f"SELECT {', '.join(expected_columns)} FROM {table_name}", conn)

        # Remove duplicates to avoid inserting the same incident twice
        df_to_insert = pd.concat([df, df_existing, df_existing]).drop_duplicates(keep=False)

        if df_to_insert.empty:
            print("No new incidents to add — all already exist in the DB.")
            return 0

        # Insert new records
        df_to_insert.to_sql(name=table_name, con=conn, if_exists='append', index=False)
        row_count = len(df_to_insert)
        print(f"Successfully loaded {row_count} rows into '{table_name}'.")
        return row_count

    except Exception as e:
        print(f"Error loading CSV to table: {e}")
        return 0
