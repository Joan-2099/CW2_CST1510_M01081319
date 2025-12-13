import pandas as pd

#Load CSV data into a database table while avoiding duplicate records.
def load_to_table(conn, csv_source, table_name, table_schemas):
    try:
        # Ensure the table has a defined schema before proceeding
        if table_name not in table_schemas:
            return False, 0, f"No schema defined for table '{table_name}'."

        expected_columns = table_schemas[table_name]

        # Read CSV into DataFrame
        df = pd.read_csv(csv_source)

        if df.empty:
            return False, 0, "Uploaded CSV file is empty."

        # Check for missing required columns
        missing_cols = set(expected_columns) - set(df.columns)
        if missing_cols:
            return False, 0, f"Missing required columns: {', '.join(missing_cols)}"

        # Keep only expected columns
        df = df[expected_columns]

        # Read existing records from DB
        df_existing = pd.read_sql(f"SELECT {', '.join(expected_columns)} FROM {table_name}", conn)

        # Normalize string columns (strip spaces)
        for col in expected_columns:
            if df[col].dtype == object:
                df[col] = df[col].astype(str).str.strip()
                df_existing[col] = df_existing[col].astype(str).str.strip()

        # Normalize datetime columns to string
        for ts_col in ['created_at', 'resolved_at']:
            if ts_col in expected_columns:
                df[ts_col] = df[ts_col].astype(str)
                df_existing[ts_col] = df_existing[ts_col].astype(str)

        # Identify new rows that don't exist in DB
        df_to_insert = pd.merge(
            df,
            df_existing,
            on=expected_columns,
            how="outer",
            indicator=True
        )
        df_to_insert = df_to_insert[df_to_insert["_merge"] == "left_only"]
        df_to_insert.drop(columns="_merge", inplace=True)

        if df_to_insert.empty:
            return True, 0, "No new records to insert."

        # Append new rows
        df_to_insert.to_sql(name=table_name, con=conn, if_exists="append", index=False)

        return True, len(df_to_insert), "CSV data imported successfully."

    except Exception as e:
        return False, 0, f"CSV import failed: {e}"
