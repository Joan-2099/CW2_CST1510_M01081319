import pandas as pd
import csv
from pathlib import Path
import datetime

# This points to the root of my project folder
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")

#A class to manage all cyber incidents in our database and CSV backup.
class Incidents:
    #Each method requires a database connection (conn) to stay thread-safe.

    #Initialize the class with a CSV file path for backups.
    
    def __init__(self, CSV_FILE = project_root / "DATA" / "cyber_incidents.csv"):
        # Conn not stored here to avoid threading issues.
        self.csv_path = CSV_FILE

    #Save incident data to a CSV file as a backup.
    def _write_to_csv(self, row_data):
    
        #Adds a header if the CSV is empty or doesn't exist.
        write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
        with open(self.csv_path, "a", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow([
                    "incident_id", "date", "incident_type",
                    "severity", "status", "description", "reported_by"
                ])
            writer.writerow(row_data)

    #Insert a new incident into the database.
    def insert_incident(self, conn, date, incident_type, severity, status, description, reported_by):

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO cyber_incidents 
            (date, incident_type, severity, status, description, reported_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (date, incident_type, severity, status, description, reported_by))
        conn.commit()
        incident_id = cursor.lastrowid  # get the auto-generated ID

        # Save backup to CSV
        self._write_to_csv([
            incident_id, date, incident_type, severity, status, description, reported_by
        ])

        #Returns the database ID of the new incident.
        return incident_id
    
    #Fetch all incidents from the database and return them as a pandas DataFrame.
    def get_all_incidents(self, conn):
    
        #Return in order of most recent
        return pd.read_sql_query("SELECT * FROM cyber_incidents ORDER BY id DESC", conn)

    #Delete an incident by its ID.
    def delete_incident(self, conn, incident_id):
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cyber_incidents WHERE id = ?", (incident_id,))
        conn.commit()
        #Returns the number of rows deleted (should be 1 if successful).
        return cursor.rowcount

    #Update fields of an existing incident.
    def update_incident(self, conn, incident_id, date=None, incident_type=None,
                        severity=None, status=None, description=None, reported_by=None):
       
        #Only fields provided (not None) will be updated.
        
        cursor = conn.cursor()

        # Map field names to new values
        field_map = {
            "date": date,
            "incident_type": incident_type,
            "severity": severity,
            "status": status,
            "description": description,
            "reported_by": reported_by,
        }

        #If status is "Resolved", sets resolved_at to today's date automatically.
        if status == "Resolved":
            field_map["resolved_at"] = datetime.date.today().isoformat()

        fields = []
        values = []

        # Only include fields that have new values
        for field, value in field_map.items():
            if value is not None:
                fields.append(f"{field} = ?")
                values.append(value)

        if fields:
            # Build SQL UPDATE query dynamically
            sql = f"UPDATE cyber_incidents SET {', '.join(fields)} WHERE id = ?"
            values.append(incident_id)  # add the ID to the query
            cursor.execute(sql, values)
            conn.commit()

            # Optional: update CSV backup as well
            self._write_to_csv([
                incident_id, date, incident_type, severity, status, description, reported_by
            ])
            return incident_id

        # Return None if nothing was updated
        return None
