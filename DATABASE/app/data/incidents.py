import pandas as pd
from .db import connect_database


def insert_incident(date, incident_type, severity, status, description, reported_by):
    """Insert new incident."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO cyber_incidents 
        (date, incident_type, severity, status, description, reported_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (date, incident_type, severity, status, description, reported_by))
    conn.commit()
    incident_id = cursor.lastrowid
    conn.close()
    return incident_id


def get_all_incidents():
    """Get all incidents as DataFrame."""
    conn = connect_database()
    df = pd.read_sql_query(
        "SELECT * FROM cyber_incidents ORDER BY id DESC",
        conn
    )
    conn.close()
    return df


def delete_incident(incident_id):
    """Delete an incident by its ID."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM cyber_incidents WHERE id = ?
    """, (incident_id,))
    conn.commit()
    conn.close()
    return cursor.rowcount  # returns number of rows deleted


def update_incident(incident_id, date=None, incident_type=None, severity=None, status=None, description=None, reported_by=None):
    """Update an incident by its ID. Only provided fields will be updated."""
    conn = connect_database()
    cursor = conn.cursor()

    # Build dynamic SQL based on which fields are provided
    fields = []
    values = []

    if date is not None:
        fields.append("date = ?")
        values.append(date)
    if incident_type is not None:
        fields.append("incident_type = ?")
        values.append(incident_type)
    if severity is not None:
        fields.append("severity = ?")
        values.append(severity)
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if description is not None:
        fields.append("description = ?")
        values.append(description)
    if reported_by is not None:
        fields.append("reported_by = ?")
        values.append(reported_by)

    # Only proceed if there’s something to update
    if fields:
        sql = f"UPDATE cyber_incidents SET {', '.join(fields)} WHERE id = ?"
        values.append(incident_id)
        cursor.execute(sql, values)
        conn.commit()

    conn.close()
    return cursor.rowcount  # returns number of rows updated
