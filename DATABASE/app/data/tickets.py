import csv
from datetime import datetime
import os
from DATABASE.app.data.db import connect_database

# connencting to database
conn = connect_database("DATA/intelligence_platform.db")

def get_ticket_by_id(ticket_id):
    """Fetch an IT ticket by its ID."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets WHERE id = ?", (ticket_id,))
    ticket = cursor.fetchone()
    conn.close()
    return ticket


def insert_ticket(title, description, status="open", assigned_to="unassigned"):
    # Generate ticket ID
    ticket_id = int(datetime.now().timestamp())

    # Save to CSV
    csv_path = os.path.join("DATA", "it_tickets.csv")
    file_exists = os.path.isfile(csv_path)

    with open(csv_path, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["id", "title", "description", "status", "assigned_to"])
        writer.writerow([ticket_id, title, description, status, assigned_to])

    # Save to Database
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO it_tickets (title, description, status, assigned_to) VALUES (?, ?, ?, ?)",
        (title, description, status, assigned_to)
    )
    conn.commit()
    new_ticket_id = cursor.lastrowid  # get the ID SQLite assigned
    conn.close()

    return new_ticket_id



def get_all_tickets():
    """Fetch all IT tickets."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets")
    tickets = cursor.fetchall()
    conn.close()
    return tickets

def assign_ticket(ticket_id, staff_member):
    #save in csv
    file_path = os.path.join("DATA", "it_tickets.csv")

    rows = []
    with open(file_path, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if str(row["id"]) == str(ticket_id):
                row["assigned_to"] = staff_member
            rows.append(row)

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    
    #save in dbs
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE it_tickets
        SET assigned_to = ?
        WHERE id = ?
    """, (staff_member, ticket_id))
    conn.commit()
    conn.close()

def update_ticket_status(ticket_id, new_status):
    file_path = os.path.join("DATA", "it_tickets.csv")

    rows = []
    with open(file_path, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if str(row["ticket_id"]) == str(ticket_id):
                row["status"] = new_status
            rows.append(row)

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    # Update DATABASE
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE it_tickets SET status = ? WHERE id = ?",
        (new_status, ticket_id)
    )
    conn.commit()
    conn.close()