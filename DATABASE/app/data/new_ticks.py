import csv
import os
import pandas as pd
from datetime import datetime
from DATABASE.app.data.db import connect_database

CSV_PATH = os.path.join("DATA", "it_tickets.csv")


def save_tickets_to_csv(tickets, headers=None):
    """Save a list of tickets to CSV."""
    if not tickets:
        return

    if headers is None:
        headers = tickets[0].keys() if isinstance(tickets[0], dict) else [
            "id", "title", "description", "status", "assigned_to", "date_created", "resolved_date", "created_at"
        ]

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        for ticket in tickets:
            if isinstance(ticket, dict):
                writer.writerow([ticket[h] for h in headers])
            else:  # tuple from DB
                writer.writerow(ticket)


def sync_csv_from_db():
    """Fetch all tickets from DB and save to CSV."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets")
    tickets = cursor.fetchall()
    headers = [desc[0] for desc in cursor.description]
    conn.close()

    save_tickets_to_csv(tickets, headers)


# -----------------------
# CRUD Functions
# -----------------------
def insert_ticket(title, description, status="open", assigned_to="unassigned"):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO it_tickets (title, description, status, assigned_to, date_created) VALUES (?, ?, ?, ?, ?)",
        (title, description, status, assigned_to, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    ticket_id = cursor.lastrowid
    conn.close()

    sync_csv_from_db()
    return ticket_id


def get_ticket_by_id(ticket_id):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets WHERE id=?", (ticket_id,))
    ticket = cursor.fetchone()
    conn.close()
    return ticket


def get_all_tickets(as_df=False):
    """Fetch all tickets. Return as DataFrame if as_df=True."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets")
    tickets = cursor.fetchall()
    headers = [desc[0] for desc in cursor.description]
    conn.close()

    if as_df:
        return pd.DataFrame(tickets, columns=headers)
    return tickets

def get_unassigned_tickets():
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets WHERE assigned_to='unassigned'")
    tickets = cursor.fetchall()
    conn.close()
    return tickets


def get_staff_tickets(staff_member):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets WHERE assigned_to=?", (staff_member,))
    tickets = cursor.fetchall()
    conn.close()
    return tickets


def assign_ticket(ticket_id, staff_member):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("UPDATE it_tickets SET assigned_to=? WHERE id=?", (staff_member, ticket_id))
    conn.commit()
    conn.close()

    sync_csv_from_db()


def update_ticket_status(ticket_id, new_status):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("UPDATE it_tickets SET status=? WHERE id=?", (new_status, ticket_id))
    conn.commit()
    conn.close()

    sync_csv_from_db()


def delete_ticket(ticket_id):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM it_tickets WHERE id=?", (ticket_id,))
    conn.commit()
    conn.close()

    sync_csv_from_db()
