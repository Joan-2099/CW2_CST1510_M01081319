import csv
import os
import pandas as pd
from datetime import datetime
from DATABASE.app.data.db import connect_database

CSV_PATH = os.path.join("DATA", "it_tickets.csv")

class Tickets:
    def __init__(self, csv_path=CSV_PATH):
        self.csv_path = csv_path
        self.conn = connect_database()  # optional: you can keep a persistent connection if desired

    # Insert a new ticket into the database and sync it to the CSV file
    def save_to_csv(self, tickets, headers=None):
        """Save a list of tickets to CSV."""
        if not tickets:
            return

        if headers is None:
            if isinstance(tickets[0], dict):
                headers = tickets[0].keys()
            else:  # tuple from DB
                headers = ["id", "title", "description", "status", "assigned_to",
                         "resolved_date", "created_at"]

        with open(self.csv_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            for ticket in tickets:
                if isinstance(ticket, dict):
                    writer.writerow([ticket[h] for h in headers])
                else:  # tuple from DB
                    writer.writerow(ticket)


    def sync_csv_from_db(self):
        """Fetch all tickets from DB and save to CSV."""
        tickets = self.get_all_tickets()
        if tickets:
            if isinstance(tickets[0], tuple):
                headers = ["id", "title", "description", "status", "assigned_to",
                            "resolved_date", "created_at"]
            else:
                headers = tickets[0].keys()
        else:
            headers = None
        self.save_to_csv(tickets, headers)

    #CRUD Operations
    def insert_ticket(self, title, description, status="open", assigned_to="unassigned"):
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO it_tickets (title, description, status, assigned_to, created_at) VALUES (?, ?, ?, ?, ?)",
            (title, description, status, assigned_to, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        ticket_id = cursor.lastrowid
        conn.close()

        self.sync_csv_from_db()
        return ticket_id


    def get_ticket_by_id(self, ticket_id):
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM it_tickets WHERE id=?", (ticket_id,))
        ticket = cursor.fetchone()
        conn.close()
        return ticket

    #Fetch all tickets from the database
    def get_all_tickets(self, as_df=False):
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM it_tickets")
        tickets = cursor.fetchall()
        headers = [desc[0] for desc in cursor.description]
        conn.close()

        if as_df:
            return pd.DataFrame(tickets, columns=headers)
        return tickets

    #Fetch tickets that are not yet assigned to any staff member
    def get_unassigned_tickets(self):
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM it_tickets WHERE assigned_to='unassigned'")
        tickets = cursor.fetchall()
        conn.close()
        return tickets

    #Fetch all tickets assigned to a specific staff member
    def get_staff_tickets(self, staff_member):
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM it_tickets WHERE assigned_to=?", (staff_member,))
        tickets = cursor.fetchall()
        conn.close()
        return tickets

    #Assign a ticket to a staff member
    def assign_ticket(self, ticket_id, staff_member):
        conn = connect_database()
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE it_tickets SET assigned_to=? WHERE id=?", (staff_member, ticket_id))
            conn.commit()
        finally:
            conn.close()
            self.sync_csv_from_db()

    #Update the status of a ticket
    def update_ticket_status(self, ticket_id, new_status):
        conn = connect_database()
        cursor = conn.cursor()
        try:
            if new_status== "Resolved":
                cursor.execute("UPDATE it_tickets SET status=?, resolved_date = CURRENT_TIMESTAMP Where id=?",(new_status, ticket_id))
        
            else:
                 cursor.execute("UPDATE it_tickets SET status=? WHERE id=?", (new_status, ticket_id))
        finally:
            conn.commit()
            conn.close()
            self.sync_csv_from_db()


    #Delete a ticket from the database by its ID.
    def delete_ticket(self, ticket_id):
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM it_tickets WHERE id=?", (ticket_id,))
        conn.commit()
        conn.close()
        #update csv after deletion
        self.sync_csv_from_db()
