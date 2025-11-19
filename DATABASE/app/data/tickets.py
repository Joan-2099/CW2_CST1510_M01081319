from app.data.db import connect_database


def get_ticket_by_id(ticket_id):
    """Fetch an IT ticket by its ID."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets WHERE id = ?", (ticket_id,))
    ticket = cursor.fetchone()
    conn.close()
    return ticket


def insert_ticket(title, description=None, status='open', assigned_to=None, date_created=None, resolved_date=None):
    """Insert a new IT ticket into it_tickets table."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO it_tickets 
        (title, description, status, assigned_to, date_created, resolved_date) 
        VALUES (?, ?, ?, ?, ?, ?)
    """, (title, description, status, assigned_to, date_created, resolved_date))
    ticket_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return ticket_id


def get_all_tickets():
    """Fetch all IT tickets."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM it_tickets")
    tickets = cursor.fetchall()
    conn.close()
    return tickets
