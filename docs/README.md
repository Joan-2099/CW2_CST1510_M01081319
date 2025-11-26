
Student Name: Joan Martha Acom
Student ID: M01081319
Course: CST1510 -Programming and Communication with Python

# Week 7: Secure Authentication System

## Project Description
A command-line authentication system implementing secure password hashing
This system allows users to register accounts and log in with proper pass.

## Features
- Secure password hashing using bcrypt with automatic salt generation
- User registration with duplicate username prevention
- User login with password verification
- Input validation for usernames and passwords
- File-based user data persistence

## Technical Implementation
- Hashing Algorithm: bcrypt with automatic salting
- Data Storage: Plain text file (`users.txt`) with comma-separated values
- Password Security: One-way hashing, no plaintext storage
- Validation: Username (Atleast 5 alphanumeric characters), Password (atleast 8 characters|)


# Week 8: SQLite Database Integration & Incident Management System

## Project description
This week extends the secure authentication system from Week 7 by migrating from file-based storage to a structured SQLite relational database. 

The project now supports persistent, query-friendly data storage, user authentication backed by hashed passwords, and the ability to log and manage cyber incidents through a menu-driven command-line interface.

# Features

## Database Initialization
- When the program starts, the init_database() function in db.py is called.
init_database():
- Checks if the DATA folder exists; if not, it creates it.
- Connects to the SQLite database file intelligence_platform.db.
- Calls create_all_tables(conn) from schema.py to create the necessary tables.
- Closes the database connection after tables are created.

## Tables Creation
    The database consists of four core tables, each designed to store specific data:

    users Table – Stores registered users:

    id (INTEGER PRIMARY KEY AUTOINCREMENT)- Unique identifier for each user.
    username (TEXT, UNIQUE)- Login name.
    password_hash (TEXT)- Hashed password using bcrypt.
    role (TEXT, default 'user')- User role (e.g., analyst, admin).
This ensures secure storage of users with hashed passwords and unique usernames.

    cyber_incidents Table – Stores all cyber incident reports:

    id (INTEGER PRIMARY KEY AUTOINCREMENT): Unique incident identifier.
    date (TEXT): Date of the incident.
    incident_type (TEXT): Type/category of the incident.
    severity (TEXT): Incident severity (High, Medium, Low).
    status (TEXT): Status of the incident (Open, Closed).
    description (TEXT): Details about the incident.
    reported_by (TEXT): Username of the reporter.
    created_at (TIMESTAMP, default CURRENT_TIMESTAMP): Automatic record creation timestamp.
This provides a structured way to log, track, and manage cyber incidents.

    datasets_metadata Table – Stores metadata about datasets:

    id (INTEGER PRIMARY KEY AUTOINCREMENT)
    name (TEXT)
    description (TEXT)
    source (TEXT)
    date_created (TEXT)
    last_updated (TEXT)
    record_count (INTEGER)
    file_size_mb (REAL)
    created_at (TIMESTAMP, default CURRENT_TIMESTAMP)
This tracks datasets relevant to the platform, including size, records, and update history.

    it_tickets Table – Stores IT support ticket data:

    id (INTEGER PRIMARY KEY AUTOINCREMENT)
    title (TEXT)
    description (TEXT)
    status (TEXT, default 'open')
    assigned_to (TEXT)
    date_created (TEXT)
    resolved_date (TEXT)
    created_at (TIMESTAMP, default CURRENT_TIMESTAMP)
This organizes IT support tasks and their progress/status.

## User Data Flow
During registration:
- Input is validated (username length, password complexity, matching passwords) as mentioned in week 7
- User data is inserted into the users table.
- Duplicate usernames are prevented by SQLite’s UNIQUE constraint.

During login:
- Username is checked for existence within database
- Stored hashed password is retrieved.
- Input password is verified (refer to week 7)
- Successful login grants access for users to interact with incidents.

## Cyber Incidents Data Flow
- Users can add incidents via the CLI.
- Data is inserted into the cyber_incidents table.
- Each incident is automatically timestamped.
- Incidents can later be queried or updated as part of CRUD operations.

## Interactive CLI
Menu-based interface with three options:
Register a new user
Login
Exit
Prompts guide the user through registration, login, and error handling.

# Week 9 – Web Interface, MVC & Visualisation

## Project Description
This week, I took the cyber incident system I built before and moved it into a simple web dashboard using Streamlit.

Instead of using the terminal, I now have a small web page where I can view all cyber incidents stored in my SQLite database and add new ones using a form. It’s still simple, but it feels more like a real application now.

## What the Web Dashboard Can Do
- Shows all recorded cyber incidents in a table
- Lets the user fill out a form with:
- Name of the person reporting
- Incident title
- Severity (Low, Medium, High, Critical)
- Status (Open, In Progress, Resolved)
- Description
- Saves the new incident into the database when the form is submitted
- Updates automatically so the new incident appears right away

## How the System Works
This project uses the MVC idea (Model–View–Controller), even in a basic way:

### Model (M) – Data and Database

- I used an SQLite database called intelligence_platform.db
- It stores all cyber incidents in a table called cyber_incidents
- Each incident has:
    id
    date
    incident type (title)
    severity
    status
    description
    reported_by
    timestamp when it was created

- My Python files inside /DATABASE/app/data/ handle everything related to the database (reading, writing, connecting, etc.)

## View (V) – The Web Page
This is the Streamlit page (master.py)
It displays:
    - A title
    - A table with all the incidents
    - A form to add a new incident
Streamlit automatically refreshes the page when new data is saved

## Controller (C) – The Logic
When the user presses “Add Incident,” the program:
- Collects the data from the form
- Gets the current date
- Sends everything to insert_incident()
- Shows a success message



# Datasets Page - Multi-Domain 

## Intelligence Platform
### Overview
The Datasets page provides a data ingestion and visualization interface for CSV files in the Multi-Domain Intelligence Platform. It leverages Streamlit for the web interface, pandas for data handling, and Plotly for dynamic charting.
The page enables:
Uploading CSV datasets
Previewing data in tabular format
Generating interactive charts (Bar and Pie)
This module is designed for rapid data exploration and can integrate into a larger MVC Streamlit architecture.
### Technical Architecture
Frontend: Streamlit widgets for file upload, table preview, and chart selection.
Backend:
pandas: Handles CSV parsing, column type inference, and DataFrame operations.
Plotly Express / Graph Objects: Provides dynamic, interactive visualizations.
Workflow:
User uploads a CSV file via st.file_uploader.
CSV is read into a pandas DataFrame (pd.read_csv).
Basic statistics (row count, column count, preview) are displayed.
User selects a chart type (Bar or Pie) and X/Y axes from available columns.
Chart is dynamically rendered using Plotly and displayed in the Streamlit page.
### File Upload & Parsing
uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])
if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
Validation: Only .csv files are accepted.
Error handling: Exceptions are captured and displayed using st.error.
DataFrame: Column types are automatically inferred by pandas.
### Data Exploration
st.dataframe(df): Displays a scrollable, interactive table.
df.head(): Shows top N rows for preview.
Column metadata:
num_columns = len(df.columns)
all_columns = df.columns.tolist()
numeric_cols = df.select_dtypes(include='number').columns.tolist()
### Charting
Dynamic charting with Plotly:
Bar Chart: Visualizes numeric Y-axis values against categorical X-axis.
Pie Chart: Aggregates numeric Y-axis values for slices based on categorical X-axis.
Chart selection workflow:
chart_type = st.radio("Choose a chart type:", ["Bar Chart","Pie Chart"])
x_axis = st.selectbox("Select X-axis (category):", all_columns)
y_axis = st.selectbox("Select Y_axis (category):", numeric_cols)
Charts update reactively when X/Y axes or chart type are changed.
Uses px.bar() and px.pie() for visualization.