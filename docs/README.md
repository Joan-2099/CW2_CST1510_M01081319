# Multi-Domain Intelligence Platform
Student Name: Joan Martha Acom
Student ID: M01081319
Course: CST1510 – Programming and Communication with Python

## Built With
Python 3.10+ – Core programming language
Streamlit – Web interface framework
SQLite – Relational database for persistent storage
Pandas – Data manipulation and analysis
Plotly / Plotly Express – Interactive visualizations (bar, pie, line charts)
Altair – Lightweight charting for some ticket analytics
bcrypt – Secure password hashing

## File Structure
/CW2_CST1510_M01081319
|-/.streamlit/secrets.tonl
|
|-/Animations
|   |-json_anm.py             #function to load functions
│
├─ /DATABASE/app/data
│   ├─ db.py                 # Database connection and 
│   ├─ incidents.py            # CRUD for incidents 
│   ├─ datasets.py            # CRUD for datasets metadata 
│   ├─ tickets.py             # CRUD for tickets
│   ├─ api.py                # Analyze with Gemini for all domains
│   ├─ init_db.py            # Initializes database at helper functions
│   ├─ schema.py             # Table creation scripts
|
├─ /DATABASE/app/services
│   ├─ user_service.py             #user services
|
├─ /DATABASE/app/utils
│   ├─ csv_schema.py            #
|   ├─ csv_utils.py             #holds load to table helper func
|
|-docs
|   |-ReadMe
|
|-skeleton/..                #raw functions used later
|
├─ /web_app
│   ├─ /pages
│   │   ├─ cyber_incidents.py         # Main dashboard and cyber incidents page
│   │   ├─ datasets.py       # Dataset upload, preview, and visualization
│   │   ├─ it_tickets.py     # IT ticket management page
|   |   |-main.py           #Description of domains
|   |-Home.py               # Login and registration page
│
├─ /DATA
│   └─ intelligence_platform.db  # SQLite database file
│
├─ users.txt                  # (Week 7) File-based user storage for CLI version
├
## What’s Saved in Each File
db.py – Connects to SQLite, contains utility functions like connect_database(), wipe_table(), alter_table(). Functions are standalone for simplicity.
schema.py – SQL scripts to create tables: users, cyber_incidents, it_tickets, datasets_metadata.
init_db.py – Initializes database and creates tables if they don’t exist.
master.py – Streamlit dashboard; displays cyber incidents table, KPIs, and trend visualizations. Handles form submissions.
datasets.py – Upload, preview, and visualize CSV datasets. Supports bar and pie charts with Plotly.
it_tickets.py – View, assign, and update IT tickets. Generates charts for staff performance and ticket status.
intelligence_platform.db – Stores all user, incident, ticket, and dataset information.
users.txt – Initial CLI-based storage for user accounts (Week 7).
Usage
## Login/Register
Users register with a username and password (hashed with bcrypt).
Role-based access determines which pages and actions are available.
Cyber Incidents Dashboard
View all incidents in a table.
Add new incidents via a form.
Calculate KPIs: most frequent threat, most critical, longest unresolved, fastest-growing threat.
Visualizations: line charts for trends, bar charts for severity, donut charts for types.
Datasets Page
Upload CSV files via st.file_uploader.
Preview data in a table (st.dataframe).
Generate interactive bar or pie charts using selected columns.
## IT Tickets Page
Submit, assign, and update tickets.
Visualize staff workload and ticket status trends.
Roadmap
Add changelog and version history
Include “Back to Top” links for easy navigation in README
Add additional template pages with examples
Create a “Components” document to reuse Streamlit sections
Multi-language support: Chinese, Spanish
Notes
Streamlit automatically reruns the script on user interactions; session-state management prevents duplicate submissions and inconsistent UI.
SQLite locks and threading issues are handled with proper connection management.
Pandas and Plotly visualizations validate data to avoid runtime errors from empty or inconsistent datasets.