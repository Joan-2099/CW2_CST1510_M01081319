# Multi-Domain Intelligence Platform
Student Name: Joan Martha Acom
Student ID: M01081319
Course: CST1510 – Programming and Communication with Python

## Project Structure
### Root Directory
#### /CW2_CST1510_M01081319
Main project root containing the Streamlit web application, database logic, utilities, documentation, and assets.
#### Streamlit Configuration
/.streamlit/secrets.toml
Stores sensitive configuration values such as API keys and credentials used by the application. This file is excluded from version control for security reasons.
#### Animations
/Animations
Contains animation-related helper files used to enhance the user interface.
json_anm.py
Utility function for loading and handling Lottie JSON animations in the Streamlit app.
#### Database Core Logic
/DATABASE/app/data
Houses all database interaction logic and domain-specific CRUD functionality.
db.py
Manages SQLite database connections and helper functions.
incidents.py
Implements CRUD operations for cybersecurity incidents.
datasets.py
Handles CRUD functionality for dataset metadata storage and retrieval.
tickets.py
Manages CRUD operations for IT support tickets.
api.py
Provides AI-powered analysis using the Gemini API across all domains.
init_db.py
Initializes the database and runs setup helper functions.
schema.py
Defines database table schemas and creation scripts.
#### Services Layer
/DATABASE/app/services
Contains service-level logic that coordinates application behavior.
user_service.py
Handles user registration, login, authentication, role-based access control, and session validation.
#### Utility Functions
/DATABASE/app/utils
Contains stateless helper functions used across the application.
csv_schema.py
Defines schemas or structure used when working with CSV data.
csv_utils.py
Provides helper functions for loading CSV files into database tables.
#### Documentation
/docs
Project documentation and supporting materials.
ReadMe
Contains project description, usage instructions, and structural overview.
#### Skeleton Code
/skeleton
Contains early or raw function implementations that were later refactored and integrated into the main application.
#### Streamlit Web Application
/web_app
Main Streamlit-based web interface.
/pages
Contains individual application pages:
cyber_incidents.py
Cybersecurity incidents dashboard and management page.
datasets.py
Dataset upload, preview, metadata management, and visualization page.
it_tickets.py
IT ticket submission, tracking, and staff management page.
main.py
Describes platform domains and serves as a domain overview page.
Home.py
Login and registration page, serving as the application entry point.
#### Data Storage
/DATA
Contains application data files.
intelligence_platform.db
SQLite database storing users, incidents, tickets, and dataset metadata.

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
 ## Important instructions
### Run database-related utility scripts from the project root
When executing functions such as load_csv_to_table(), ensure they are run from the project root directory using module execution (e.g. python -m DATABASE.app.utils.csv_utils). Running these scripts directly may cause import or path resolution errors due to relative imports and project structure.

### Staff-only actions are role-protected
Features such as updating incident statuses, assigning IT tickets, or managing unresolved records require a user role of "staff". Ensure the correct role is assigned during registration for testing these features.
## CSV uploads to the incidents page must follow expected structure
Uploaded CSV files are assumed to have a consistent schema. Files with missing headers, unexpected column names, or incompatible data types may fail silently or be rejected during ingestion.