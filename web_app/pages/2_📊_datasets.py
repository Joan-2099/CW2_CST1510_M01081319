import streamlit as st
import pandas as pd
import sys
from pathlib import Path
import plotly.express as px

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.services.user_service import UserService
from DATABASE.app.data.api import API_analyzer
from DATABASE.app.data.datasets import Datasets
from datetime import datetime

api_analyze= API_analyzer()
datasets_func = Datasets()
st.set_page_config(page_title="Data Science",layout="wide")

st.title("Data Science")
if "username" not in st.session_state:
    st.session_state["username"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None
  
#ensure user is looged in
UserService.require_login(role="user")

df = None
default_dataset_files = {
    "Tiktok user growth (2020)": "DATA/tiktok.csv",
    "University attendance (2010)": "DATA/uni.csv",
    "Cyber Incidents": "DATA/cyber_incidents.csv"
}

uploaded_file = st.file_uploader(
    "Upload CSV file",
    type=["csv"],  # to onlty allow CSV files
    help="Select a CSV file to preview and check."
)


default_choice=st.selectbox("Choose existing datasets",["--None--"] + list(default_dataset_files.keys()))


if uploaded_file is not None:
    try:
        # Read CSV into pandas DataFrame
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        # Show error if the CSV cannot be read
        st.error(f"Error reading CSV file: {e}")
elif default_choice != "--None--":
    try:
        df = pd.read_csv(default_dataset_files[default_choice])
        st.success(f"Loaded default dataset: {default_choice}")
    except Exception as e:
        st.error(f"Error loading default dataset: {e}")


#user input
if df is not None:
    st.dataframe(df)

    with st.expander("Save dataset to Metadata Catalog"):
        name=st.text_input("Enter name")
        source=st.selectbox("Choose a department",["Cybersecurity","IT","Human Resource"])
        description=st.text_area("Description")
        record_count = len(df)

        if uploaded_file is not None:
            file_size_mb = uploaded_file.size / (1024 * 1024)
        elif default_choice != "--None--":
            file_size_mb = Path(default_dataset_files[default_choice]).stat().st_size / (1024 * 1024)

        date_created=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_updated=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        submit=st.button("Submit Dataset")

        st.write(f"📊 Rows detected: **{record_count}**")
        st.write(f"💾 File size: **{file_size_mb:.2f} MB**")

        if submit:
            datasets_func.insert_dataset(name, description, source, date_created, last_updated, record_count, file_size_mb)
            st.success("Metadata saved")

        #to ensure not to overwrite df
        metadata_df = datasets_func.get_all_datasets()
        st.dataframe(metadata_df)

    #display basic info about the CSV and list
    st.subheader("CSV Summary")
    st.write("Number of rows:", len(df))
    num_columns = len(df.columns)
    st.write(f"Number of columns: {num_columns}")

    
    #ensure chart code is withing the if bock to display if file is uploaded 
    #Display charts
    st.subheader("⚙️ Charts")
    chart_type=st.radio("Choose a chart type:",["Bar Chart","Pie Chart"])

        #colum selections
    all_columns=df.columns.tolist()
    numeric_cols=df.select_dtypes(include='number').columns.tolist()

        #allow choice of data for comparison in charts
    x_axis=st.selectbox("Select X-axis (category):", all_columns)
    y_axis=st.selectbox("Select Y_axis (category):",numeric_cols)

        #display of charts
    if chart_type == "Bar Chart":
        st.subheader("Bar Chart")
        fig = px.bar(df, x=x_axis, y=y_axis,color=x_axis)
        st.plotly_chart(fig, use_container_width=True)
    elif chart_type == "Pie Chart":
        st.subheader("Pie Chart")
        fig = px.pie(df, names=x_axis, values=y_axis,title=f"{y_axis} by {x_axis}")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Ensure to upload a csv file")

    #AI Summary
    st.subheader("🤖 AI Summary of Dataset")

    num_rows = st.slider(
        "How many rows to sample for AI summary?", 
        #ensure user can't sample less than 5 rows and cant go beyond existing num of rows
        min_value=5,
        max_value=len(df),
        value=min(20, len(df))
    )
    sample_csv = df.head(num_rows).to_csv(index=False)

    if st.button("Generate AI Summary"):
        ai_text=api_analyze.analyze_datasets(df,sample_csv)
        st.info(ai_text)
        
else:
    st.info("Please upload a CSV file to preview it.")