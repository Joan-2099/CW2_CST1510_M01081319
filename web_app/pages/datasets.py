import streamlit as st
import pandas as pd
import sys
from pathlib import Path
import plotly.express as px
from streamlit_lottie import st_lottie

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.services.user_service import UserService
from DATABASE.app.data.api import API_analyzer
from DATABASE.app.data.datasets import Datasets
from datetime import datetime
from Animations.json_anm import load_lottiefile

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


# Load dataset
if uploaded_file is not None:
    try: df = pd.read_csv(uploaded_file)
    except Exception as e: st.error(f"Error reading CSV file: {e}")
elif default_choice != "--None--":
    try: df = pd.read_csv(default_dataset_files[default_choice]); st.success(f"Loaded default dataset: {default_choice}")
    except Exception as e: st.error(f"Error loading default dataset: {e}")


#user input
if df is not None:
    st.dataframe(df)

    with st.expander("Save dataset to Metadata Catalog"):
        name=st.text_input("Enter name")
        source=st.selectbox("Choose a department",["Cybersecurity","IT","Human Resource"])
        description=st.text_area("Description")
        record_count = len(df)

        if uploaded_file is not None:
            file_size_mb = uploaded_file.size / (1024*1024)
        elif default_choice != "--None--":
            file_size_mb = Path(default_dataset_files[default_choice]).stat().st_size / (1024*1024)

        record_count = len(df)
        st.subheader("Dataset Resource Info")
        st.write(f"📊 Rows detected: **{record_count}** | 💾 File size: **{file_size_mb:.5f} MB**")
        st.write(f"🗂 Columns: **{len(df.columns)}** | Missing values: **{df.isna().sum().sum()}** | Duplicates: **{df.duplicated().sum()}**")


        date_created=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_updated=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        submit=st.button("Submit Dataset")

        
        if submit:
            datasets_func.insert_dataset(name, description, source, date_created, last_updated, record_count, file_size_mb)
            st.success("Metadata saved")

    #to ensure not to overwrite df
    st.subheader("Metadata table")
    metadata_df = datasets_func.get_all_datasets()
        #st.dataframe(metadata_df)

        #metadata_df = datasets_func.get_all_datasets()

    # Convert to DataFrame safely
    if isinstance(metadata_df, list):
        metadata_df = pd.DataFrame(metadata_df)  # let pandas assign numeric columns

        # Optionally rename columns if you know their meaning
    if metadata_df.shape[1] >= 9:  # make sure it has enough columns
        metadata_df.columns = [
            "id", "name", "description", "source", "date_created", 
            "last_updated", "record_count", "file_size_mb", "extra_column"
        ]
    st.dataframe(metadata_df)

    # horizontal bar chart safely
    required_cols = ['source', 'record_count', 'file_size_mb']
    if all(col in metadata_df.columns for col in required_cols):
        metadata_summary = metadata_df.groupby('source').agg({
            'record_count':'sum',
            'file_size_mb':'sum'
        }).reset_index()

        fig = px.bar(
            metadata_summary,
            y='source', 
            x=['record_count','file_size_mb'], 
            orientation='h', 
            barmode='group', 
            title='Dataset Summary by Source',
            labels={'value':'Count / Size', 'source':'Department'}
        )
        st.plotly_chart(fig, use_container_width=True, key="Horizontal chart for Departments")
    else:
        st.warning(f"Missing expected columns in metadata: {set(required_cols)-set(metadata_df.columns)}")


    #ensure chart code is withing the if bock to display if file is uploaded 
    #Display charts
    st.subheader("⚙️ Charts")

    chart_type=st.radio("Choose a chart type:",["Bar Chart","Pie Chart","Donut Chart", "Line Chart"])

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
        st.plotly_chart(fig, use_container_width=True, key="Bar Chart for data")
    elif chart_type == "Pie Chart":
        st.subheader("Pie Chart")
        fig = px.pie(df, names=x_axis, values=y_axis,title=f"{y_axis} by {x_axis}")
        st.plotly_chart(fig, use_container_width=True, key="Pie Chart for data")
    elif chart_type == "Donut Chart":
        st.subheader("Donut Chart")
        fig = px.pie(df, names=x_axis, values=y_axis, title=f"{y_axis} by {x_axis}", hole=0.4)
        st.plotly_chart(fig, use_container_width=True, key="Donut Chart for data")
    elif chart_type == "Line Chart":
        st.subheader("Line Chart")
        fig = px.line(df, x=x_axis, y=y_axis, color=x_axis, markers=True)
        st.plotly_chart(fig, use_container_width=True, key="Line Chart for data")
    else:
        st.info("Ensure to upload a csv file")

    col1, col2 = st.columns(2)

    
    with col1:
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
        AI_summary= st.button("Generate AI Summary")

        
    with col2:
        tools =load_lottiefile("Animations/Tools.json")
        st_lottie(tools,
            speed =1,
            height=250,
            key=None
        )
        
    if AI_summary:
        ai_text=api_analyze.analyze_datasets(df,sample_csv)
        st.info(ai_text)
else:
    st.info("Please upload a CSV file to preview it.")

if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.rerun()