import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="Data Science",layout="wide")

uploaded_file = st.file_uploader(
    "Upload CSV file",
    type=["csv"],  # to onlty allow CSV files
    help="Select a CSV file to preview and check."
)


if uploaded_file is not None:
    try:
        # Read CSV into pandas DataFrame
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        # Show error if the CSV cannot be read
        st.error(f"Error reading CSV file: {e}")
    else:
        # Show a success message and preview the data
        st.success("CSV successfully uploaded!")
        st.dataframe(df, width=1200, height=600)

        #display basic info about the CSV and list
        st.subheader("CSV Summary")
        st.write("Number of rows:", len(df))
        num_columns = len(df.columns)
        st.write(f"Number of columns: {num_columns}")
        st.write(df.head())
        
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

else:
    st.info("Please upload a CSV file to preview it.")
