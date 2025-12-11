import streamlit as st
from google import genai

api_key = st.secrets["GEMINAI_API_KEY"]
client = genai.Client(api_key=api_key)


st.title("Test Secrets Setup")
# Try to access the secret
try:
    api_key = st.secrets["GEMINAI_API_KEY"]
    st.success(" API key loaded successfully!")
    st.write(f"Key starts with: {api_key[:10]}...")
except Exception as e:
    st.error(f"Error loading API key: {e}")
    st.info("Make sure .streamlit/secrets.toml exists and contains GEMINAI_API_KEY")