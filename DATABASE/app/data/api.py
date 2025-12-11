import streamlit as st
from google import genai

api_key = st.secrets["GEMINAI_API_KEY"]
client = genai.Client(api_key=api_key)


class API_analyzer:
    def __init__(self,api_key=None,model="gemini-2.5-flash"):
       #Initialize the API client and model.
        if api_key is None:
            api_key = st.secrets["GEMINAI_API_KEY"]
        self.client = genai.Client(api_key=api_key)
        self.model = model 

    def analyze_incident(self, description, severity):
        system_prompt = f"""You are a cybersecurity expert.
                    Analyze this cyber incident and give insights.
             
                   """
        with st.spinner("Generating AI in" \
        "cident analysis..."):
            # Make sure you replace the model with a valid one
            response = self.client.models.generate_content(
                model=self.model,
                contents=f"Severity: {severity}\nDescription: {description}\n System prompt:{system_prompt}"
            )
        return response.text

    def analyze_datasets(self,df,sample_csv):
        # Convert the dtypes to a dictionary
        column_types = df.dtypes.apply(lambda x: str(x)).to_dict()
    
        system_prompt = f"""
            You are a data science expert.
            Analyze this CSV dataset sample and provide a plain-English summary.
            Include patterns, trends, anomalies, and any interesting insights.
            Columns: {column_types}
            """
 
        with st.spinner("Generating AI summary..."):
            response = self.client.models.generate_content(
                model=self.model,
                contents=f"{system_prompt}\n{sample_csv}"
            )
        return response.text

    def analyze_it_tickets(self,ticket_row):
        system_prompt = f"""
            You are an IT operations expert.
            Analyze this ticket and provide troubleshooting suggestions, potential causes, and priority recommendations.
        """
        with st.spinner("Analyzing ticket with AI..."):
            response = self.client.models.generate_content(
            model=self.model,
            contents=f"{system_prompt}\nTicket Title: {ticket_row.title}\nDescription: {ticket_row.description}"
            )
        return response.text