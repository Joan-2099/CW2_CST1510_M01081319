import streamlit as st
from google import genai

# Initialize OpenAI client
api_key = st.secrets["GEMINAI_API_KEY"]
client = genai.Client(api_key=api_key)

# Page title
st.title("🛡 Cybersecurity AI Assistant")
# Initialize session state with system prompt
if 'messages' not in st.session_state:
    st.session_state.messages = [
    {
        "role": "system",
        "content": """You are a cybersecurity expert assistant.
        - Analyze incidents and threats
        - Provide technical guidance
        - Explain attack vectors and mitigations
        - Use standard terminology (MITRE ATT&CK, CVE)
        - Prioritize actionable recommendations
        Tone: Professional, technical
        Format: Clear, structured responses"""
        }
    ]
# Display all previous messages (skip system message)
for message in st.session_state.messages:
    if message["role"] != "system": # Don't display system prompt
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
# Get user input
prompt = st.chat_input("Ask about cybersecurity...")
if prompt:
# Display user message
    with st.chat_message("user"):
        st.markdown(prompt)
# Add user message to session state
st.session_state.messages.append({
    "role": "user",
    "content": prompt
})

# Prepare conversation as a list of strings for Gemini
history = [
    f"{m['role'].capitalize()}: {m['content']}" 
    for m in st.session_state.messages
]

# Call OpenAI API
completion = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=history
    )

# Extract assistant response
response = completion.text

# Display assistant response
with st.chat_message("assistant"):
    st.markdown(response)
# Add assistant response to session state
st.session_state.messages.append({
    "role": "assistant",
    "content": response
})