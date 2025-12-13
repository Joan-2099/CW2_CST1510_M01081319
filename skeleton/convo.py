import streamlit as st
import time
from google import genai

api_key = st.secrets["GEMINAI_API_KEY"]
client = genai.Client(api_key=api_key)

st.title("🤖 Gemini Chatbot")

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display all previous messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Take user input
user_input = st.chat_input("Type here...")

if user_input:
    # Save user message
    st.session_state.messages.append({
        "role": "user",
        "content": user_input
    })

    # Display user message immediately
    with st.chat_message("user"):
        st.markdown(user_input)

    # Prepare conversation history as a list of strings for Gemini
    history = [f"{m['role'].capitalize()}: {m['content']}" for m in st.session_state.messages]

    # Generate response
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=history
    )

    bot_message = response.text

    # Save assistant message
    st.session_state.messages.append({
        "role": "assistant",
        "content": bot_message
    })

    # Display assistant message
    with st.chat_message("assistant"):
        container = st.empty()
        display_text = ""
        for char in bot_message:
            display_text += char
            container.markdown(display_text)
            time.sleep(0.02)
