import os
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()
# The client gets the API key from the environment variable `GEMINI_API_KEY`.
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
history = []
while True:
    user_input=input("You: ")
    if user_input.lower()=="quit":
        print("Goodbye")
        break

    #append user input in history
    history.append("User: "+user_input)

    #generate response
    response = client.models.generate_content(
    model="gemini-2.5-flash", 
    contents=history)

    # Access assistant text
    assistant_message = response.text
    history.append("Assistant: " + assistant_message)

    #display AI assistant message
    print(f"AI: {assistant_message}\n")