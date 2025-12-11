import json

#lottie Ref: https://github.com/andfanilo/streamlit-lottie
#lottie animations: https://lottiefiles.com/free-animations/welcome
def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)
 