
import sys
from pathlib import Path
import streamlit as st
from streamlit_lottie import st_lottie

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))
from DATABASE.app.services.session import init_session
from DATABASE.app.services.user_service import UserService
from Animations.json_anm import load_lottiefile
DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"

st.set_page_config(
    page_title="MAIN DASHBOARD",
    layout="wide"
)

st.title("Intelligence Platform  Main dashboard")
init_session()
UserService.require_login(role="user")

   
lottie_coding = load_lottiefile("Animations/WelcomeAnimation.json")

col1, col2 = st.columns(2)
with col1:
    st_lottie(lottie_coding,
            speed =1,
            height=450,
            key=None
            )
with col2:
    st.markdown("""
    ## Welcome to Your Intelligence Platform  
    **Where your three digital worlds finally meet.**

    This dashboard is your command center — a quiet engine room where data, systems,  
    and support all speak the same language.  
    Think of it as the front porch before the journey: a place to get your bearings  
    before stepping into each domain.""")

st.markdown("""
### 🛠️ IT Operations  
This is where the heartbeat of your tech environment lives.Track tickets, monitor staff performance, spot delays, and cut through bottlenecks with clarity instead of chaos.

### 🛡️ Cybersecurity  
A watchtower for threats, incidents, and anomalies. Investigate patterns, review breaches, and arm yourself with insightbecause security isn’t noise; it’s an early warning.

### 📁 Data & Intelligence  
Your space for datasets, metadata, insights, and AI-powered analysis.  
Every file has a story, and this domain helps you make sense of the ones that matter.

---
**Three domains. One platform.  
Everything you need, right where it should be.**
""")