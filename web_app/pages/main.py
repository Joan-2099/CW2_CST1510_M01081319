
import sys
from pathlib import Path
import streamlit as st
from streamlit_lottie import st_lottie


project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.services.user_service import UserService
from Animations.json_anm import load_lottiefile


st.set_page_config(
    page_title="MAIN DASHBOARD",
    layout="wide"
)

st.title("Intelligence Platform  Main dashboard")
UserService.init_session()
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

st.subheader("🛠️ IT Operations")

st.markdown("This is the engine room.Track tickets from creation to resolution, monitor workload and performance, surface delays early, and dismantle bottlenecks before they harden into failures. Less scrambling. More control. Systems run better when visibility is non-negotiable.")
st.subheader("🛡️ Cybersecurity")
st.markdown("Your early-warning system.Log incidents, examine threat patterns, review breaches, and detect anomalies before they become headlines. Security isn’t constant panic—it’s quiet vigilance, clear signals, and decisive response.") 
st.subheader("📁 Data & Intelligence")
st.markdown("Where information becomes understanding.Manage datasets, metadata, and analytical outputs, then layer in AI-powered insights to uncover trends that aren’t obvious at first glance. Every dataset carries intent; this space helps you read it properly.")
