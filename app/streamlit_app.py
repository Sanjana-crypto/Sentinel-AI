# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Streamlit UI for SentinelAI Cybersecurity Investigation Assistant."""

import asyncio
import datetime
import io
import logging
import os
import re
import uuid
from typing import Any

import google.auth
import streamlit as st
from dotenv import load_dotenv
from google.adk.agents.run_config import RunConfig, StreamingMode
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from app.agent import root_agent



# Load environment variables
load_dotenv(override=True)

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel-ai.streamlit_app")

# Page Configuration
st.set_page_config(
    page_title="SentinelAI - Incident Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize Session State
if "current_page" not in st.session_state:
    st.session_state.current_page = "📧 Phishing Email Analysis"
if "investigation_state" not in st.session_state:
    st.session_state.investigation_state = None

# Sidebar Page-specific styling configurations
active_page = st.session_state.current_page
if active_page == "📧 Phishing Email Analysis":
    accent_color = "#00d4ff"       # Blue-Cyan
    glow_color = "rgba(0, 212, 255, 0.4)"
    border_color = "rgba(0, 212, 255, 0.3)"
elif active_page == "🔗 URL Reputation Checker":
    accent_color = "#bd00ff"       # Purple-Cyan
    glow_color = "rgba(189, 0, 255, 0.4)"
    border_color = "rgba(189, 0, 255, 0.3)"
else:  # "📊 Investigation Results"
    accent_color = "#ff3c00"       # Red-Orange for threat visual
    glow_color = "rgba(255, 60, 0, 0.4)"
    border_color = "rgba(255, 60, 0, 0.3)"

# Custom Premium Dark Theme CSS with Dynamic CSS Variables
st.markdown(
    f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700;800&family=Share+Tech+Mono&display=swap');

        :root {{
            --accent-color: {accent_color};
            --glow-color: {glow_color};
            --border-color: {border_color};
        }}

        /* Main Container Background and Matrix dots */
        @keyframes matrix-rain {{
            0% {{ background-position: 0 0; }}
            100% {{ background-position: 0 1000px; }}
        }}
        .stApp {{
            background-color: #0a0e1a;
            background-image:
                radial-gradient(circle, rgba(0, 255, 0, 0.08) 1.5px, transparent 1.5px);
            background-size: 24px 24px;
            animation: matrix-rain 35s linear infinite;
            color: #ffffff;
        }}

        /* Glowing Grid Lines Overlay */
        .stApp::before {{
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image:
                linear-gradient(rgba(0, 212, 255, 0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 212, 255, 0.02) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
            z-index: 0;
        }}

        /* Headers styling */
        h1, h2, h3, h4, h5, h6 {{
            color: var(--accent-color) !important;
            font-family: 'Rajdhani', sans-serif !important;
            font-weight: 700 !important;
            text-shadow: 0 0 10px var(--glow-color), 0 0 20px rgba(0, 212, 255, 0.1) !important;
            letter-spacing: 1px !important;
        }}

        /* Fonts for normal text */
        body, p, li, label, span, div, .stMarkdown {{
            font-family: 'Rajdhani', sans-serif;
            font-size: 1.1rem;
            color: #cbd5e0 !important;
        }}

        /* Monospace for code/data/tables */
        code, pre, .mono-text, td {{
            font-family: 'Share Tech Mono', 'Courier New', monospace !important;
            font-size: 0.95rem !important;
            color: #00ff66 !important;
        }}

        /* Glassmorphic Cards and Expanders */
        .security-card, .stAlert, div[data-testid="stExpander"] {{
            background: rgba(13, 17, 25, 0.8) !important;
            border: 1px solid var(--border-color) !important;
            border-radius: 12px !important;
            box-shadow: 0 0 20px var(--glow-color) !important;
            backdrop-filter: blur(15px) !important;
            -webkit-backdrop-filter: blur(15px) !important;
            padding: 24px;
            margin-bottom: 25px;
        }}

        /* Sidebar Styling */
        section[data-testid="stSidebar"] {{
            background-color: #0d1117 !important;
            border-right: 1px solid var(--border-color) !important;
            box-shadow: 0 0 20px var(--glow-color) !important;
        }}
        section[data-testid="stSidebar"] h1,
        section[data-testid="stSidebar"] h2,
        section[data-testid="stSidebar"] h3 {{
            color: #00d4ff !important;
            text-shadow: 0 0 10px rgba(0, 212, 255, 0.4) !important;
        }}

        /* Buttons Styling */
        div.stButton > button {{
            background-color: transparent !important;
            color: var(--accent-color) !important;
            border: 2px solid var(--accent-color) !important;
            border-radius: 6px !important;
            padding: 10px 24px !important;
            font-family: 'Rajdhani', sans-serif !important;
            font-weight: 700 !important;
            font-size: 16px !important;
            text-transform: uppercase !important;
            letter-spacing: 2px !important;
            transition: all 0.3s ease-in-out !important;
            box-shadow: 0 0 8px var(--glow-color) !important;
            width: 100%;
        }}
        div.stButton > button:hover {{
            background-color: var(--accent-color) !important;
            color: #0a0e1a !important;
            box-shadow: 0 0 25px var(--accent-color), 0 0 45px var(--glow-color) !important;
            transform: translateY(-2px) !important;
        }}
        div.stButton > button:active {{
            transform: translateY(0px) !important;
        }}

        /* Tables Styling */
        div[data-testid="stMarkdownContainer"] table {{
            width: 100%;
            border-collapse: collapse;
            border: 1px solid var(--accent-color);
            background-color: rgba(13, 17, 25, 0.95);
            margin: 15px 0;
        }}
        div[data-testid="stMarkdownContainer"] th {{
            background-color: rgba(0, 212, 255, 0.1);
            color: var(--accent-color);
            border: 1px solid var(--accent-color);
            padding: 12px;
            font-family: 'Rajdhani', sans-serif;
            font-weight: 700;
            text-transform: uppercase;
        }}
        div[data-testid="stMarkdownContainer"] td {{
            border: 1px solid var(--accent-color);
            padding: 10px;
            color: #ffffff !important;
        }}
        div[data-testid="stMarkdownContainer"] tr:nth-child(even) {{
            background-color: rgba(0, 212, 255, 0.03);
        }}

        /* Risk Badges */
        .risk-badge {{
            display: inline-block;
            padding: 8px 18px;
            border-radius: 20px;
            font-weight: 800;
            text-transform: uppercase;
            font-family: 'Rajdhani', sans-serif;
            letter-spacing: 1.5px;
            font-size: 14px;
        }}
        .risk-critical {{
            background-color: rgba(234, 67, 53, 0.2);
            color: #ff4a4a;
            border: 1px solid #ff4a4a;
            box-shadow: 0 0 10px #ff4a4a;
        }}
        .risk-high {{
            background-color: rgba(255, 109, 1, 0.2);
            color: #ff8800;
            border: 1px solid #ff8800;
            box-shadow: 0 0 10px #ff8800;
        }}
        .risk-medium {{
            background-color: rgba(251, 188, 4, 0.2);
            color: #ffcc00;
            border: 1px solid #ffcc00;
            box-shadow: 0 0 10px #ffcc00;
        }}
        .risk-low {{
            background-color: rgba(52, 168, 83, 0.2);
            color: #00ff66;
            border: 1px solid #00ff66;
            box-shadow: 0 0 10px #00ff66;
        }}
        .risk-unknown {{
            background-color: rgba(154, 160, 166, 0.2);
            color: #a0aec0;
            border: 1px solid #a0aec0;
            box-shadow: 0 0 10px #a0aec0;
        }}

        /* API Badges */
        .api-badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            margin-bottom: 8px;
            letter-spacing: 1px;
            font-family: 'Rajdhani', sans-serif;
        }}
        .api-connected {{
            background-color: rgba(52, 168, 83, 0.15);
            color: #00ff66;
            border: 1px solid #00ff66;
            box-shadow: 0 0 8px rgba(0, 255, 102, 0.3);
        }}
        .api-disconnected {{
            background-color: rgba(234, 67, 53, 0.15);
            color: #ff4a4a;
            border: 1px solid #ff4a4a;
            box-shadow: 0 0 8px rgba(255, 74, 74, 0.3);
        }}

        /* Hero pulsing logo and layout */
        @keyframes pulse {{
            0% {{ transform: scale(1); filter: drop-shadow(0 0 8px rgba(0, 212, 255, 0.4)); opacity: 0.8; }}
            50% {{ transform: scale(1.08); filter: drop-shadow(0 0 25px rgba(0, 212, 255, 0.8)); opacity: 1; }}
            100% {{ transform: scale(1); filter: drop-shadow(0 0 8px rgba(0, 212, 255, 0.4)); opacity: 0.8; }}
        }}
        .hero-container {{
            text-align: center;
            margin-bottom: 30px;
            padding: 20px 0;
            position: relative;
        }}
        .shield-logo {{
            font-size: 4rem;
            animation: pulse 3s infinite ease-in-out;
            display: inline-block;
            vertical-align: middle;
            margin-bottom: 10px;
        }}
        .sidebar-shield-logo {{
            font-size: 2.2rem;
            animation: pulse 4s infinite ease-in-out;
            display: inline-block;
            margin-bottom: 10px;
        }}
        .hero-title {{
            font-size: 3.8rem !important;
            font-family: 'Rajdhani', sans-serif !important;
            font-weight: 800 !important;
            color: #00d4ff !important;
            text-shadow: 0 0 25px rgba(0, 212, 255, 0.7), 0 0 50px rgba(0, 212, 255, 0.3) !important;
            margin: 5px 0 0 0 !important;
            letter-spacing: 2px !important;
        }}
        .hero-subtitle {{
            font-family: 'Share Tech Mono', monospace !important;
            font-size: 1.15rem !important;
            color: #a0aec0 !important;
            margin: 8px 0 12px 0 !important;
            letter-spacing: 3px !important;
            text-transform: uppercase;
        }}
        .hero-divider {{
            border: 0;
            height: 1px;
            background-image: linear-gradient(to right, transparent, #00d4ff, transparent);
            margin-top: 15px;
            margin-bottom: 25px;
        }}
    </style>
    """,
    unsafe_allow_html=True,
)


def get_val(obj: Any, key: str, default: Any = None) -> Any:
    """Safely get values from Pydantic models or dicts."""
    if not obj:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def parse_risk_level(threat_assessment: str, report: str) -> str:
    """Extract the threat risk score from assessment content."""
    text = ((threat_assessment or "") + " " + (report or "")).lower()
    if "critical" in text:
        return "CRITICAL"
    elif "high" in text:
        return "HIGH"
    elif "medium" in text:
        return "MEDIUM"
    elif "low" in text:
        return "LOW"
    return "UNKNOWN"


def classify_threat_type(state: dict[str, Any]) -> str:
    """Deduce a high-level Threat Type badge classification."""
    email_analysis = state.get("email_analysis")
    url_inv = state.get("url_investigation")

    urgency = False
    impersonation = False
    if email_analysis:
        urgency = get_val(email_analysis, "urgency_detected", False)
        impersonation = get_val(email_analysis, "brand_impersonation_detected", False)

    url_flagged = False
    if url_inv and any(
        kw in url_inv.lower() for kw in ["malicious", "flagged", "threat"]
    ):
        url_flagged = True

    if impersonation:
        brand = get_val(email_analysis, "impersonated_brand", "Brand")
        return f"Phishing Email (Impersonating {brand})"
    elif urgency:
        return "Phishing Email (Social Engineering)"
    elif url_flagged:
        return "Malicious Redirect URL / Impersonation Domain"

    assessment = (state.get("threat_assessment") or "").lower()
    if "phish" in assessment:
        return "Phishing Attempt"
    elif "malware" in assessment:
        return "Malware Distribution Domain"
    elif "safe" in assessment or "low" in assessment:
        return "Clean / Safe Input"
    return "Suspicious Security Incident"


def update_timeline_ui(placeholder: Any, timeline: list[dict[str, Any]]) -> None:
    """Render the chronological Multi-Agent timeline."""
    with placeholder.container():
        st.markdown("### 🕵️ Autonomous Agent Investigations")
        for t in timeline:
            status_emoji = "⏳" if t["status"] == "Running..." else "✅"
            agent_name = t["agent"].replace("_", " ").title()
            st.markdown(
                f"**{status_emoji} {agent_name}** — *{t['status']}* at `{t['time']}`"
            )




def calculate_confidence_score(state: dict[str, Any]) -> float:
    """Calculate the confidence score (0-100) based on actual investigation evidence."""
    confidence = 50.0  # Base confidence
    
    email_analysis = state.get("email_analysis")
    url_inv = str(state.get("url_investigation", "")).lower()
    iocs = str(state.get("extracted_iocs", "")).lower()
    threat_assessment = str(state.get("threat_assessment", "")).lower()
    soc_report = str(state.get("soc_report", "")).lower()
    
    malicious_signals = 0
    benign_signals = 0
    
    # 1. Email Analysis Factors
    if email_analysis:
        # Brand Impersonation
        if get_val(email_analysis, "brand_impersonation_detected", False):
            malicious_signals += 2
        else:
            benign_signals += 1
            
        # Urgency Language
        if get_val(email_analysis, "urgency_detected", False):
            malicious_signals += 1
        else:
            benign_signals += 1
            
        # Authentication (SPF/DKIM/DMARC)
        auth = get_val(email_analysis, "authentication", {})
        spf = str(get_val(auth, "spf", "")).lower()
        dkim = str(get_val(auth, "dkim", "")).lower()
        if "fail" in spf or "softfail" in spf or "fail" in dkim:
            malicious_signals += 2
        elif "pass" in spf and "pass" in dkim:
            benign_signals += 2
            
    # 2. URL & Reputation Factors (VT, Safe Browsing)
    if "malicious" in url_inv or "phishing" in url_inv or "flagged" in url_inv or "malware" in url_inv:
        malicious_signals += 3
    elif "safe" in url_inv or "clean" in url_inv:
        benign_signals += 2
        
    if "virustotal" in url_inv or "virustotal" in iocs:
        if "0/" in url_inv or "0/" in iocs or "clean" in url_inv:
            benign_signals += 1
        else:
            malicious_signals += 2

    # 3. IOC Extraction 
    if "abuse confidence score" in iocs and ("100" in iocs or "high" in iocs):
        malicious_signals += 2
        
    # 4. Agent Agreement / Risk Level
    risk_level = parse_risk_level(threat_assessment, soc_report)
    if risk_level in ["CRITICAL", "HIGH"]:
        if malicious_signals >= 3:
            confidence += 30 + (malicious_signals * 5)
        else:
            confidence += 15
    elif risk_level == "LOW":
        if benign_signals >= 3:
            confidence += 30 + (benign_signals * 5)
        else:
            confidence += 15
    elif risk_level == "MEDIUM":
        confidence += 15 # Less confident
        
    # Adjust based on strong evidence
    if malicious_signals > 0 and benign_signals > 0:
        # Mixed signals, lower confidence
        confidence -= 10
        
    # Cap between 0 and 100
    return min(max(confidence, 0.0), 100.0)


def display_results(state: dict[str, Any]) -> None:
    """Render the incident analysis metrics, tables, and reports."""
    threat_assessment = state.get("threat_assessment", "")
    soc_report = state.get("soc_report", "")
    extracted_iocs = state.get("extracted_iocs", "")
    email_analysis = state.get("email_analysis")
    url_inv = state.get("url_investigation", "")

    risk_level = parse_risk_level(threat_assessment, soc_report)
    threat_type = classify_threat_type(state)

    # Color configurations
    colors_map = {
        "CRITICAL": "#ff4a4a",
        "HIGH": "#ff8800",
        "MEDIUM": "#ffcc00",
        "LOW": "#00ff66",
        "UNKNOWN": "#a0aec0",
    }
    color = colors_map.get(risk_level, "#a0aec0")

    confidence_score = calculate_confidence_score(state)

    st.markdown("## 📊 SentinelAI Incident Investigation Report")

    # Metrics Section
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            f"""
            <div class="security-card" style="text-align: center; border-left: 6px solid {color} !important;">
                <span style="font-size: 14px; text-transform: uppercase; letter-spacing: 2px; color: #a0aec0; font-weight: 600;">Risk Level</span>
                <div style="margin: 15px 0;">
                    <span class="risk-badge risk-{risk_level.lower()}">{risk_level}</span>
                </div>
                <p style="color: #cbd5e0; margin: 0; font-size: 15px;">Confidence Score: <strong>{confidence_score:.2f}%</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="security-card" style="min-height: 155px; display: flex; flex-direction: column; justify-content: center; border-left: 6px solid var(--accent-color) !important;">
                <span style="font-size: 14px; text-transform: uppercase; letter-spacing: 2px; color: #a0aec0; font-weight: 600;">Classified Threat Type</span>
                <h3 style="margin: 10px 0; font-size: 20px; font-weight: 700; color: #ffffff !important; text-shadow: none !important;">{threat_type}</h3>
                <p style="color: #cbd5e0; margin: 0; font-size: 14px;">Determined via multi-agent consensus.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            """
            <div class="security-card" style="min-height: 155px; display: flex; flex-direction: column; justify-content: center; border-left: 6px solid #00d4ff !important;">
                <span style="font-size: 14px; text-transform: uppercase; letter-spacing: 2px; color: #a0aec0; font-weight: 600;">Investigation Scope</span>
                <h3 style="margin: 10px 0; font-size: 20px; font-weight: 700; color: #ffffff !important; text-shadow: none !important;">Multi-Agent Intelligence</h3>
                <p style="color: #cbd5e0; margin: 0; font-size: 14px;">5 autonomous agents checking live reputation sources.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 1. Threat Assessment & Justification
    with st.expander("🛡️ Threat Assessment & Justification", expanded=True):
        if threat_assessment:
            st.markdown(threat_assessment)
        else:
            st.info("No threat assessment details generated.")

    # 2. Structured Email Analysis
    if email_analysis:
        with st.expander("📧 Structured Email Header & Content Analysis", expanded=True):
            headers = get_val(email_analysis, "headers", {})
            auth = get_val(email_analysis, "authentication", {})
            urgency_detected = get_val(email_analysis, "urgency_detected", False)
            urgency_just = get_val(email_analysis, "urgency_justification", "")
            brand_impersonation = get_val(email_analysis, "brand_impersonation_detected", False)
            impersonated_brand = get_val(email_analysis, "impersonated_brand", "None")
            ext_urls = get_val(email_analysis, "extracted_urls", [])
            summary = get_val(email_analysis, "detailed_summary", "")

            scol1, scol2 = st.columns(2)
            with scol1:
                st.markdown("#### ✉️ Headers")
                st.markdown(f"**Sender (From):** `{get_val(headers, 'sender', 'N/A')}`")
                st.markdown(f"**Reply-To:** `{get_val(headers, 'reply_to', 'N/A')}`")
                st.markdown(f"**Subject:** `{get_val(headers, 'subject', 'N/A')}`")

                st.markdown("#### 🔒 Authentication")
                spf_val = get_val(auth, "spf", "unknown")
                dkim_val = get_val(auth, "dkim", "unknown")
                dmarc_val = get_val(auth, "dmarc", "unknown")

                spf_style = "color: #00ff66;" if spf_val == "pass" else "color: #ff4a4a;" if spf_val == "fail" else "color: #ffcc00;"
                dkim_style = "color: #00ff66;" if dkim_val == "pass" else "color: #ff4a4a;" if dkim_val == "fail" else "color: #ffcc00;"
                dmarc_style = "color: #00ff66;" if dmarc_val == "pass" else "color: #ff4a4a;" if dmarc_val == "fail" else "color: #ffcc00;"

                st.markdown(f"- **SPF Record:** <span style='{spf_style} font-weight: bold;'>{spf_val.upper()}</span>", unsafe_allow_html=True)
                st.markdown(f"- **DKIM Signature:** <span style='{dkim_style} font-weight: bold;'>{dkim_val.upper()}</span>", unsafe_allow_html=True)
                st.markdown(f"- **DMARC Alignment:** <span style='{dmarc_style} font-weight: bold;'>{dmarc_val.upper()}</span>", unsafe_allow_html=True)

            with scol2:
                st.markdown("#### 🚨 Urgency & Impersonation")
                urgency_badge = "<span style='color: #ff4a4a; font-weight: bold;'>URGENT</span>" if urgency_detected else "<span style='color: #00ff66; font-weight: bold;'>NORMAL</span>"
                st.markdown(f"**Urgency Status:** {urgency_badge}", unsafe_allow_html=True)
                if urgency_detected and urgency_just:
                    st.markdown(f"*Justification:* {urgency_just}")

                impers_badge = f"<span style='color: #ff4a4a; font-weight: bold;'>YES (Brand: {impersonated_brand})</span>" if brand_impersonation else "<span style='color: #00ff66; font-weight: bold;'>NO</span>"
                st.markdown(f"**Brand Impersonation Detected:** {impers_badge}", unsafe_allow_html=True)

                st.markdown("#### 🔗 Extracted URL List")
                if ext_urls:
                    for url in ext_urls:
                        st.markdown(f"- `{url}`")
                else:
                    st.info("No URLs found in the email content.")

            st.markdown("---")
            st.markdown("#### 📄 Analyst Detailed Summary")
            st.markdown(summary)

    # 3. URL Checker Investigation Findings
    if url_inv:
        with st.expander("🔗 URL/IP Reputation Checker Findings", expanded=True):
            st.markdown(url_inv)

    # 4. Indicators of Compromise (IOCs)
    with st.expander("🔍 Extracted Indicators of Compromise (IOCs)", expanded=True):
        if extracted_iocs:
            st.markdown(extracted_iocs)
        else:
            st.info("No indicators of compromise extracted.")

    # 5. Full SOC Incident Report
    with st.expander("📄 View Full SOC Incident Report", expanded=False):
        if soc_report:
            st.markdown(soc_report)
        else:
            st.warning("Full SOC report was not generated.")



def run_investigation(input_text: str) -> None:
    """Execute the ADK multi-agent runner workflow."""
    if not input_text.strip():
        st.error("Please enter a valid input for investigation.")
        return

    # Clear previous state explicitly
    st.session_state.investigation_state = None
    
    # Explicitly clear result keys from st.session_state
    keys_to_clear = [
        "soc_report",
        "threat_assessment",
        "email_analysis",
        "url_investigation",
        "extracted_iocs"
    ]
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]
            
    # Also explicitly reset root_agent's internal state if it exists, to avoid ADK caching
    if hasattr(root_agent, "state") and isinstance(root_agent.state, dict):
        for key in keys_to_clear:
            if key in root_agent.state:
                del root_agent.state[key]
    
    run_id = uuid.uuid4().hex
    user_id = f"streamlit_user_{run_id}"
    session_id = str(uuid.uuid4())

    print(f"DEBUG: Starting new investigation. Session ID: {session_id}")
    print(f"DEBUG: Raw Input:\n{input_text[:100]}...\n")

    session_service = InMemorySessionService()
    session = session_service.create_session_sync(
        user_id=user_id, app_name="sentinel-ai", session_id=session_id
    )
    runner = Runner(
        agent=root_agent, session_service=session_service, app_name="sentinel-ai"
    )

    message = types.Content(role="user", parts=[types.Part.from_text(text=input_text)])

    timeline_placeholder = st.empty()

    with st.status(
        "Orchestrating multi-agent cyber security workflow...", expanded=True
    ) as status_box:
        timeline = []

        async def execute_async_workflow():
            async for event in runner.run_async(
                new_message=message,
                user_id=user_id,
                session_id=session.id,
                run_config=RunConfig(streaming_mode=StreamingMode.SSE),
            ):
                author = event.author
                if author and author not in [
                    "user",
                    "START",
                    "init_state",
                    "complete_workflow",
                ]:
                    # Update currently running agents
                    if author not in [t["agent"] for t in timeline]:
                        for t in timeline:
                            t["status"] = "Completed"
                        timeline.append(
                            {
                                "agent": author,
                                "status": "Running...",
                                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                            }
                        )
                        update_timeline_ui(timeline_placeholder, timeline)

        try:
            # Use asyncio.run to execute the async runner workflow properly
            asyncio.run(execute_async_workflow())
        except Exception as e:
            logger.error(f"Error during runner execution: {e}", exc_info=True)
            st.error(f"Investigation execution failed: {e}")
            status_box.update(
                label="Investigation Encountered Errors!",
                state="error",
                expanded=True,
            )
            return

        for t in timeline:
            t["status"] = "Completed"
        update_timeline_ui(timeline_placeholder, timeline)
        status_box.update(
            label="Security Investigation Completed!",
            state="complete",
            expanded=False,
        )

    # Get completed session state
    updated_session = session_service.get_session_sync(
        app_name="sentinel-ai",
        user_id=user_id, session_id=session.id
    )

    # Save the updated session state to Streamlit's session state
    st.session_state.investigation_state = updated_session.state
    # Switch to Results page automatically!
    st.session_state.current_page = "📊 Investigation Results"


# Streamlit Layout Header Hero Banner
st.markdown(
    """
    <div class="hero-container">
        <div class="shield-logo">🛡️</div>
        <h1 class="hero-title">SentinelAI</h1>
        <p class="hero-subtitle">Multi-Agent Cyber Investigation System</p>
        <div>
            <span class="api-badge" style="background-color: rgba(0, 212, 255, 0.15); color: #00d4ff; border: 1px solid #00d4ff;">
                Powered by Google ADK • Groq LLM • Threat Intelligence APIs
            </span>
        </div>
        <hr class="hero-divider">
    </div>
    """,
    unsafe_allow_html=True,
)

# Sidebar Design
with st.sidebar:
    st.markdown(
        """
        <div style="text-align: center; margin-bottom: 20px;">
            <div class="sidebar-shield-logo">🛡️</div>
            <h3 style="margin: 0; color: #00d4ff !important; text-shadow: 0 0 10px rgba(0, 212, 255, 0.4) !important;">SentinelAI Panel</h3>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("SentinelAI is a multi-agent cybersecurity investigator. It orchestrates Gemini specialist agents to analyze email headers, authenticity alignments, urgency language, and check threat intel APIs.")

    st.markdown("### 🧭 Dashboard Navigation")

    # Radio select button synced directly with the current_page state
    pages = ["📧 Phishing Email Analysis", "🔗 URL Reputation Checker", "📊 Investigation Results"]
    current_index = pages.index(st.session_state.current_page) if st.session_state.current_page in pages else 0
    
    page = st.radio(
        "Select Dashboard View:",
        pages,
        index=current_index,
        key="nav_radio",
        label_visibility="collapsed"
    )
    
    if page != st.session_state.current_page:
        st.session_state.current_page = page
        st.rerun()

    st.markdown("### 🌐 Threat Intelligence API Status")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    sb_key = os.getenv("SAFE_BROWSING_API_KEY")

    if vt_key:
        st.markdown(
            '<span class="api-badge api-connected">VirusTotal: Connected</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span class="api-badge api-disconnected">VirusTotal: Not Configured</span>',
            unsafe_allow_html=True,
        )

    if abuse_key:
        st.markdown(
            '<span class="api-badge api-connected">AbuseIPDB: Connected</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span class="api-badge api-disconnected">AbuseIPDB: Not Configured</span>',
            unsafe_allow_html=True,
        )

    if sb_key:
        st.markdown(
            '<span class="api-badge api-connected">Safe Browsing: Connected</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span class="api-badge api-disconnected">Safe Browsing: Not Configured</span>',
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown("v1.0 • Multi-Agent SOC Analyst Dashboard")

# Page Routing Layout
if st.session_state.current_page == "📧 Phishing Email Analysis":
    st.markdown("### 📧 Paste Raw Email Headers & Content")
    st.markdown(
        "Paste the raw SMTP email headers, SPF/DKIM/DMARC metadata, "
        "and email body content. Our system will analyze routing legitimacy "
        "and social engineering urgency cues."
    )

    email_text = st.text_area(
        "Email text (headers, SPF/DKIM details, and body):",
        height=300,
        placeholder="Delivered-To: victim@domain.com\nFrom: security@paypa1.com\nSubject: Critical Security Action Required\n\nDear Customer, your account has been suspended...",
    )
    if st.button("Run Email Investigation", type="primary"):
        run_investigation(email_text)

elif st.session_state.current_page == "🔗 URL Reputation Checker":
    st.markdown("### 🔗 Enter Suspicious URL, Domain, or IP Address")
    st.markdown(
        "Input a suspicious web address or IP. SentinelAI will query "
        "reputation engines and examine typosquatting lookalikes."
    )

    url_text = st.text_input(
        "Suspicious Domain, URL, or IP address:",
        placeholder="http://verification-login-paypal.com/signin",
    )
    if st.button("Run URL/IP Investigation", type="primary"):
        run_investigation(url_text)

elif st.session_state.current_page == "📊 Investigation Results":
    if st.session_state.investigation_state:
        display_results(st.session_state.investigation_state)
    else:
        st.markdown(
            """
            <div class="security-card" style="text-align: center;">
                <h3 style="margin-top: 0; color: #a0aec0 !important; text-shadow: none !important;">No Results Found</h3>
                <p>An investigation has not been run in the current session.</p>
                <p style="font-size: 14px; color: #718096 !important;">Navigate to Phishing Email Analysis or URL Reputation Checker to run a scan.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
