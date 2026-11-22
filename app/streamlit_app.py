"""
Entry point for the threat modeling app. Registers the pages with explicit
titles, so the sidebar shows proper names rather than file names.

Run:  streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import streamlit as st

st.set_page_config(page_title="Threat Model Review", layout="wide")

nav = st.navigation([
    st.Page("review.py", title="Threat Model Review", icon="🛡️", default=True),
    st.Page("pages/2_SAD_Threat_Model.py", title="SAD Threat Model", icon="📄",
            url_path="sad-threat-model"),
    st.Page("pages/1_Control_Catalog.py", title="Control Catalog", icon="📚",
            url_path="control-catalog"),
    st.Page("pages/3_Help.py", title="Help", icon="❓", url_path="help"),
])
nav.run()
