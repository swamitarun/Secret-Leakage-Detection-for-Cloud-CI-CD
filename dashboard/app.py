"""
Streamlit Dashboard for Context-Aware Secret Leakage Detection.

Visualizes:
1. Executive Summary & Scan Statistics (Files, Findings, Risk Distribution)
2. Interactive Directory / File Scanner
3. IaC & Cloud Resource Intelligence (Terraform, CloudFormation, AWS Resources)
4. CI/CD Pipeline Risk Monitor
5. Deep-Dive Explainable Findings Table with Scoring Factor Breakdown
"""

import os
import sys
from pathlib import Path
import pandas as pd
import streamlit as st

# Setup Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.cli import scan_directory, discover_files
from scanner.scanner import scan_file, redact
from scanner.iac_analyzer import analyze_file
from scanner.risk_engine import assess_risk, to_json_dict

# Page Config
st.set_page_config(
    page_title="Context-Aware Secret Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1e293b;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #64748b;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #f8fafc;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid #e2e8f0;
    }
    .badge-critical { background-color: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background-color: #f97316; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #f59e0b; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #3b82f6; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-safe { background-color: #10b981; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("🛡️ Scanner Control")
st.sidebar.markdown("---")

default_scan_dir = str(PROJECT_ROOT / "tests" / "fixtures")
target_path_input = st.sidebar.text_input("Target Directory or File to Scan", value=default_scan_dir)

risk_filter = st.sidebar.multiselect(
    "Filter by Risk Level",
    options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"],
    default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]
)

scan_btn = st.sidebar.button("🚀 Run Security Scan", use_container_width=True)

# Header
st.markdown('<div class="main-header">🛡️ Context-Aware Secret Leakage Detection</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Novel Security Scanner: Enriches regex matching with IaC (Terraform / CloudFormation), AWS Resource Intelligence, and CI/CD Context.</div>', unsafe_allow_html=True)

# Perform Scan
if target_path_input and os.path.exists(target_path_input):
    assessments = scan_directory(target_path_input)
    
    # Filter
    filtered_assessments = [a for a in assessments if a.risk_level in risk_filter]
    
    # Overview Metrics
    total_files = len(assessments)
    crit_count = sum(1 for a in assessments if a.risk_level == "CRITICAL")
    high_count = sum(1 for a in assessments if a.risk_level == "HIGH")
    med_count = sum(1 for a in assessments if a.risk_level == "MEDIUM")
    low_count = sum(1 for a in assessments if a.risk_level == "LOW")
    safe_count = sum(1 for a in assessments if a.risk_level == "SAFE")
    
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    col1.metric("📁 Files Scanned", total_files)
    col2.metric("🚨 Critical", crit_count)
    col3.metric("⚠️ High", high_count)
    col4.metric("🟡 Medium", med_count)
    col5.metric("🔵 Low", low_count)
    col6.metric("✅ Safe", safe_count)
    
    st.markdown("---")
    
    # Visual Analytics Tabs
    tab_overview, tab_findings, tab_iac, tab_explain = st.tabs([
        "📊 Risk & Context Distribution",
        "🔍 Detailed Findings",
        "🏗️ IaC & AWS Resources",
        "🧠 Explainability Engine"
    ])
    
    with tab_overview:
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.subheader("Risk Level Breakdown")
            risk_df = pd.DataFrame({
                "Risk Level": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"],
                "Count": [crit_count, high_count, med_count, low_count, safe_count]
            })
            st.bar_chart(risk_df.set_index("Risk Level"), color="#ef4444")
            
        with col_chart2:
            st.subheader("File Type Distribution")
            ft_counts = {}
            for a in assessments:
                ft_counts[a.file_type] = ft_counts.get(a.file_type, 0) + 1
            ft_df = pd.DataFrame(list(ft_counts.items()), columns=["File Type", "Count"])
            st.bar_chart(ft_df.set_index("File Type"), color="#3b82f6")
            
    with tab_findings:
        st.subheader("Scan Findings Table")
        
        table_rows = []
        for a in filtered_assessments:
            table_rows.append({
                "File": os.path.basename(a.filepath),
                "Path": a.filepath,
                "Risk Level": a.risk_level,
                "Score": a.risk_score,
                "IaC Type": a.iac_type,
                "AWS Resources": ", ".join(a.aws_resources) if a.aws_resources else "None",
                "CI/CD Context": "Yes (" + a.ci_cd_platform + ")" if a.ci_cd_context else "No",
                "Secrets Detected": len([f for f in a.findings if not f.is_placeholder]),
                "Explanation": a.explanation
            })
            
        if table_rows:
            df_table = pd.DataFrame(table_rows)
            st.dataframe(df_table, use_container_width=True)
        else:
            st.info("No files match the selected filter.")
            
    with tab_iac:
        st.subheader("Infrastructure-as-Code & Cloud Assets Intelligence")
        
        iac_files = [a for a in assessments if a.iac_type != "none"]
        st.write(f"Detected **{len(iac_files)}** Infrastructure-as-Code templates:")
        
        for a in iac_files:
            with st.expander(f"📦 {os.path.basename(a.filepath)} ({a.iac_type.capitalize()}) - Risk: {a.risk_level} ({a.risk_score})"):
                st.write(f"**Full Path:** `{a.filepath}`")
                st.write(f"**Cloud Provider:** `{a.cloud_provider.upper()}`")
                st.write(f"**Detected AWS Resources:** `{', '.join(a.aws_resources) if a.aws_resources else 'None'}`")
                st.write(f"**Explanation:** {a.explanation}")
                if a.findings:
                    st.write("**Detected Secret Types:**")
                    for f in a.findings:
                        st.code(f"Line {f.line_number}: [{f.secret_type}] - Entropy: {f.entropy} - Placeholder: {f.is_placeholder}")

    with tab_explain:
        st.subheader("Explainable Deterministic Scoring Breakdown")
        st.markdown("Select a file below to inspect how each positive & negative scoring factor contributed to the final risk score:")
        
        file_options = {a.filepath: a for a in assessments}
        selected_file_path = st.selectbox("Choose File to Inspect", options=list(file_options.keys()))
        
        if selected_file_path:
            sel_a = file_options[selected_file_path]
            
            st.markdown(f"### Assessment for: `{os.path.basename(sel_a.filepath)}`")
            st.markdown(f"**Final Risk:** `{sel_a.risk_level}` | **Composite Score:** `{sel_a.risk_score} / 100`")
            st.info(f"**Rationale:** {sel_a.explanation}")
            
            factors_data = []
            for fac in sel_a.factors:
                factors_data.append({
                    "Factor Name": fac.name,
                    "Points": f"{'+' if fac.points >= 0 else ''}{fac.points}",
                    "Description": fac.description
                })
                
            st.table(pd.DataFrame(factors_data))
            
else:
    st.error(f"Target directory or file '{target_path_input}' does not exist. Please specify a valid path in the sidebar.")
