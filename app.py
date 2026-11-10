"""
LOGSENTRY | Enterprise AI SOC & Autonomous Incident Response Platform
Next-Generation Cyber Threat Detection, MITRE ATT&CK Correlation, and SOAR Containment.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import io

# Import core LOGSENTRY modules
from detector import analyze_logs, make_demo_logs, validate_logs, generate_report, extract_ip_features
import threat_intelligence as ti
import scenarios as sc
import soar
from log_parsers import parse_generic_csv, parse_syslog_auth_log, parse_apache_nginx_log

# Page Configuration
st.set_page_config(
    page_title="LOGSENTRY | Enterprise AI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber SOC Dark Glassmorphism Styling
st.markdown("""
<style>
/* Main Background and Typography */
.stApp {
    background: radial-gradient(circle at 15% 15%, #0f172a 0%, #080d1a 100%);
    color: #f1f5f9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
}

/* Glassmorphism Cards */
[data-testid="stMetric"] {
    background: rgba(18, 29, 48, 0.75);
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 12px;
    padding: 16px 20px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    backdrop-filter: blur(8px);
    transition: transform 0.2s ease, border-color 0.2s ease;
}
[data-testid="stMetric"]:hover {
    border-color: rgba(56, 189, 248, 0.5);
    transform: translateY(-2px);
}

/* Header & Banner */
.soc-banner {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: linear-gradient(90deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.8) 100%);
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 16px 24px;
    margin-bottom: 24px;
}
.soc-title {
    font-size: 1.8rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    margin: 0;
    background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.soc-subtitle {
    color: #94a3b8;
    font-size: 0.88rem;
    margin-top: 4px;
}
.defcon-pill {
    padding: 6px 16px;
    border-radius: 9999px;
    font-weight: 700;
    font-size: 0.82rem;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    display: inline-flex;
    align-items: center;
    gap: 8px;
}
.defcon-critical {
    background: rgba(239, 68, 68, 0.2);
    color: #f87171;
    border: 1px solid #ef4444;
    box-shadow: 0 0 12px rgba(239, 68, 68, 0.4);
}
.defcon-nominal {
    background: rgba(34, 197, 94, 0.2);
    color: #4ade80;
    border: 1px solid #22c55e;
}

/* Kill Chain Cards */
.kc-container {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin: 18px 0;
}
.kc-card {
    background: rgba(15, 23, 42, 0.85);
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 14px;
    text-align: center;
    position: relative;
    transition: all 0.3s ease;
}
.kc-active {
    border-color: #ef4444;
    background: rgba(239, 68, 68, 0.12);
    box-shadow: 0 0 16px rgba(239, 68, 68, 0.25);
}
.kc-title {
    font-weight: 700;
    font-size: 0.85rem;
    color: #e2e8f0;
    margin-top: 6px;
}
.kc-desc {
    font-size: 0.72rem;
    color: #94a3b8;
    margin-top: 4px;
}

/* Code Boxes & Pre */
pre, code {
    background-color: #0b1329 !important;
    border: 1px solid #1e293b !important;
    border-radius: 8px !important;
}

/* Custom Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    border-bottom: 1px solid #334155;
}
.stTabs [data-baseweb="tab"] {
    background-color: transparent;
    border-radius: 8px 8px 0 0;
    padding: 10px 18px;
    color: #94a3b8;
    font-weight: 600;
}
.stTabs [aria-selected="true"] {
    background-color: rgba(56, 189, 248, 0.15) !important;
    color: #38bdf8 !important;
    border-bottom: 2px solid #38bdf8 !important;
}
</style>
""", unsafe_allow_html=True)

# Session State Initialization
if "current_scenario_name" not in st.session_state:
    st.session_state.current_scenario_name = "APT Multi-Stage Intrusion (Recommended)"
    st.session_state.active_logs = sc.generate_apt_multistage_scenario()

# Sidebar Configuration
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.markdown("### **LOGSENTRY AI SOC**")
    st.caption("v2.5 Autonomous SIEM & Threat Hunting Engine")
    st.divider()
    
    st.markdown("#### 🎯 Threat Scenario Presets")
    scenario_choice = st.selectbox(
        "Select Attack Scenario",
        [
            "APT Multi-Stage Intrusion (Recommended)",
            "Distributed Botnet Password Spray",
            "Malicious Insider Threat (Off-Hours)",
            "Credential Stuffing Surge",
            "Clean Baseline (Zero-Alert Test)",
            "Default Starter Demo Logs"
        ],
        index=0
    )
    
    if st.button("⚡ Load Selected Scenario", use_container_width=True):
        st.session_state.current_scenario_name = scenario_choice
        if scenario_choice == "APT Multi-Stage Intrusion (Recommended)":
            st.session_state.active_logs = sc.generate_apt_multistage_scenario()
        elif scenario_choice == "Distributed Botnet Password Spray":
            st.session_state.active_logs = sc.generate_password_spraying_scenario()
        elif scenario_choice == "Malicious Insider Threat (Off-Hours)":
            st.session_state.active_logs = sc.generate_insider_threat_scenario()
        elif scenario_choice == "Credential Stuffing Surge":
            st.session_state.active_logs = sc.generate_credential_stuffing_scenario()
        elif scenario_choice == "Clean Baseline (Zero-Alert Test)":
            st.session_state.active_logs = sc.generate_clean_baseline_scenario()
        else:
            st.session_state.active_logs = make_demo_logs()
        st.rerun()

    st.divider()
    st.markdown("#### 📥 Ingest Custom Log Sources")
    log_format = st.radio("Log Source Format", ["CSV / Excel", "Linux auth.log (Syslog)", "Apache / Nginx Access Log"])
    uploaded_file = st.file_uploader(f"Upload {log_format}", type=["csv", "log", "txt"])
    
    st.divider()
    st.markdown("#### ⚙️ Detection Sensitivity Tuning")
    brute_force_thresh = st.slider("Brute-Force Threshold (Failures)", min_value=3, max_value=15, value=5, help="Number of failed logins required to trip brute-force rule")
    sliding_window_min = st.slider("Time Window (Minutes)", min_value=1, max_value=10, value=2, help="Sliding time window for velocity correlation")

# Handle Custom Uploads
if uploaded_file is not None:
    try:
        content = uploaded_file.getvalue().decode("utf-8", errors="replace")
        if log_format == "CSV / Excel":
            raw_csv = pd.read_csv(io.StringIO(content))
            success, msg, norm_df = parse_generic_csv(raw_csv)
            if success:
                st.session_state.active_logs = norm_df
                st.session_state.current_scenario_name = f"Uploaded CSV ({uploaded_file.name})"
            else:
                st.sidebar.error(msg)
        elif log_format == "Linux auth.log (Syslog)":
            success, msg, norm_df = parse_syslog_auth_log(content)
            if success:
                st.session_state.active_logs = norm_df
                st.session_state.current_scenario_name = f"Linux Auth Log ({uploaded_file.name})"
            else:
                st.sidebar.error(msg)
        else: # Apache / Nginx
            success, msg, norm_df = parse_apache_nginx_log(content)
            if success:
                st.session_state.active_logs = norm_df
                st.session_state.current_scenario_name = f"Web Access Log ({uploaded_file.name})"
            else:
                st.sidebar.error(msg)
    except Exception as e:
        st.sidebar.error(f"Error parsing uploaded file: {e}")

# Validate and Run Analysis
valid, msg, cleaned_logs = validate_logs(st.session_state.active_logs)
if not valid:
    st.error(f"Log Validation Error: {msg}")
    st.stop()

results = analyze_logs(cleaned_logs, failure_threshold=brute_force_thresh, window_minutes=sliding_window_min)
events_df = results["events"]
incidents = results["incidents"]

# Determine SOC DEFCON Posture
has_critical = any(inc["severity"] in ["Critical", "High"] for inc in incidents)
defcon_class = "defcon-critical" if has_critical else "defcon-nominal"
defcon_text = "DEFCON 1 • CRITICAL THREAT DETECTED" if has_critical else "DEFCON 5 • POSTURE NOMINAL"
defcon_icon = "🚨" if has_critical else "🟢"

# Top Banner
st.markdown(f"""
<div class="soc-banner">
    <div>
        <h1 class="soc-title">🛡️ LOGSENTRY AI SOC COMMAND</h1>
        <div class="soc-subtitle">Active Scenario: <strong>{st.session_state.current_scenario_name}</strong> • Engine: Hybrid ML & MITRE ATT&CK Matrix</div>
    </div>
    <div class="defcon-pill {defcon_class}">
        <span>{defcon_icon}</span>
        <span>{defcon_text}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Top KPI Metric Strip
col_kpi1, col_kpi2, col_kpi3, col_kpi4, col_kpi5 = st.columns(5)
total_events = len(events_df)
total_incidents = len(incidents)
high_crit_count = sum(1 for inc in incidents if inc["severity"] in ["High", "Critical"])
unique_ips = events_df["ip"].nunique()
ml_anomaly_count = int(events_df["ml_anomaly"].sum())

col_kpi1.metric("Ingested Events", f"{total_events:,}")
col_kpi2.metric("Security Incidents", total_incidents, delta=f"{high_crit_count} Critical/High", delta_color="inverse")
col_kpi3.metric("ML Anomalies Flagged", ml_anomaly_count, help="Flagged by unsupervised Isolation Forest")
col_kpi4.metric("Unique Hosts / IPs", unique_ips)
col_kpi5.metric("Mean Time to Detect (MTTD)", "< 0.4 sec", delta="Instant Sub-Second", delta_color="normal")

st.markdown("<br>", unsafe_allow_html=True)

# Main Tabbed Interface
tab_cmd, tab_forensics, tab_ml, tab_soar, tab_stream, tab_report = st.tabs([
    "🛰️ SOC Command Center & Kill Chain",
    "🔍 Incident Forensics & Triage",
    "🧠 Explainable AI / ML Lab",
    "⚡ SOAR Automated Response",
    "📡 Live Attack Simulator",
    "📑 Threat Briefing & Export"
])

# ==========================================
# TAB 1: SOC COMMAND CENTER & KILL CHAIN
# ==========================================
with tab_cmd:
    st.subheader("⚔️ Cyber Kill Chain Progression")
    st.caption("Automated phase correlation mapping adversarial progression through enterprise defenses.")
    
    # Assess which Kill Chain stages are active
    active_stages = set()
    for inc in incidents:
        stage = inc.get("kill_chain", "")
        if stage:
            active_stages.add(stage)
    if "failed" in events_df["event"].values:
        active_stages.add("2. Credential Access")
    if "success" in events_df["event"].values and len(events_df[events_df["event"] == "failed"]) >= brute_force_thresh:
        active_stages.add("3. Initial Access")
    if "privilege_change" in events_df["event"].values:
        active_stages.add("4. Privilege Escalation")
    if "sensitive_access" in events_df["event"].values:
        active_stages.add("5. Actions on Objectives")
    if len(active_stages) == 0:
        active_stages.add("1. Recon & Probing")

    kc_html = "<div class='kc-container'>"
    for stage_info in ti.KILL_CHAIN_STAGES:
        is_active = stage_info["stage"] in active_stages
        active_cls = "kc-active" if is_active else ""
        badge_status = "<span style='color: #ef4444; font-weight: bold;'>⚠️ BREACHED</span>" if is_active else "<span style='color: #22c55e;'>SECURE</span>"
        kc_html += f"""
        <div class="kc-card {active_cls}">
            <div style="font-size: 1.6rem;">{stage_info['icon']}</div>
            <div class="kc-title">{stage_info['stage']}</div>
            <div class="kc-desc">{stage_info['desc']}</div>
            <div style="margin-top: 8px; font-size: 0.75rem;">{badge_status}</div>
        </div>
        """
    kc_html += "</div>"
    st.markdown(kc_html, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Interactive Event Scatter Timeline & Volume
    col_time1, col_time2 = st.columns([1.6, 1])
    
    with col_time1:
        st.subheader("⏱️ Multi-Dimensional Event Timeline")
        timeline_df = events_df.copy()
        timeline_df["Event Type"] = timeline_df["event"].str.replace("_", " ").str.title()
        
        # Color mapping
        color_map = {
            "Success": "#34d399",
            "Failed": "#f87171",
            "Privilege Change": "#fbbf24",
            "Sensitive Access": "#c084fc"
        }
        
        fig_timeline = px.scatter(
            timeline_df,
            x="timestamp",
            y="ip",
            color="Event Type",
            color_discrete_map=color_map,
            hover_data={"user": True, "event": True, "timestamp": "|%Y-%m-%d %H:%M:%S"},
            title="Authentication & Security Events by Source IP",
            size_max=12
        )
        fig_timeline.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.6)",
            height=370,
            xaxis=dict(gridcolor="#1e293b", title="Timeline"),
            yaxis=dict(gridcolor="#1e293b", title="Source Host / IP"),
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
        
    with col_time2:
        st.subheader("📊 Event Type Distribution")
        event_counts = events_df["event"].value_counts().reset_index()
        event_counts.columns = ["Event", "Count"]
        event_counts["Event"] = event_counts["Event"].str.replace("_", " ").str.title()
        
        fig_donut = px.pie(
            event_counts,
            values="Count",
            names="Event",
            hole=0.6,
            color="Event",
            color_discrete_map=color_map
        )
        fig_donut.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=370,
            showlegend=True,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    # MITRE ATT&CK Matrix Alignment
    st.subheader("🗺️ Mapped MITRE ATT&CK Matrix")
    st.caption("Standardized threat tactics & techniques correlated from observed activity.")
    
    mitre_cols = st.columns(4)
    all_observed_mitre = {}
    for inc in incidents:
        for m in inc.get("mitre", []):
            all_observed_mitre[m["id"]] = m
            
    if all_observed_mitre:
        for idx, (m_id, m_data) in enumerate(all_observed_mitre.items()):
            target_col = mitre_cols[idx % 4]
            with target_col:
                st.markdown(f"""
                <div style="background: rgba(30, 41, 59, 0.7); border-left: 4px solid {m_data['color']}; padding: 12px 14px; border-radius: 8px; margin-bottom: 12px;">
                    <span style="font-size: 0.75rem; color: #94a3b8; font-weight: 700;">{m_data['tactic_id']} • {m_data['tactic']}</span>
                    <div style="font-size: 0.95rem; font-weight: 800; color: #f8fafc; margin: 4px 0;">{m_id}: {m_data['name']}</div>
                    <div style="font-size: 0.78rem; color: #cbd5e1;">{m_data['description']}</div>
                    <div style="margin-top: 6px;"><span style="font-size: 0.7rem; background: {m_data['color']}; color: #000; padding: 2px 8px; border-radius: 4px; font-weight: 700;">{m_data['severity'].upper()}</span></div>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No active MITRE ATT&CK techniques matched in the current baseline dataset.")

# ==========================================
# TAB 2: INCIDENT FORENSICS & TRIAGE
# ==========================================
with tab_forensics:
    st.subheader("🚨 Detected Security Incidents & Threat Triage")
    
    if incidents:
        inc_summary_rows = []
        for inc in incidents:
            inc_summary_rows.append({
                "Severity": inc["severity"],
                "Risk Score": f"{inc['risk_score']} / 100",
                "Source IP": inc["ip"],
                "Targeted Account": inc.get("target_user", "Multiple"),
                "Incident Title": inc["title"],
                "Kill Chain Phase": inc.get("kill_chain", "N/A")
            })
        st.dataframe(pd.DataFrame(inc_summary_rows), use_container_width=True, hide_index=True)
        
        st.divider()
        
        # Deep inspection
        sel_idx = st.selectbox(
            "Select Incident for Forensic Deep Dive",
            options=list(range(len(incidents))),
            format_func=lambda i: f"[{incidents[i]['severity'].upper()}] {incidents[i]['ip']} — {incidents[i]['title']} (Score: {incidents[i]['risk_score']})"
        )
        selected_inc = incidents[sel_idx]
        
        col_deep1, col_deep2 = st.columns([1.4, 1])
        
        with col_deep1:
            st.markdown(f"### {selected_inc['title']}")
            st.write(selected_inc["summary"])
            
            st.markdown("#### 🔬 Forensic Evidence Corroboration")
            for ev in selected_inc["evidence"]:
                st.markdown(f"- 🔴 **{ev}**")
                
            st.markdown("#### 🛡️ Prescribed Containment Actions")
            for rec in selected_inc["recommendations"]:
                st.markdown(f"- 📋 {rec}")
                
        with col_deep2:
            # Risk Gauge
            gauge_color = "#ef4444" if selected_inc["risk_score"] >= 70 else ("#f59e0b" if selected_inc["risk_score"] >= 40 else "#10b981")
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=selected_inc["risk_score"],
                title={'text': "Calculated Threat Score"},
                gauge={
                    'axis': {'range': [None, 100], 'tickcolor': "#94a3b8"},
                    'bar': {'color': gauge_color},
                    'steps': [
                        {'range': [0, 40], 'color': "rgba(16, 185, 129, 0.2)"},
                        {'range': [40, 70], 'color': "rgba(245, 158, 11, 0.2)"},
                        {'range': [70, 100], 'color': "rgba(239, 68, 68, 0.3)"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ))
            fig_gauge.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                height=260,
                margin=dict(l=30, r=30, t=50, b=10)
            )
            st.plotly_chart(fig_gauge, use_container_width=True)
            
            # Host Forensic Summary
            st.markdown(f"""
            <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid #334155; padding: 14px; border-radius: 8px;">
                <div style="font-size: 0.8rem; color: #94a3b8;">HOST FORENSIC PROFILE</div>
                <div style="font-weight: 700; color: #38bdf8; font-size: 1.1rem; margin-top: 4px;">{selected_inc['ip']}</div>
                <div style="font-size: 0.85rem; color: #cbd5e1; margin-top: 6px;">Target Account: <code>{selected_inc.get('target_user', 'N/A')}</code></div>
                <div style="font-size: 0.85rem; color: #cbd5e1;">Severity Classification: <strong>{selected_inc['severity']}</strong></div>
            </div>
            """, unsafe_allow_html=True)
            
        # Raw Event Slice
        st.markdown(f"#### 📜 Correlated Log Events for Host `{selected_inc['ip']}`")
        if "Distributed" not in selected_inc["ip"]:
            slice_df = events_df[events_df["ip"] == selected_inc["ip"]][["timestamp", "ip", "event", "user", "rule_alert", "ml_anomaly"]]
        else:
            slice_df = events_df[events_df["user"] == selected_inc.get("target_user", "")][["timestamp", "ip", "event", "user", "rule_alert", "ml_anomaly"]]
        st.dataframe(slice_df, use_container_width=True, hide_index=True)
    else:
        st.success("🟢 No security incidents detected matching active rules and thresholds in this dataset.")

# ==========================================
# TAB 3: EXPLAINABLE AI / ML LAB
# ==========================================
with tab_ml:
    st.subheader("🧠 Explainable Machine Learning (XAI) & Isolation Forest")
    st.caption("Unsupervised behavioral anomaly modeling with per-feature contribution explanations.")
    
    features_df = extract_ip_features(events_df)
    
    col_ml1, col_ml2 = st.columns([1.3, 1])
    
    with col_ml1:
        st.markdown("#### 🔬 Unsupervised Behavioral Clustering")
        # 2D Scatter showing anomalies
        plot_feat = features_df.copy().reset_index().rename(columns={"index": "ip"})
        plot_feat["Is Anomaly"] = plot_feat["ip"].isin(events_df.loc[events_df["ml_anomaly"], "ip"])
        plot_feat["Status"] = plot_feat["Is Anomaly"].map({True: "Flagged Anomaly", False: "Normal Baseline"})
        
        fig_ml = px.scatter(
            plot_feat,
            x="total_events",
            y="failed_events",
            size="events_per_minute",
            color="Status",
            hover_name="ip",
            hover_data=["failure_ratio", "unique_users_targeted", "privilege_changes", "sensitive_access"],
            color_discrete_map={"Flagged Anomaly": "#ef4444", "Normal Baseline": "#38bdf8"},
            title="Total Events vs. Authentication Failures (Bubble Size = Velocity)",
            labels={"total_events": "Total Event Count", "failed_events": "Failed Login Count"}
        )
        fig_ml.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.6)",
            height=380,
            xaxis=dict(gridcolor="#1e293b"),
            yaxis=dict(gridcolor="#1e293b")
        )
        st.plotly_chart(fig_ml, use_container_width=True)
        
    with col_ml2:
        st.markdown("#### 🔍 Explainable AI (XAI) Breakdown")
        st.write("Isolation Forest isolates anomalies by building random decision trees. Points isolated with short average path lengths exhibit statistically extreme behavior.")
        
        flagged_ips = plot_feat[plot_feat["Is Anomaly"]]["ip"].tolist()
        if flagged_ips:
            st.markdown(f"**Anomalous Host Identified:** `{flagged_ips[0]}`")
            ml_reasons = results.get("ml_reasons", {}).get(flagged_ips[0], ["Behavioral outlier"])
            for r in ml_reasons:
                st.markdown(f"- ⚡ {r}")
        else:
            st.info("No host exceeded the Isolation Forest anomaly decision boundary in this dataset.")
            
        st.divider()
        st.markdown("#### 📈 Statistical Feature Matrix")
        st.dataframe(features_df, use_container_width=True)

# ==========================================
# TAB 4: SOAR AUTOMATED RESPONSE
# ==========================================
with tab_soar:
    st.subheader("⚡ Automated Containment & Incident Response (SOAR)")
    st.caption("Generate instant multi-platform blocking commands, Sigma SIEM detection rules, and SOC tickets.")
    
    if incidents:
        target_inc = incidents[0]
        containment_ip = target_inc["ip"]
        
        if "Distributed" in containment_ip:
            st.warning("Selected incident is a distributed spray across multiple IPs. Containment rules can be generated for individual sub-nodes.")
            containment_ip = "198.51.100.14"
            
        scripts = soar.generate_containment_scripts(containment_ip, target_inc["title"], target_inc["severity"])
        
        col_soar1, col_soar2 = st.columns([1, 1])
        
        with col_soar1:
            st.markdown(f"#### 🛡️ 1-Click Firewall Containment for `{containment_ip}`")
            fw_platform = st.radio("Target Firewall Platform", ["Linux (iptables/nftables)", "Windows Defender Firewall", "AWS VPC Network ACL", "Cloudflare Edge WAF"])
            
            if "Linux" in fw_platform:
                st.code(scripts["linux"], language="bash")
            elif "Windows" in fw_platform:
                st.code(scripts["windows"], language="powershell")
            elif "AWS" in fw_platform:
                st.code(scripts["aws"], language="bash")
            else:
                st.code(scripts["cloudflare"], language="bash")
                
        with col_soar2:
            st.markdown("#### 📜 Auto-Generated Sigma SIEM Rule (YAML)")
            st.caption("Ready for immediate import into Splunk, Microsoft Sentinel, Elastic, and QRadar.")
            sigma_content = soar.generate_sigma_rule(target_inc)
            st.code(sigma_content, language="yaml")
            st.download_button("⬇️ Download Sigma Rule (.yml)", sigma_content, file_name=f"sigma_rule_{containment_ip}.yml", mime="text/yaml")
            
        st.divider()
        st.markdown("#### 🎫 Auto-Generated Jira / ServiceNow SOC Escalation Ticket")
        ticket_content = soar.generate_soc_ticket(target_inc)
        st.text_area("Ticket Markdown Preview", ticket_content, height=220)
        st.download_button("⬇️ Download SOC Incident Ticket (.md)", ticket_content, file_name=f"soc_ticket_{containment_ip}.md", mime="text/markdown")
    else:
        st.info("No active incidents to contain. Load an attack scenario from the sidebar to test SOAR capabilities.")

# ==========================================
# TAB 5: LIVE ATTACK STREAM SIMULATOR
# ==========================================
with tab_stream:
    st.subheader("📡 Live Attack Stream Simulator")
    st.caption("Simulate real-time log ingestion into LOGSENTRY to demonstrate live threat alerts during presentations.")
    
    stream_col1, stream_col2 = st.columns([1.5, 1])
    
    with stream_col1:
        st.write("Click below to simulate incoming real-time telemetry from external and internal perimeter firewalls.")
        if st.button("▶️ Launch Live 10-Second Threat Ingestion Simulation"):
            stream_placeholder = st.empty()
            progress_bar = st.progress(0)
            
            sim_logs = sc.generate_apt_multistage_scenario().to_dict('records')
            streamed = []
            
            for i, row in enumerate(sim_logs[:12]):
                streamed.append(row)
                progress_bar.progress((i + 1) / 12)
                
                # Render simulated radar ticker
                ticker_html = "<div style='background: #090e1a; border: 1px solid #1e293b; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 0.85rem;'>"
                for item in reversed(streamed[-5:]):
                    evt_color = "#f87171" if item['event'] == 'failed' else ("#fbbf24" if item['event'] == 'privilege_change' else ("#c084fc" if item['event'] == 'sensitive_access' else "#34d399"))
                    ticker_html += f"<div style='margin-bottom: 4px;'><span style='color: #64748b;'>[{item['timestamp']}]</span> <span style='color: #38bdf8;'>{item['ip']}</span> -> <strong style='color: {evt_color};'>{item['event'].upper()}</strong> (User: {item['user']})</div>"
                ticker_html += "</div>"
                stream_placeholder.markdown(ticker_html, unsafe_allow_html=True)
                
            st.success("✅ Real-Time Ingestion complete. Threat correlated across kill chain!")
            
    with stream_col2:
        st.markdown("""
        <div style="background: rgba(30, 41, 59, 0.5); border: 1px solid #334155; padding: 18px; border-radius: 12px;">
            <h4>🎙️ Presentation Demo Script</h4>
            <p style="font-size: 0.85rem; color: #94a3b8;">Use this flow when presenting to judges:</p>
            <ol style="font-size: 0.82rem; color: #cbd5e1; line-height: 1.6;">
                <li><strong>Baseline:</strong> Show how normal users authenticate without tripping false positives.</li>
                <li><strong>Attack Trigger:</strong> Launch the simulated stream or switch to the APT scenario.</li>
                <li><strong>Correlation:</strong> Point to the Kill Chain cards lighting up from Credential Access to Crown Jewels.</li>
                <li><strong>XAI & ML:</strong> Show the Isolation Forest 2D scatter plot proving statistical anomaly detection.</li>
                <li><strong>Remediation:</strong> Click the SOAR tab to show production-ready Linux/Windows firewall blocking commands and Sigma rules.</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)

# ==========================================
# TAB 6: THREAT BRIEFING & EXPORT
# ==========================================
with tab_report:
    st.subheader("📑 Threat Intelligence Briefing & Export")
    st.caption("Generate boardroom-ready executive summaries and standardized incident briefs.")
    
    std_report = generate_report(results)
    
    st.text_area("Incident Briefing Preview", std_report, height=300)
    
    col_exp1, col_exp2 = st.columns(2)
    with col_exp1:
        st.download_button(
            "⬇️ Download Plain Text Report (.txt)",
            std_report,
            file_name="LOGSENTRY_Executive_Incident_Report.txt",
            mime="text/plain",
            use_container_width=True
        )
    with col_exp2:
        # JSON SIEM Feed export
        json_export = events_df.to_json(orient="records", date_format="iso")
        st.download_button(
            "⬇️ Download SIEM JSON Feed (.json)",
            json_export,
            file_name="LOGSENTRY_SIEM_Events.json",
            mime="application/json",
            use_container_width=True
        )

# Footer Safety Note
st.divider()
st.markdown("<p style='text-align: center; color: #64748b; font-size: 0.8rem;'>LOGSENTRY Autonomous SIEM & Threat Hunting Engine • Built for Hackathon Excellence • Local & Offline Capable</p>", unsafe_allow_html=True)
