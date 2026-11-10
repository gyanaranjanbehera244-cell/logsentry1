# 🛡️ LOGSENTRY — Enterprise AI SOC & Autonomous Incident Response Platform

> ** Cybersecurity Prototype for Hackathons**  
> Hybrid SIEM Engine combining MITRE ATT&CK Matrix Correlation, Multi-Stage Cyber Kill Chain Analytics, Explainable Machine Learning (Isolation Forest), and Automated SOAR Remediation.

---

## 🌟 Executive Summary

Traditional Security Information and Event Management (SIEM) systems suffer from alert fatigue, rigid rules, and slow response times. **LOGSENTRY** bridges the gap between rule-based intrusion detection and modern machine learning by correlating multi-stage attack patterns in sub-second time without external cloud dependencies.

LOGSENTRY operates **100% locally and offline**, protecting sensitive enterprise telemetry while delivering actionable, explainable threat intelligence.

---

## ✨ Key Capabilities & Innovation

### 1. ⚔️ Cyber Kill Chain & MITRE ATT&CK Mapping
- Maps raw authentication and access logs to standardized MITRE ATT&CK tactics and techniques:
  - **T1110.001**: Password Guessing (Brute Force)
  - **T1110.003**: Distributed Password Spraying across Botnets
  - **T1078**: Valid Accounts (Compromised Credential Abuse)
  - **T1098**: Account Manipulation (Privilege Escalation)
  - **T1530**: Data from Cloud / Crown Jewels Exfiltration
  - **T1087**: Account Discovery & Enumeration
- Visualizes progression across the 5 Kill Chain phases in real time.

### 2. 🧠 Dual-Engine Hybrid AI / ML Architecture
- **Rule-Based Correlation**: Sliding-window temporal correlation to track attacker state transitions (`failed` ➔ `success` ➔ `privilege_change` ➔ `sensitive_access`).
- **Unsupervised Machine Learning (Isolation Forest)**: Analyzes multi-dimensional feature vectors (velocity, failure ratios, privilege frequency, account targeting) to isolate anomalous behavioral outliers.
- **Explainable AI (XAI)**: Decomposes anomaly decisions into plain-English root causes (e.g. *"Velocity 5.2σ above baseline; failure ratio 85%"*).

### 3. ⚡ SOAR (Security Orchestration, Automation and Response)
- **1-Click Perimeter Containment**: Auto-generates exact, production-ready blocking commands for:
  - Linux `iptables` & `nftables`
  - Windows Defender Firewall (PowerShell)
  - AWS VPC Network ACL (NACL)
  - Cloudflare Edge WAF Rules
- **Sigma Rule Generation**: Automatically exports standardized Sigma detection rules (YAML) for Splunk, Elastic, Sentinel, and QRadar.
- **Automated Incident Tickets**: Produces pre-formatted Jira / ServiceNow escalation tickets.

### 4. 🎯 Realistic Multi-Scenario Simulator
Includes 5 pre-built, high-fidelity threat scenarios ready for live hackathon demos:
1. **APT Multi-Stage Intrusion (Recommended Demo)**: Full kill-chain breach from initial brute-force to crown jewel database access.
2. **Distributed Botnet Password Spray**: 8 rotating IPs targeting executive accounts to bypass single-host rate limiters.
3. **Malicious Insider Threat**: Legitimate employee credentials escalating privileges at 03:15 AM with bulk data extraction.
4. **Credential Stuffing Surge**: High-velocity automated credential dumps.
5. **Clean Enterprise Baseline**: 0 false positives under normal office working conditions.

### 5. 📥 Multi-Source Log Ingestion
- Standard or messy CSVs (with smart column auto-detection)
- Linux `/var/log/auth.log` (Syslog / SSH)
- Apache / Nginx Combined Web Access Logs

---

## 🚀 Quick Start Guide (Windows)

### Option A: 1-Click Launch (Easiest)
Double-click `START_LOGSENTRY.bat` in the root folder. It will launch the SOC platform and open your browser automatically!

### Option B: Terminal Launch
```bash
cd "LOGSENTRY_hackathon_starter\LOGSENTRY"
.\.venv\Scripts\streamlit run app.py
```
Open **http://localhost:8501** in your browser.

---OPEN https://sun-blowing-doctrine-forecasts.trycloudflare.com/



## 🔒 Security & Privacy Notice
LOGSENTRY executes completely offline on local compute. No telemetry or log content is sent to third-party APIs.







