"""
LOGSENTRY Core Detection & Machine Learning Engine
Empowered with MITRE ATT&CK correlation, multi-stage kill chain detection,
and Explainable AI (XAI) Isolation Forest.
"""

from collections import defaultdict
from datetime import timedelta, datetime
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import threat_intelligence as ti

REQUIRED = {"timestamp", "ip", "event", "user"}
ALLOWED_EVENTS = {"failed", "success", "privilege_change", "sensitive_access"}

def make_demo_logs():
    """Default demonstration dataset (backward compatible)."""
    rows = [
        ("2026-11-10 09:00:00", "10.0.0.5", "success", "student1"),
        ("2026-11-10 09:01:00", "10.0.0.8", "success", "staff1"),
        ("2026-11-10 09:02:00", "10.0.0.9", "success", "student2"),
        ("2026-11-10 09:03:00", "10.0.0.5", "success", "student1"),
        ("2026-11-10 09:04:00", "10.0.0.8", "success", "staff1"),
        ("2026-11-10 09:05:00", "10.0.0.20", "failed", "admin"),
        ("2026-11-10 09:05:12", "10.0.0.20", "failed", "admin"),
        ("2026-11-10 09:05:24", "10.0.0.20", "failed", "admin"),
        ("2026-11-10 09:05:36", "10.0.0.20", "failed", "admin"),
        ("2026-11-10 09:05:48", "10.0.0.20", "failed", "admin"),
        ("2026-11-10 09:06:02", "10.0.0.20", "success", "admin"),
        ("2026-11-10 09:06:30", "10.0.0.20", "privilege_change", "admin"),
        ("2026-11-10 09:07:00", "10.0.0.20", "sensitive_access", "admin"),
        ("2026-11-10 09:08:00", "10.0.0.11", "success", "student3"),
    ]
    return pd.DataFrame(rows, columns=["timestamp", "ip", "event", "user"])

def validate_logs(frame):
    """Validates dataframe schema and coerces timestamps cleanly."""
    if not isinstance(frame, pd.DataFrame):
        return False, "Input is not a valid dataframe.", None
        
    missing = REQUIRED - set(frame.columns)
    if missing:
        # Check if generic column mapper can resolve it
        from log_parsers import parse_generic_csv
        success, msg, mapped = parse_generic_csv(frame)
        if success:
            data = mapped
        else:
            return False, "Missing required columns: " + ", ".join(sorted(missing)), None
    else:
        data = frame.copy()
        
    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce")
    if data["timestamp"].isna().any():
        return False, "Some timestamps could not be read. Please use standard ISO format (e.g. 2026-11-10 09:05:12).", None
        
    for col in ["ip", "event", "user"]:
        data[col] = data[col].astype(str).str.strip()
    data["event"] = data["event"].str.lower()
    
    unknown = sorted(set(data["event"]) - ALLOWED_EVENTS)
    if unknown:
        return False, "Unknown event value(s): " + ", ".join(unknown) + ". Allowed: " + ", ".join(sorted(ALLOWED_EVENTS)), None
        
    data = data.sort_values("timestamp").reset_index(drop=True)
    return True, "OK", data

def extract_ip_features(df):
    """Calculates rich statistical security features for each IP address."""
    ips = sorted(df["ip"].unique())
    features = pd.DataFrame(index=ips)
    
    # Event counts
    features["total_events"] = df.groupby("ip").size()
    features["failed_events"] = df[df["event"] == "failed"].groupby("ip").size()
    features["success_events"] = df[df["event"] == "success"].groupby("ip").size()
    features["privilege_changes"] = df[df["event"] == "privilege_change"].groupby("ip").size()
    features["sensitive_access"] = df[df["event"] == "sensitive_access"].groupby("ip").size()
    features = features.fillna(0)
    
    # Failure ratio
    features["failure_ratio"] = features["failed_events"] / (features["total_events"] + 1e-5)
    
    # Unique accounts targeted
    features["unique_users_targeted"] = df.groupby("ip")["user"].nunique()
    
    # Event velocity (events per minute)
    velocities = {}
    for ip, group in df.groupby("ip"):
        if len(group) <= 1:
            velocities[ip] = 0.0
        else:
            time_span_sec = max((group["timestamp"].max() - group["timestamp"].min()).total_seconds(), 1.0)
            velocities[ip] = len(group) / (time_span_sec / 60.0)
    features["events_per_minute"] = pd.Series(velocities)
    
    return features.fillna(0)

def add_ml_anomalies(data):
    """
    Trains an Isolation Forest on multi-dimensional security features.
    Provides continuous anomaly scores and per-IP feature contribution explanations.
    """
    df = data.copy()
    features = extract_ip_features(df)
    
    anomaly_ips = set()
    ip_ml_scores = {}
    ip_ml_reasons = {}
    
    # Minimum cluster size needed for unsupervised learning
    if len(features) >= 4 and features.nunique().max() > 1:
        contamination_rate = min(max(0.15, 1.0 / len(features)), 0.35)
        model = IsolationForest(n_estimators=100, contamination=contamination_rate, random_state=42)
        
        feature_cols = ["total_events", "failed_events", "privilege_changes", "sensitive_access", 
                        "failure_ratio", "unique_users_targeted", "events_per_minute"]
        X = features[feature_cols]
        
        model.fit(X)
        preds = model.predict(X)
        scores = model.decision_function(X) # lower score means more anomalous
        
        # Calculate baseline means for explainability
        means = X.mean()
        stds = X.std().replace(0, 1)
        
        for ip, pred, score in zip(features.index, preds, scores):
            # Normalized score from 0 (normal) to 100 (extreme anomaly)
            normalized_score = max(0, min(100, int((0.2 - score) * 150)))
            ip_ml_scores[ip] = normalized_score
            
            if pred == -1 or score < 0.0:
                anomaly_ips.add(ip)
                # Determine top contributing features
                row = X.loc[ip]
                z_scores = (row - means) / stds
                top_deviations = z_scores.sort_values(ascending=False)
                
                reasons = []
                for feat, z in top_deviations.head(2).items():
                    if z > 1.2:
                        val = row[feat]
                        feat_clean = feat.replace("_", " ").title()
                        reasons.append(f"{feat_clean} ({val:.1f}) is {z:.1f}σ above baseline")
                if not reasons:
                    reasons.append("Multi-dimensional behavioral deviation across authentication and privilege metrics")
                ip_ml_reasons[ip] = reasons
            else:
                ip_ml_reasons[ip] = ["Behavioral profile aligns with standard baseline clusters"]
    else:
        for ip in features.index:
            ip_ml_scores[ip] = 10
            ip_ml_reasons[ip] = ["Dataset has insufficient IP diversity for statistical ML baseline"]
            
    df["ml_anomaly"] = df["ip"].isin(anomaly_ips)
    df["ml_score"] = df["ip"].map(ip_ml_scores).fillna(0)
    return df, ip_ml_scores, ip_ml_reasons

def analyze_logs(data, failure_threshold=5, window_minutes=2):
    """
    Advanced SIEM Correlation Engine:
    Correlates multi-stage cyber kill chain indicators, distributed attacks,
    insider threats, and ML anomaly signals.
    """
    df, ip_ml_scores, ip_ml_reasons = add_ml_anomalies(data)
    df["rule_alert"] = False
    incidents = []
    
    # 1. Check for Distributed Password Spraying across multiple IPs
    # If the same account experiences failed logins from >= 3 different IPs within 10 mins
    user_failures = defaultdict(list)
    for idx, row in df[df["event"] == "failed"].iterrows():
        user_failures[row["user"]].append(row)
        
    sprayed_users = set()
    for user, rows in user_failures.items():
        if len(rows) >= 3:
            user_df = pd.DataFrame(rows)
            unique_ips = user_df["ip"].nunique()
            if unique_ips >= 3:
                sprayed_users.add(user)
                # Create a distributed incident if significant
                evidence = [
                    f"Target account '{user}' experienced distributed login failures from {unique_ips} distinct IPs.",
                    f"Source IPs involved in spray: {', '.join(user_df['ip'].unique()[:5])}",
                    "Adversaries cycle IPs to circumvent single-host rate limiting."
                ]
                incidents.append({
                    "ip": f"Distributed ({unique_ips} IPs)",
                    "target_user": user,
                    "risk_score": 85,
                    "severity": "High",
                    "title": f"Distributed Password Spraying against '{user}'",
                    "summary": f"LOGSENTRY detected a coordinated botnet or proxy spray attacking account '{user}'.",
                    "evidence": evidence,
                    "mitre": [ti.MITRE_TECHNIQUES["T1110.003"], ti.MITRE_TECHNIQUES["T1087"]],
                    "kill_chain": "2. Credential Access",
                    "recommendations": [
                        f"Enforce mandatory Multi-Factor Authentication (MFA) immediately on account '{user}'.",
                        "Enable intelligent geo-blocking or CAPTCHA triggers on repeated cross-IP failures.",
                        "Inspect corporate credential leak dumps (HaveIBeenPwned API) for compromised passwords."
                    ]
                })

    # 2. Per-IP Correlation Analysis
    for ip, group in df.groupby("ip"):
        group = group.sort_values("timestamp")
        failed_rows = group[group["event"] == "failed"]
        success_rows = group[group["event"] == "success"]
        privilege_rows = group[group["event"] == "privilege_change"]
        sensitive_rows = group[group["event"] == "sensitive_access"]
        
        # Sliding time window: 5+ failed logins within window
        brute_force = False
        bf_details = ""
        for _, row in failed_rows.iterrows():
            window_end = row["timestamp"] + timedelta(minutes=window_minutes)
            count = ((failed_rows["timestamp"] >= row["timestamp"]) &
                     (failed_rows["timestamp"] <= window_end)).sum()
            if count >= failure_threshold:
                brute_force = True
                bf_details = f"{count} failed logins within a {window_minutes}-minute sliding window"
                break
                
        # Compromised account transition: failures followed by success
        success_after_failures = False
        if brute_force and not success_rows.empty:
            first_success = success_rows["timestamp"].min()
            earlier_failures = failed_rows[failed_rows["timestamp"] < first_success]
            success_after_failures = len(earlier_failures) >= failure_threshold
            
        has_privilege = not privilege_rows.empty
        has_sensitive = not sensitive_rows.empty
        unique_users_targeted = group["user"].nunique()
        account_enumeration = (len(failed_rows) >= 3 and unique_users_targeted >= 3)
        
        # High velocity automation check (> 2 requests/sec)
        high_velocity = False
        if len(group) >= 6:
            duration = (group["timestamp"].max() - group["timestamp"].min()).total_seconds()
            if duration > 0 and (len(group) / duration) >= 0.5:
                high_velocity = True
                
        # Insider threat pattern: zero failures, but privilege change + sensitive access
        insider_threat_pattern = (len(failed_rows) == 0 and has_privilege and has_sensitive)
        
        # Scoring logic
        score = 0
        evidence = []
        mitre_tags = []
        
        if brute_force:
            score += 30
            evidence.append(f"Brute-force authentication velocity detected: {bf_details}.")
            mitre_tags.append(ti.MITRE_TECHNIQUES["T1110.001"])
            
        if success_after_failures:
            score += 30
            evidence.append("Account compromise transition: A successful authentication succeeded repeated brute-force failures.")
            mitre_tags.append(ti.MITRE_TECHNIQUES["T1078"])
            
        if has_privilege:
            score += 25
            evidence.append("Privilege escalation: Account executed administrative / privilege change operations.")
            mitre_tags.append(ti.MITRE_TECHNIQUES["T1098"])
            
        if has_sensitive:
            score += 20
            evidence.append("Crown jewel access: Confidential databases or sensitive resources were directly accessed.")
            mitre_tags.append(ti.MITRE_TECHNIQUES["T1530"])
            
        if account_enumeration:
            score += 15
            evidence.append(f"Account discovery / enumeration: Targeted {unique_users_targeted} different usernames.")
            mitre_tags.append(ti.MITRE_TECHNIQUES["T1087"])
            
        if high_velocity:
            score += 10
            evidence.append("High-velocity automated burst pattern indicates programmatic bot/script execution.")
            
        if insider_threat_pattern:
            score += 35
            evidence.append("Anomalous high-privilege access pattern without antecedent failures (Potential Insider Threat).")
            
        is_ml_flagged = ip in set(df.loc[df["ml_anomaly"], "ip"])
        if is_ml_flagged:
            reasons = ip_ml_reasons.get(ip, ["Isolation Forest algorithm flagged multi-feature anomaly."])
            evidence.append("Isolation Forest ML Engine marked activity as statistically anomalous: " + "; ".join(reasons))
            if score > 0:
                score += 10  # Corroborate rule violations with ML anomaly signal

        # Only promote to an incident if at least one actionable rule triggered or score >= 20
        if score >= 20:
            final_score = min(score, 100)
            if final_score >= 70:
                severity = "Critical" if (has_privilege and has_sensitive) else "High"
                title = "Multi-Stage Cyber Kill Chain Intrusion" if (brute_force and has_privilege and has_sensitive) else "High-Risk Account Takeover & Escalation"
            elif final_score >= 40:
                severity = "Medium"
                title = "Brute-Force Credential Attack" if brute_force else "Suspicious Access Anomaly"
            else:
                severity = "Low"
                title = "Low-Severity Security Event"
                
            targeted_users = list(group["user"].unique())
            recommendations = [
                f"Isolate host / block inbound network traffic from {ip} across edge firewalls.",
                f"Immediately expire active sessions and force credential resets for targeted account(s): {', '.join(targeted_users[:3])}.",
                "Inspect database/application audit logs to ascertain whether data exfiltration occurred.",
                "Preserve volatile forensic logs and report incident to Information Security Incident Response Team (CSIRT)."
            ]
            
            kill_chain = "5. Actions on Objectives" if has_sensitive else ("4. Privilege Escalation" if has_privilege else ("3. Initial Access" if success_after_failures else "2. Credential Access"))
            
            incidents.append({
                "ip": ip,
                "target_user": ", ".join(targeted_users[:3]),
                "risk_score": final_score,
                "severity": severity,
                "title": title,
                "summary": f"LOGSENTRY assigned {final_score}/100 risk points based on {len(evidence)} verified threat signals across the cyber kill chain.",
                "evidence": evidence,
                "mitre": mitre_tags,
                "kill_chain": kill_chain,
                "recommendations": recommendations
            })
            df.loc[df["ip"] == ip, "rule_alert"] = True
            
    incidents.sort(key=lambda x: x["risk_score"], reverse=True)
    return {"events": df, "incidents": incidents, "ml_scores": ip_ml_scores, "ml_reasons": ip_ml_reasons}

def generate_report(results):
    """Generates standard incident report text (backward compatible)."""
    lines = [
        "=======================================================",
        "           LOGSENTRY SECURITY INCIDENT REPORT          ",
        "=======================================================",
        f"Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Events Analyzed: {len(results['events'])}",
        f"Unique Source IPs: {results['events']['ip'].nunique()}",
        f"Total Incidents Detected: {len(results['incidents'])}",
        "=======================================================",
        ""
    ]
    for n, incident in enumerate(results["incidents"], 1):
        lines += [
            f"[{n}] {incident['title'].upper()}",
            f"Source IP: {incident['ip']}",
            f"Target Account(s): {incident.get('target_user', 'N/A')}",
            f"Calculated Risk Score: {incident['risk_score']}/100 ({incident['severity']})",
            f"Kill Chain Stage: {incident.get('kill_chain', 'N/A')}",
            f"Summary: {incident['summary']}",
            "",
            "Forensic Evidence:"
        ]
        lines += ["  - " + x for x in incident["evidence"]]
        
        if incident.get("mitre"):
            lines.append("Mapped MITRE ATT&CK Techniques:")
            for m in incident["mitre"]:
                lines.append(f"  * [{m['id']}] {m['name']} (Tactic: {m['tactic']})")
                
        lines.append("Recommended SOAR Remediation Actions:")
        lines += ["  * " + x for x in incident["recommendations"]]
        lines.append("-" * 55)
        lines.append("")
        
    return "\n".join(lines)
