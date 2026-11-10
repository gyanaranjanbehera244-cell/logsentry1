"""
LOGSENTRY Realistic Threat Scenario Generator
Generates high-fidelity cybersecurity attack scenarios for live hackathon demonstrations.
"""

from datetime import datetime, timedelta
import pandas as pd
import numpy as np

def generate_apt_multistage_scenario():
    """
    Scenario 1: Full Cyber Kill Chain APT Attack
    An external attacker (10.0.0.20) scans, brute-forces admin, succeeds,
    escalates privileges, and exfiltrates confidential database data.
    Accompanied by normal background baseline traffic.
    """
    base_time = datetime(2026, 11, 10, 9, 0, 0)
    rows = []
    
    # Benign normal user activity
    users = ["alice_eng", "bob_sales", "carol_hr", "dave_dev", "elena_fin", "frank_ops"]
    benign_ips = ["192.168.1.10", "192.168.1.15", "192.168.1.22", "192.168.1.33", "192.168.1.45"]
    
    for i in range(25):
        t = base_time + timedelta(seconds=i * 20)
        u = users[i % len(users)]
        ip = benign_ips[i % len(benign_ips)]
        rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), ip, "success", u))
        
    # Occasional normal typo login failure
    rows.append(((base_time + timedelta(minutes=3, seconds=10)).strftime("%Y-%m-%d %H:%M:%S"), "192.168.1.15", "failed", "bob_sales"))
    rows.append(((base_time + timedelta(minutes=3, seconds=25)).strftime("%Y-%m-%d %H:%M:%S"), "192.168.1.15", "success", "bob_sales"))

    # Attack Sequence from 10.0.0.20 (Attacker)
    attack_start = base_time + timedelta(minutes=5)
    for idx, sec in enumerate([0, 11, 23, 34, 45, 58, 69]):
        t = attack_start + timedelta(seconds=sec)
        rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), "10.0.0.20", "failed", "admin"))
        
    # Attacker hits the right credential
    t_success = attack_start + timedelta(seconds=82)
    rows.append((t_success.strftime("%Y-%m-%d %H:%M:%S"), "10.0.0.20", "success", "admin"))
    
    # Privilege Escalation
    t_priv = attack_start + timedelta(seconds=115)
    rows.append((t_priv.strftime("%Y-%m-%d %H:%M:%S"), "10.0.0.20", "privilege_change", "admin"))
    
    # Sensitive Database Crown Jewel Exfiltration
    t_sens1 = attack_start + timedelta(seconds=145)
    rows.append((t_sens1.strftime("%Y-%m-%d %H:%M:%S"), "10.0.0.20", "sensitive_access", "admin"))
    t_sens2 = attack_start + timedelta(seconds=170)
    rows.append((t_sens2.strftime("%Y-%m-%d %H:%M:%S"), "10.0.0.20", "sensitive_access", "admin"))
    
    # More background traffic
    for i in range(10):
        t = attack_start + timedelta(seconds=180 + i * 15)
        u = users[i % len(users)]
        ip = benign_ips[i % len(benign_ips)]
        rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), ip, "success", u))

    df = pd.DataFrame(rows, columns=["timestamp", "ip", "event", "user"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df

def generate_password_spraying_scenario():
    """
    Scenario 2: Distributed Password Spraying Attack (Botnet)
    An attacker rotates across 8 distinct IP addresses to test 1 password
    against multiple target executives, evading standard per-IP rate limiters.
    """
    base_time = datetime(2026, 11, 10, 14, 0, 0)
    rows = []
    
    spray_ips = [f"198.51.100.{10 + i}" for i in range(8)]
    targets = ["ceo_office", "cfo_finance", "vp_engineering", "hr_director", "sec_admin", "devops_lead"]
    
    # Benign baseline
    for i in range(20):
        t = base_time + timedelta(seconds=i * 25)
        rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), f"10.10.1.{i%5 + 1}", "success", f"staff_member_{i%5}"))
        
    # Password spray wave 1
    t_wave1 = base_time + timedelta(minutes=2)
    for idx, (ip, user) in enumerate(zip(spray_ips, targets * 2)):
        t = t_wave1 + timedelta(seconds=idx * 6)
        rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), ip, "failed", user))
        
    # Botnet IP 198.51.100.14 compromises sec_admin on second wave
    t_wave2 = base_time + timedelta(minutes=3, seconds=30)
    for idx, (ip, user) in enumerate(zip(spray_ips, reversed(targets * 2))):
        t = t_wave2 + timedelta(seconds=idx * 7)
        if ip == "198.51.100.14" and user == "sec_admin":
            rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), ip, "success", user))
            rows.append(((t + timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S"), ip, "privilege_change", user))
            rows.append(((t + timedelta(seconds=35)).strftime("%Y-%m-%d %H:%M:%S"), ip, "sensitive_access", user))
        else:
            rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), ip, "failed", user))
            
    df = pd.DataFrame(rows, columns=["timestamp", "ip", "event", "user"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df

def generate_insider_threat_scenario():
    """
    Scenario 3: Malicious Insider Threat
    A trusted internal workstation (10.0.50.4) operated by a departing contractor/employee.
    No brute force failures! Valid login, immediate unapproved privilege change,
    followed by multiple high-velocity sensitive data access events off-hours (03:15 AM).
    """
    base_time = datetime(2026, 11, 10, 3, 15, 0)
    rows = []
    
    # Dormant night baseline
    rows.append(((base_time - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"), "10.0.0.1", "success", "backup_service"))
    rows.append(((base_time - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"), "10.0.0.2", "success", "healthcheck_agent"))
    
    # Insider logs in normally (no password failures)
    insider_ip = "10.0.50.4"
    insider_user = "contractor_mike"
    
    rows.append((base_time.strftime("%Y-%m-%d %H:%M:%S"), insider_ip, "success", insider_user))
    rows.append(((base_time + timedelta(seconds=20)).strftime("%Y-%m-%d %H:%M:%S"), insider_ip, "privilege_change", insider_user))
    
    # Repeated bulk access to crown jewels
    for sec in [40, 55, 70, 90, 115, 140]:
        t = base_time + timedelta(seconds=sec)
        rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), insider_ip, "sensitive_access", insider_user))
        
    df = pd.DataFrame(rows, columns=["timestamp", "ip", "event", "user"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df

def generate_credential_stuffing_scenario():
    """
    Scenario 4: High-Velocity Credential Stuffing
    An automated adversary fires hundreds of stolen credentials from a bulletproof proxy.
    Demonstrates ML anomaly detection on velocity and failure clustering.
    """
    base_time = datetime(2026, 11, 10, 11, 0, 0)
    rows = []
    
    # Benign traffic
    for i in range(15):
        t = base_time + timedelta(seconds=i * 12)
        rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), f"172.16.0.{i%6+1}", "success", f"emp_{i}"))
        
    # Attack burst from 203.0.113.88
    stuffer_ip = "203.0.113.88"
    t_burst = base_time + timedelta(minutes=1)
    
    compromised_accounts = [f"acc_{k}" for k in range(1, 19)]
    for i, acc in enumerate(compromised_accounts):
        t = t_burst + timedelta(seconds=i * 3)
        # 17 failures, then 1 lucky success
        if i == 14:
            rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), stuffer_ip, "success", acc))
        else:
            rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), stuffer_ip, "failed", acc))
            
    df = pd.DataFrame(rows, columns=["timestamp", "ip", "event", "user"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df

def generate_clean_baseline_scenario():
    """
    Scenario 5: Clean Enterprise Baseline (Testing False Positive Suppression)
    Normal campus / office traffic with healthy success ratios and occasional human typos.
    """
    base_time = datetime(2026, 11, 10, 9, 30, 0)
    rows = []
    
    users = ["alice", "bob", "charlie", "david", "emma", "frank", "grace", "heidi"]
    ips = [f"192.168.10.{i+1}" for i in range(8)]
    
    for i in range(40):
        t = base_time + timedelta(seconds=i * 15)
        user = users[i % len(users)]
        ip = ips[i % len(ips)]
        # 95% success, 5% solitary human typo
        if i in [7, 23]:
            rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), ip, "failed", user))
            rows.append(((t + timedelta(seconds=12)).strftime("%Y-%m-%d %H:%M:%S"), ip, "success", user))
        else:
            rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), ip, "success", user))
            
    df = pd.DataFrame(rows, columns=["timestamp", "ip", "event", "user"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df
