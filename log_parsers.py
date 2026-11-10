"""
LOGSENTRY Multi-Format Log Ingestion & Normalizer
Normalizes disparate enterprise log sources into the standard LOGSENTRY schema:
timestamp, ip, event, user
"""

import re
from datetime import datetime
import pandas as pd
import io

def parse_generic_csv(file_or_df):
    """
    Intelligently inspects any CSV, guessing column mapping for
    timestamp, IP, event, and user even if named differently.
    """
    if isinstance(file_or_df, pd.DataFrame):
        df = file_or_df.copy()
    else:
        df = pd.read_csv(file_or_df)
        
    lower_cols = {c.lower().strip(): c for c in df.columns}
    
    # 1. Map Timestamp
    time_candidates = ["timestamp", "datetime", "date_time", "time", "date", "@timestamp", "eventtime"]
    time_col = None
    for cand in time_candidates:
        if cand in lower_cols:
            time_col = lower_cols[cand]
            break
            
    # 2. Map IP
    ip_candidates = ["ip", "src_ip", "source_ip", "client_ip", "ip_address", "host", "source", "client"]
    ip_col = None
    for cand in ip_candidates:
        if cand in lower_cols:
            ip_col = lower_cols[cand]
            break
            
    # 3. Map Event
    event_candidates = ["event", "action", "status", "event_type", "type", "activity", "result"]
    event_col = None
    for cand in event_candidates:
        if cand in lower_cols:
            event_col = lower_cols[cand]
            break
            
    # 4. Map User
    user_candidates = ["user", "username", "account", "user_id", "actor", "target_user"]
    user_col = None
    for cand in user_candidates:
        if cand in lower_cols:
            user_col = lower_cols[cand]
            break
            
    # If all 4 found, project and normalize
    if time_col and ip_col and event_col and user_col:
        norm = pd.DataFrame()
        norm["timestamp"] = df[time_col]
        norm["ip"] = df[ip_col].astype(str)
        norm["event"] = df[event_col].astype(str)
        norm["user"] = df[user_col].astype(str)
        
        # Normalize event verbs
        norm["event"] = norm["event"].apply(normalize_event_verb)
        return True, "Successfully normalized generic CSV", norm
        
    return False, f"Could not map columns. Detected: {list(df.columns)}", df

def normalize_event_verb(val):
    v = str(val).lower().strip()
    if any(k in v for k in ["fail", "invalid", "err", "denied", "block", "401", "403", "4625"]):
        return "failed"
    elif any(k in v for k in ["priv", "sudo", "elevat", "role", "group", "grant", "4672", "4728"]):
        return "privilege_change"
    elif any(k in v for k in ["sensit", "secret", "dump", "export", "confid", "exfil", "db_read", "backup"]):
        return "sensitive_access"
    elif any(k in v for k in ["succ", "ok", "login", "auth", "allow", "200", "4624"]):
        return "success"
    return "success"

def parse_syslog_auth_log(text_data):
    """
    Parses standard Linux /var/log/auth.log or secure lines:
    e.g. 'Nov 10 09:05:00 server sshd[1234]: Failed password for admin from 10.0.0.20 port 22'
    """
    lines = text_data.splitlines()
    rows = []
    
    current_year = datetime.now().year
    failed_re = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)', re.IGNORECASE)
    accepted_re = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+)', re.IGNORECASE)
    sudo_re = re.compile(r'sudo:.* (\S+) : TTY=.*COMMAND=(.*)', re.IGNORECASE)
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Try timestamp prefix "Nov 10 09:05:00"
        ts_part = line[:15]
        try:
            dt = datetime.strptime(f"{current_year} {ts_part}", "%Y %b %d %H:%M:%S")
            ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        m_fail = failed_re.search(line)
        if m_fail:
            user, ip = m_fail.groups()
            rows.append((ts_str, ip, "failed", user))
            continue
            
        m_acc = accepted_re.search(line)
        if m_acc:
            user, ip = m_acc.groups()
            rows.append((ts_str, ip, "success", user))
            continue
            
        m_sudo = sudo_re.search(line)
        if m_sudo:
            user, cmd = m_sudo.groups()
            ip = "127.0.0.1"
            evt = "sensitive_access" if any(x in cmd for x in ["dump", "shadow", "cat /etc", "secret"]) else "privilege_change"
            rows.append((ts_str, ip, evt, user))
            continue
            
    if not rows:
        return False, "No recognizeable Linux auth.log lines found.", None
        
    df = pd.DataFrame(rows, columns=["timestamp", "ip", "event", "user"])
    return True, f"Parsed {len(df)} auth.log entries", df

def parse_apache_nginx_log(text_data):
    """
    Parses Apache / Nginx combined access logs:
    10.0.0.20 - admin [10/Nov/2026:09:05:00 +0000] "POST /api/login HTTP/1.1" 401 128
    """
    lines = text_data.splitlines()
    rows = []
    
    # Combined log regex
    log_pattern = re.compile(r'^(\S+) \S+ (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+)\s*.*?" (\d{3})')
    
    for line in lines:
        line = line.strip()
        m = log_pattern.match(line)
        if m:
            ip, user, time_raw, method, url, status_code = m.groups()
            try:
                # 10/Nov/2026:09:05:00 +0000
                dt = datetime.strptime(time_raw.split()[0], "%d/%b/%Y:%H:%M:%S")
                ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
            username = user if user != "-" else "guest"
            status = int(status_code)
            
            if status in [401, 403]:
                evt = "failed"
            elif any(x in url.lower() for x in ["/admin", "/sudo", "/elevate", "/role"]):
                evt = "privilege_change"
            elif any(x in url.lower() for x in ["/export", "/dump", "/credit_cards", "/database", "/crown_jewels", "/secrets"]):
                evt = "sensitive_access"
            elif status < 400:
                evt = "success"
            else:
                evt = "failed"
                
            rows.append((ts_str, ip, evt, username))
            
    if not rows:
        return False, "No recognizeable Apache/Nginx combined access log lines found.", None
        
    df = pd.DataFrame(rows, columns=["timestamp", "ip", "event", "user"])
    return True, f"Parsed {len(df)} web access log entries", df
