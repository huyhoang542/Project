# -*- coding: utf-8 -*-
import json
import time
import os
import re
from datetime import datetime, timedelta
import db_manager 
import ai_detect 
import notifier_email
import requests

# ==================== CONFIGURATION ====================
LOG_FILE_PATH = '/var/log/secure'
CONFIG_PATH = 'config/rules.json'
OFFSET_FILE = 'data/secure_offset.txt'
# =======================================================

# Regex để khớp với định dạng log CentOS 7 SSHD
SSH_PATTERN = re.compile(
    r'(?P<Timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<Hostname>.*?)\s+'  
    r'sshd\[\d+\]:\s+'
    r'(?P<Status>Accepted|Failed)\s+password\s+for\s+'
    r'(?:invalid user\s+)?(?P<Username>\w+)\s+from\s+'
    r'(?P<IP_Address>[\d\.]+)\s+port\s+'
)

def lookup_country(ip):
    """Sử dụng API miễn phí để tra cứu quốc gia của IP (GeoIP Lite)."""
    if ip in ['127.0.0.1', '::1', '0.0.0.0']:
        return "LOCAL"
    
    try:
        response = requests.get(f"http://ipinfo.io/{ip}/country", timeout=1)
        if response.status_code == 200:
            country_code = response.text.strip()
            return country_code 
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"

def load_config():
    """Loads configuration from rules.json file."""
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise Exception(f"CONFIG ERROR: Failed to load {CONFIG_PATH}. {e}")

def get_new_log_entries(log_path, offset_path):
    """Reads new log lines using file offset (mimicking tail -f)."""
    current_offset = 0
    if os.path.exists(offset_path):
        with open(offset_path, 'r') as f:
            content = f.read().strip()
            if content:
                try:
                    current_offset = int(content)
                except ValueError:
                    current_offset = 0 
    
    if not os.path.exists(log_path):
        print(f"LOG READ ERROR: File not found at {log_path}")
        return []

    try:
        with open(log_path, 'r') as f:
            f.seek(current_offset)
            new_entries = f.readlines()
            new_offset = f.tell()
            
            if new_entries:
                print(f"DEBUG: Read {len(new_entries)} new log entries.") 

            with open(offset_path, 'w') as of:
                of.write(str(new_offset))
            
            return new_entries
            
    except Exception as e:
        print(f"LOG READ ERROR (Non-fatal): Error: {e}. Attempting to reset offset.")
        with open(offset_path, 'w') as of:
            of.write('0')
        return []

def check_rules(entry, config):
    """Checks the rules defined in the config for a single log entry."""
    
    print(f"DEBUG: Processing entry: {entry.strip()}") 
    
    match = SSH_PATTERN.search(entry)
    if not match:
        return None, None 
    
    data = match.groupdict()
    ip = data['IP_Address']
    country = lookup_country(ip)
    user = data['Username']
    status = 'SUCCESS' if data['Status'] == 'Accepted' else 'FAILED'
    
    entry_data = {'ip_address': ip, 'username': user, 'status': status}

    # 1. WHITELIST RULE (Skip entirely)
    if ip in config['ip_whitelist'] or user in config['user_whitelist']:
        return None, None 

    # 2. TIME WINDOW RULE (Outside working hours)
    current_time = datetime.now() 
    start_time = datetime.strptime(config['time_window']['start'], '%H:%M').time()
    end_time = datetime.strptime(config['time_window']['end'], '%H:%M').time()

    if status == 'SUCCESS' and (current_time.time() < start_time or current_time.time() > end_time):
        alert_to_insert = {
            'ip_address': ip, 'username': user, 'detection_type': 'RULE-BASED',
            'reason': f'Successful login outside working hours from Country: {country}',
            'severity': 7
        }
        return alert_to_insert, entry_data

    # 3. BRUTE FORCE RULE (Advanced check for failures)
    if status == 'FAILED':
        
        threshold_attempts = config['brute_force_threshold']['attempts']
        threshold_minutes = config['brute_force_threshold']['time_span_minutes']
        
        recent_failures = db_manager.count_recent_failures(ip, threshold_minutes)
        
        if recent_failures >= (threshold_attempts - 1): 
            # CRITICAL ALERT (Severity 9)
            critical_alert = {
                'ip_address': ip, 'username': 'N/A', 'detection_type': 'RULE-BASED',
                'reason': f'CRITICAL: Brute force ({recent_failures + 1} attempts) detected in last {threshold_minutes} min from Country: {country}. Triggering BLOCK.',
                'severity': 9 
            }
            return critical_alert, entry_data

        else:
            # Basic Failure Logging (Severity 3)
            basic_alert = {
                'ip_address': ip, 'username': user, 'detection_type': 'RULE-BASED',
                'reason': f'Failed login attempt for user: {user} from Country: {country}.',
                'severity': 3
            }
            # TRẢ VỀ CẢNH BÁO SE
