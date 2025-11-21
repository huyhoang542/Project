# -*- coding: utf-8 -*-
import sqlite3
import subprocess
import time
import os
import db_manager 
from subprocess import PIPE 

# ==================== CONFIGURATION ====================
CHECK_INTERVAL_SECONDS = 10 
CRITICAL_SEVERITY_THRESHOLD = 9
AI_LOCK_SEVERITY = 8
# =======================================================

def get_alerts_to_handle():
    """Query DB for alerts that require automated handling (Sev >= 9 or Sev 8 AI) and are unprocessed."""
    conn = sqlite3.connect(db_manager.DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, ip_address, username, detection_type, reason, severity 
        FROM alerts 
        WHERE (severity >= ? OR detection_type = 'AI') AND is_handled IS NULL
    """, (CRITICAL_SEVERITY_THRESHOLD,))
    
    alerts = cursor.fetchall()
    conn.close()
    return alerts

def block_ip(ip_address, alert_id):
    """Execute the iptables command to block the IP."""
    try:
        print(f"BLOCKING IP: {ip_address} (Alert ID: {alert_id})")
        
        # Thêm 'sudo' để đảm bảo quyền root
        subprocess.run(
            ['sudo', 'iptables', '-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP'], 
            check=True
        )
        
        db_manager.update_alert_status(alert_id, 'BLOCKED')
        print(f"   -> Successfully blocked {ip_address} via iptables.")
        
    except subprocess.CalledProcessError as e:
        # Xử lý lỗi nếu lệnh iptables thất bại
        print(f"   -> IPTABLES EXECUTION ERROR: Failed to run block command. Exit Status {e.returncode}. (Check SUDO setup)")
        db_manager.update_alert_status(alert_id, f'BLOCK_FAILED_{e.returncode}')
    except Exception as e:
        print(f"   -> SYSTEM ERROR: {e}")

def lock_user_account(username, alert_id):
    """Locks the system account using usermod -L, handling non-existent users gracefully."""
    try:
        if username in ['N/A', 'root']: 
            db_manager.update_alert_status(alert_id, 'IGNORED_LOCK')
            return

        print(f"LOCKING USER: Attempting to lock account {username} (Alert ID: {alert_id})")
        
        # Thêm 'sudo' để đảm bảo quyền root
        result = subprocess.run(
            ['sudo', 'usermod', '-L', username], 
            stdout=subprocess.PIPE,  
            stderr=subprocess.PIPE,  
            universal_newlines=True, # Tương thích Python 3.6
            check=False 
        )
        
        if result.returncode == 0:
            db_manager.update_alert_status(alert_id, 'LOCKED_USER')
            print(f"   -> Successfully locked account {username}.")
        elif result.returncode == 6:
            # Mã lỗi 6: User không tồn tại 
            db_manager.update_alert_status(alert_id, 'USER_NON_EXISTENT')
            print(f"   -> USER LOCK LOGIC: User '{username}' does not exist (Exit Code 6). Safety check passed.")
        else:
            db_manager.update_alert_status(alert_id, f'LOCK_FAIL_{result.returncode}')
            print(f"   -> USER LOCK ERROR: Failed with exit code {result.returncode}. Output: {result.stderr.strip()}")

    except Exception as e:
        print(f"   -> SYSTEM ERROR: {e}")

def run_response_engine():
    """The main loop for the Response Engine."""
    print("--- Starting Response Engine ---")
    
    db_manager.initialize_db() 
    
    while True:
        alerts_to_handle = get_alerts_to_handle()
        
        if alerts_to_handle:
            print(f"\nFOUND {len(alerts_to_handle)} ALERTS TO HANDLE.")
            for alert_id, ip, username, det_type, reason, severity in alerts_to_handle:
                
                if severity >= CRITICAL_SEVERITY_THRESHOLD:
                    # Xử lý: Chặn IP (Severity 9)
                    block_ip(ip, alert_id)
                
                elif severity == AI_LOCK_SEVERITY and det_type == 'AI' and username is not None:
                    # Xử lý: Khóa User (Severity 8)
                    lock_user_account(username, alert_id)
        
        time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == '__main__':
    run_response_engine()
