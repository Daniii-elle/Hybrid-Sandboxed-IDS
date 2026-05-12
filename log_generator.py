"""
Continuous Network Traffic Log Generator
Simulates Zeek logs for testing the IDS system
"""
import json
import time
import random
import os
import sys
from datetime import datetime

def generate_zeek_log():
    """Generate a realistic Zeek connection log entry"""
    ts = time.time()
    duration = round(random.uniform(0.5, 10.0), 2)
    orig_bytes = random.randint(100, 50000)
    resp_bytes = random.randint(100, 100000)
    
    return {
        "ts": ts,
        "uid": f"C{int(ts*1000)}",
        "id.orig_h": f"192.168.1.{random.randint(1, 254)}",
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": f"10.0.0.{random.randint(1, 254)}",
        "id.resp_p": random.choice([80, 443, 22, 21, 25, 53, 3306, 5432]),
        "proto": "tcp",
        "service": random.choice(["http", "ssl", "ssh", "dns"]),
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": "SF",
        "local_orig": True,
        "local_resp": False,
        "missed_bytes": 0,
        "history": "ShADad",
        "orig_pkts": random.randint(5, 100),
        "orig_ip_bytes": orig_bytes + random.randint(100, 500),
        "resp_pkts": random.randint(3, 80),
        "resp_ip_bytes": resp_bytes + random.randint(100, 500),
        "tunnel_parents": []
    }

def generate_suricata_alert():
    """Generate a realistic Suricata alert"""
    ts = datetime.utcnow().isoformat(timespec='microseconds') + '+0000'
    
    signatures = [
        ("ET MALWARE Suspicious HTTP Traffic", 1),
        ("ET MALWARE Suspicious SSL Connection", 2),
        ("ET POLICY Unencrypted FTP Login", 3),
        ("ET SCAN SSH Brute Force Attempt", 2),
        ("ET TROJAN Dridex C2 Checkin", 1),
    ]
    
    sig, severity = random.choice(signatures)
    
    return {
        "timestamp": ts,
        "flow_id": random.randint(100000000, 999999999),
        "event_type": "alert",
        "src_ip": f"192.168.1.{random.randint(1, 254)}",
        "src_port": random.randint(1024, 65535),
        "dest_ip": f"10.0.0.{random.randint(1, 254)}",
        "dest_port": random.choice([80, 443, 22, 21, 25, 53, 3306, 5432]),
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": 1,
            "signature": sig,
            "category": "A Network Trojan was detected",
            "severity": severity
        }
    }

def main():
    """Main generator loop"""
    log_dir = "logs"
    zeek_log = os.path.join(log_dir, "conn.log")
    suricata_log = os.path.join(log_dir, "eve.json")
    
    # Ensure logs directory exists
    os.makedirs(log_dir, exist_ok=True)
    
    print(f"[LOG GENERATOR] Starting continuous log generation...")
    print(f"[LOG GENERATOR] Writing to: {zeek_log} and {suricata_log}")
    print(f"[LOG GENERATOR] New log every 3 seconds (Zeek) and 5 seconds (Suricata)")
    print(f"[LOG GENERATOR] Press Ctrl+C to stop\n")
    
    zeek_counter = 0
    suricata_counter = 0
    start_time = time.time()
    
    try:
        while True:
            current_time = time.time()
            elapsed = current_time - start_time
            
            # Generate Zeek logs every 3 seconds
            if int(elapsed) % 3 == 0 and zeek_counter == 0:
                log_entry = generate_zeek_log()
                with open(zeek_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(log_entry) + "\n")
                zeek_counter = 1
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Zeek log added")
            elif int(elapsed) % 3 != 0:
                zeek_counter = 0
            
            # Generate Suricata alerts every 5 seconds
            if int(elapsed) % 5 == 0 and suricata_counter == 0:
                alert = generate_suricata_alert()
                with open(suricata_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(alert) + "\n")
                suricata_counter = 1
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Suricata alert added")
            elif int(elapsed) % 5 != 0:
                suricata_counter = 0
            
            time.sleep(1)
    
    except KeyboardInterrupt:
        print(f"\n[LOG GENERATOR] Stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"[LOG GENERATOR] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
