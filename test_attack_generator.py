"""
=============================================================
  Hybrid Sandboxed IDS — Live Attack Simulation
  Final Year Project Demonstration Script
  
  Simulates realistic smart grid / network attack scenarios
  to demonstrate the full IDS detection pipeline:
  
  [Attack Generator] → [Zeek Log] → [Isolation Forest]
       → [Docker Sandbox] → [VirusTotal] → [ELK/Kibana] → [Email Report]
=============================================================
"""

import json
import time
import os
import random
from datetime import datetime

# ── Configuration ─────────────────────────────────────────
ZEEK_LOG       = "logs/conn.log"
INTERVAL       = 5      # seconds between each injected attack
REPEAT_CYCLES  = 1      # how many times to loop through all attacks

# Each attack maps to realistic SCADA / smart grid threat patterns.

ATTACK_SCENARIOS = [
    {
        "name": "DDoS Flood",
        "description": "Distributed Denial of Service.... Massive packet flood targeting smart grid SCADA server",
        "duration": 0.5,
        "orig_bytes": 950000,   # ~950KB — far above threshold
        "resp_bytes": 800000,
        "dest_port": 502,       # Modbus protocol (smart grid)
        "proto": "tcp",
        "severity": "CRITICAL"
    },
    {
        "name": "Data Exfiltration",
        "description": "Slow, persistent outbound data leak. Attacker stealing grid sensor readings",
        "duration": 3600.0,     # 1-hour connection (far above threshold)
        "orig_bytes": 850000,
        "resp_bytes": 500,
        "dest_port": 443,
        "proto": "tcp",
        "severity": "CRITICAL"
    },
    {
        "name": "SCADA Command Injection",
        "description": "Malicious Modbus commands injected to manipulate smart grid actuators",
        "duration": 12.5,
        "orig_bytes": 75000,
        "resp_bytes": 120000,
        "dest_port": 502,       # Modbus
        "proto": "tcp",
        "severity": "CRITICAL"
    },
    {
        "name": "IEC 61850 Protocol Abuse",
        "description": "Attacker exploiting IEC 61850 substation protocol, common smart grid vector",
        "duration": 45.0,
        "orig_bytes": 200000,
        "resp_bytes": 180000,
        "dest_port": 102,       # IEC 61850
        "proto": "tcp",
        "severity": "HIGH"
    },
    {
        "name": "SSH Brute Force",
        "description": "Repeated SSH login attempts targeting grid management server",
        "duration": 0.2,
        "orig_bytes": 15000,
        "resp_bytes": 12000,
        "dest_port": 22,
        "proto": "tcp",
        "severity": "HIGH"
    },
    {
        "name": "DNS Tunnelling",
        "description": "Covert C2 channel hidden inside DNS queries. Malware communicating out",
        "duration": 180.0,
        "orig_bytes": 500000,
        "resp_bytes": 300000,
        "dest_port": 53,
        "proto": "udp",
        "severity": "HIGH"
    },
    {
        "name": "Port Scan Reconnaissance",
        "description": "Attacker scanning grid network to map connected devices before attack",
        "duration": 0.001,
        "orig_bytes": 0,
        "resp_bytes": 0,
        "dest_port": random.randint(1, 1024),
        "proto": "tcp",
        "severity": "MEDIUM"
    },
    {
        "name": "Ransomware C2 Beacon",
        "description": "Infected host beaconing to ransomware command & control server",
        "duration": 8.0,
        "orig_bytes": 50000,
        "resp_bytes": 45000,
        "dest_port": 443,
        "proto": "tcp",
        "severity": "CRITICAL"
    },
    {
        "name": "Man-in-the-Middle (ARP Spoof)",
        "description": "Attacker intercepting communications between grid sensors and controller",
        "duration": 300.0,
        "orig_bytes": 400000,
        "resp_bytes": 400000,
        "dest_port": 80,
        "proto": "tcp",
        "severity": "CRITICAL"
    },
    {
        "name": "Zero-Day Exploit Attempt",
        "description": "Unknown vulnerability exploitation! Anomalous payload targeting grid firmware",
        "duration": 25.0,
        "orig_bytes": 999999,
        "resp_bytes": 888888,
        "dest_port": 102,       # IEC 61850
        "proto": "tcp",
        "severity": "CRITICAL"
    },
]

# ── Colour Output for Terminal ─────────────────────────────
COLOURS = {
    "CRITICAL": "\033[91m",   # Red
    "HIGH":     "\033[93m",   # Yellow
    "MEDIUM":   "\033[94m",   # Blue
    "OK":       "\033[92m",   # Green
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "CYAN":     "\033[96m",
}

def c(colour, text):
    return f"{COLOURS.get(colour, '')}{text}{COLOURS['RESET']}"

def print_banner():
    print(c("BOLD", """
╔══════════════════════════════════════════════════════════╗
║     HYBRID SANDBOXED IDS — LIVE ATTACK SIMULATION        ║
║     Smart Grid Zero-Day Threat Detection Demonstration   ║
╚══════════════════════════════════════════════════════════╝
    """))
    print(c("CYAN", "  Pipeline: Attack → Zeek Log → Isolation Forest"))
    print(c("CYAN", "            → Docker Sandbox → VirusTotal → ELK\n"))
    print(f"  Log target : {ZEEK_LOG}")
    print(f"  Scenarios  : {len(ATTACK_SCENARIOS)} attack types")
    print(f"  Interval   : {INTERVAL}s between injections")
    print(f"  Cycles     : {REPEAT_CYCLES}\n")
    print("─" * 60)
    print(c("OK", " Make sure ids_full_system.py is running in Terminal 1"))
    print(c("OK", " Make sure Kibana is open at http://localhost:5601"))
    print("─" * 60)
    input("\n  Press ENTER to begin simulation...\n")


def build_zeek_entry(scenario):
    """Convert attack scenario into Zeek conn.log JSON format"""
    return {
        "ts": time.time(),
        "uid": f"C{int(time.time())}{random.randint(1000, 9999)}",
        "id.orig_h": f"192.168.1.{random.randint(1, 254)}",
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": f"10.0.0.{random.randint(1, 254)}",
        "id.resp_p": scenario["dest_port"],
        "proto": scenario["proto"],
        "duration": scenario["duration"],
        "orig_bytes": scenario["orig_bytes"],
        "resp_bytes": scenario["resp_bytes"],
        "conn_state": "SF",
        "missed_bytes": 0,
        "history": "ShADad",
        "orig_pkts": random.randint(10, 200),
        "resp_pkts": random.randint(5, 100),
    }


def inject_attack(scenario, index, total):
    """Write one attack entry to conn.log and print status"""
    entry = build_zeek_entry(scenario)
    
    os.makedirs("logs", exist_ok=True)
    with open(ZEEK_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    severity_colour = scenario["severity"]
    timestamp = datetime.now().strftime("%H:%M:%S")

    print(f"\n[{timestamp}] Attack {index}/{total}")
    print(c("BOLD", f"  ► {scenario['name']}") +
          f"  [{c(severity_colour, scenario['severity'])}]")
    print(f"  {scenario['description']}")
    print(f"  src_bytes={entry['orig_bytes']:,}  "
          f"dst_bytes={entry['resp_bytes']:,}  "
          f"duration={entry['duration']}s  "
          f"port={entry['id.resp_p']}")
    print(c("CYAN", "  → Injected into conn.log — IDS processing..."))


def print_summary(total_injected):
    print("\n" + "─" * 60)
    print(c("BOLD", "  SIMULATION COMPLETE"))
    print("─" * 60)
    print(f"  Total attacks injected : {total_injected}")
    print(f"  Log file               : {ZEEK_LOG}")
    print(f"\n  Check Terminal 1 for IDS detections.")
    print(f"  Check Kibana → http://localhost:5601")
    print(f"  Check results/ folder for sandbox analysis files.\n")
    print(c("OK", "Expected pipeline output in Terminal 1:"))
    print("""
    Anomaly Detected! (N found)
    Running local Docker sandbox...
    Suspicious behavior detected - potential malware
    Escalating to cloud sandbox...
    VirusTotal: 0 detections (CSV files are not malware)
    Saved cloud API result to results/anomaly_X_cloud.json
    """)


def main():
    print_banner()

    total_injected = 0
    total_attacks  = len(ATTACK_SCENARIOS) * REPEAT_CYCLES

    for cycle in range(REPEAT_CYCLES):
        if REPEAT_CYCLES > 1:
            print(c("BOLD", f"\n  ── Cycle {cycle + 1} of {REPEAT_CYCLES} ──"))

        # Shuffling order each cycle so demo looks dynamic
        scenarios = ATTACK_SCENARIOS.copy()
        random.shuffle(scenarios)

        for i, scenario in enumerate(scenarios, start=1):
            total_injected += 1
            inject_attack(scenario, total_injected, total_attacks)

            if i < len(scenarios):
                print(f"  (Next attack in {INTERVAL}s...)")
                time.sleep(INTERVAL)

    print_summary(total_injected)


if __name__ == "__main__":
    main()