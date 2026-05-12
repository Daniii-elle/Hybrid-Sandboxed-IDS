#!/usr/bin/env python3
import os
import sys

def main():
    print("IDS Sandbox Configuration Helper")
    print("=" * 40)

    services = {
        "1": {"name": "VirusTotal", "env_var": "VIRUSTOTAL_API_KEY", "url": "https://www.virustotal.com/gui/my-apikey"},
        "2": {"name": "Hybrid Analysis", "env_var": "HYBRID_ANALYSIS_API_KEY", "url": "https://www.hybrid-analysis.com/"},
        "3": {"name": "Local Only", "env_var": None, "url": None}
    }

    print("\nAvailable sandbox services:")
    for key, service in services.items():
        print(f"{key}. {service['name']}")

if __name__ == "__main__":
    main()