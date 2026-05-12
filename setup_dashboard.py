#!/usr/bin/env python3
"""
QUICK START GUIDE — Smart Grid IDS with Email & Dashboard
=========================================================

This script sets up environment variables and starts the system.
Run this FIRST time, then you can use run_ids_with_dashboard.py
"""

import os
import platform
import subprocess
import sys

def get_input(prompt, default=""):
    """Get user input with default value."""
    if default:
        display = f"{prompt} [{default}]: "
    else:
        display = f"{prompt}: "
    value = input(display).strip()
    return value or default

def setup_gmail():
    """Guide user through Gmail setup."""
    print("\n" + "="*70)
    print("  GMAIL SETUP GUIDE")
    print("="*70)
    print("""
To use Gmail as your email provider:

1. Go to: https://myaccount.google.com/security
2. Enable "2-Step Verification" (if not already enabled)
3. Go to: https://myaccount.google.com/apppasswords
4. Select "Mail" and "Windows Computer" (or your device)
5. Google will generate a 16-character password
6. Copy that password (note that spaces don't matter)

Then use:
  Email:    your-email@gmail.com
  Password: xxxx xxxx xxxx xxxx  (the 16 characters)
""")

def main():
    print("\n" + "="*70)
    print("  SMART GRID IDS — INITIAL SETUP")
    print("="*70)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("ERROR: Python 3.8+ required!")
        sys.exit(1)
    
    print("\n  EMAIL CONFIGURATION")
    print("-"*70)
    
    use_gmail = get_input("Use Gmail? (yes/no)", "yes").lower() == "yes"
    
    if use_gmail:
        setup_gmail()
    
    smtp_host = get_input("SMTP Host", "smtp.gmail.com")
    smtp_port = get_input("SMTP Port", "587")
    smtp_user = get_input("Your Email Address")
    smtp_password = get_input("Email Password")
    report_to = get_input("Report Recipient Email")
    
    print("\n  DASHBOARD CONFIGURATION")
    print("-"*70)
    
    dashboard_port = get_input("Dashboard Port", "5000")
    dashboard_host = "0.0.0.0"  # Always listen on all interfaces
    dashboard_url = get_input("Dashboard URL (for email links)", f"http://localhost:{dashboard_port}")
    
    print("\n  OPTIONAL CONFIGURATION")
    print("-"*70)
    
    elk_enabled = get_input("Use ELK Stack? (yes/no)", "yes").lower() == "no"
    elk_host = "localhost"
    elk_port = "9201"
    
    if elk_enabled:
        elk_host = get_input("ELK Host", "localhost")
        elk_port = get_input("ELK Port", "9201")
    
    print("\n  SETTING ENVIRONMENT VARIABLES")
    print("-"*70)
    
    if platform.system() == "Windows":
        print("\n Add these to your PowerShell profile or set them before running:")
        print(f'$env:SMTP_HOST = "{smtp_host}"')
        print(f'$env:SMTP_PORT = "{smtp_port}"')
        print(f'$env:SMTP_USER = "{smtp_user}"')
        print(f'$env:SMTP_PASSWORD = "{smtp_password}"')
        print(f'$env:REPORT_TO = "{report_to}"')
        print(f'$env:IDS_DASHBOARD_PORT = "{dashboard_port}"')
        print(f'$env:DASHBOARD_URL = "{dashboard_url}"')
        if elk_enabled:
            print(f'$env:ELK_HOST = "{elk_host}"')
            print(f'$env:ELK_PORT = "{elk_port}"')
        
        print("\n Setting environment variables for this session...")
        os.environ['SMTP_HOST'] = smtp_host
        os.environ['SMTP_PORT'] = smtp_port
        os.environ['SMTP_USER'] = smtp_user
        os.environ['SMTP_PASSWORD'] = smtp_password
        os.environ['REPORT_TO'] = report_to
        os.environ['IDS_DASHBOARD_PORT'] = dashboard_port
        os.environ['DASHBOARD_URL'] = dashboard_url
        if elk_enabled:
            os.environ['ELK_HOST'] = elk_host
            os.environ['ELK_PORT'] = elk_port
    else:
        print("\n📝 Add these to ~/.bashrc or ~/.zshrc:")
        print(f'export SMTP_HOST="{smtp_host}"')
        print(f'export SMTP_PORT="{smtp_port}"')
        print(f'export SMTP_USER="{smtp_user}"')
        print(f'export SMTP_PASSWORD="{smtp_password}"')
        print(f'export REPORT_TO="{report_to}"')
        print(f'export IDS_DASHBOARD_PORT="{dashboard_port}"')
        print(f'export DASHBOARD_URL="{dashboard_url}"')
        if elk_enabled:
            print(f'export ELK_HOST="{elk_host}"')
            print(f'export ELK_PORT="{elk_port}"')
    
    print("\n  INSTALLING DEPENDENCIES")
    print("-"*70)
    
    install_deps = get_input("Install Python packages? (yes/no)", "yes").lower() == "yes"
    
    if install_deps:
        print("Installing packages from requirements.txt...")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        if result.returncode != 0:
            print(" Some packages failed to install. You may need to install manually.")
            print("   Run: pip install -r requirements.txt")
    
    print("\n  READY TO START!")
    print("="*70)
    
    start_now = get_input("Start the system now? (yes/no)", "yes").lower() == "yes"
    
    if start_now:
        print("\n Starting the IDS system...\n")
        try:
            subprocess.run([sys.executable, "run_ids_with_dashboard.py"])
        except KeyboardInterrupt:
            print("\n\nSystem stopped by user.")
        except Exception as e:
            print(f"ERROR: {e}")
            sys.exit(1)
    else:
        print("\n To start later, run:")
        print("   python run_ids_with_dashboard.py")
        print("\n For detailed documentation, see: DASHBOARD_SETUP.md")

if __name__ == '__main__':
    main()
