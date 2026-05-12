"""
Usage:
    python run_ids_with_dashboard.py
    
This will:
1. Check all prerequisites and configuration
2. Start the Flask dashboard in the background
3. Launch the main IDS monitoring loop
4. Both services will run together, sending emails with dashboard links
"""

import subprocess
import time
import os
import sys
import platform
from pathlib import Path

# Color codes for terminal output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

def print_header(text):
    """Print a formatted header."""
    print(f"\n{BOLD}{BLUE}{'='*70}{RESET}")
    print(f"{BOLD}{BLUE}{text:^70}{RESET}")
    print(f"{BOLD}{BLUE}{'='*70}{RESET}\n")

def print_success(text):
    """Print success message."""
    print(f"{GREEN} {text}{RESET}")

def print_warning(text):
    """Print warning message."""
    print(f"{YELLOW} {text}{RESET}")

def print_error(text):
    """Print error message."""
    print(f"{RED} {text}{RESET}")

def print_info(text):
    """Print info message."""
    print(f"{BLUE} {text}{RESET}")

def check_python_version():
    """Check Python version (3.8+)."""
    print_info("Checking Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print_success(f"Python {version.major}.{version.minor}.{version.micro} detected")
        return True
    else:
        print_error(f"Python 3.8+ required (found {version.major}.{version.minor})")
        return False

def check_required_files():
    """Check if required project files exist."""
    print_info("Checking required files...")
    required = [
        'ids_full_system.py',
        'dashboard_app.py',
        'email_reporter.py',
        'elk_api.py',
        'requirements.txt',
        'templates/dashboard.html',
        'templates/error.html'
    ]
    
    missing = []
    for file in required:
        if os.path.exists(file):
            print_success(f"Found {file}")
        else:
            missing.append(file)
            print_error(f"Missing {file}")
    
    return len(missing) == 0

def check_dependencies():
    """Check if required Python packages are installed."""
    print_info("Checking Python dependencies...")
    
    required_packages = {
        'flask': 'Flask',
        'pandas': 'Pandas',
        'sklearn': 'Scikit-learn',
        'requests': 'Requests',
        'joblib': 'Joblib'
    }
    
    missing = []
    for import_name, display_name in required_packages.items():
        try:
            __import__(import_name)
            print_success(f"{display_name} is installed")
        except ImportError:
            missing.append(display_name)
            print_error(f"{display_name} is NOT installed")
    
    if missing:
        print_error(f"Missing: {', '.join(missing)}")
        print_warning("Install with: pip install -r requirements.txt")
        return False
    return True

def check_environment_variables():
    """Check critical environment variables."""
    print_info("Checking environment variables...")
    
    required = ['SMTP_USER', 'SMTP_PASSWORD', 'REPORT_TO']
    missing = []
    
    for var in required:
        if os.getenv(var):
            print_success(f"{var} is set")
        else:
            missing.append(var)
            print_warning(f"{var} is NOT set")
    
    if missing:
        print_warning(f"These variables should be set for email to work: {', '.join(missing)}")
        print_info("Example (Windows PowerShell):")
        print("  $env:SMTP_USER='your.email@gmail.com'")
        print("  $env:SMTP_PASSWORD='xxxx xxxx xxxx xxxx'") 
        print("  $env:REPORT_TO='recipient@example.com'")
    
    optional = ['DASHBOARD_URL', 'IDS_DASHBOARD_PORT', 'ELK_HOST']
    print_info("Optional configuration variables:")
    for var in optional:
        value = os.getenv(var, "not set")
        print(f"  {var}: {value}")

def get_local_ip():
    """Get local IP address for dashboard URL."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "localhost"

def main():
    """Main setup and launch function."""
    print_header("HYBRID SANDBOXED IDS — COMPLETE SYSTEM LAUNCHER")
    
    # Check prerequisites
    print_header("PREREQUISITES CHECK")
    
    checks = [
        ("Python Version", check_python_version()),
        ("Required Files", check_required_files()),
        ("Dependencies", check_dependencies()),
    ]
    
    # Show status
    all_passed = all(check[1] for check in checks)
    
    for check_name, passed in checks:
        status = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
        print(f"  {check_name}: {status}")
    
    print()
    check_environment_variables()
    
    if not all_passed:
        print_error("\nPlease fix the above issues before continuing.")
        sys.exit(1)
    
    print_header("CONFIGURATION")
    
    dashboard_port = os.getenv('IDS_DASHBOARD_PORT', '5000')
    local_ip = get_local_ip()
    dashboard_url = f"http://{local_ip}:{dashboard_port}"
    
    print_info("Dashboard Configuration:")
    print(f"  Local Access    : http://localhost:{dashboard_port}")
    print(f"  Network Access  : {dashboard_url}")
    
    os.environ['DASHBOARD_URL'] = dashboard_url
    
    print_info("\nEmail Configuration:")
    if os.getenv('SMTP_USER'):
        print(f"  From    : {os.getenv('SMTP_USER')}")
    else:
        print_warning("  From    : NOT SET (emails will not be sent)")
    
    if os.getenv('REPORT_TO'):
        print(f"  To      : {os.getenv('REPORT_TO')}")
    else:
        print_warning("  To      : NOT SET (emails will not be sent)")
    
    # Launch services
    print_header("LAUNCHING SERVICES")
    
    processes = []
    
    try:
        # Start Flask dashboard in background
        print_info("Starting Flask Dashboard...")
        dashboard_process = subprocess.Popen(
            [sys.executable, 'dashboard_app.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append(('Dashboard', dashboard_process))
        print_success(f"Flask Dashboard started (PID: {dashboard_process.pid})")
        print(f"  {BOLD}Access at: {dashboard_url}{RESET}")
        
        # Wait a moment for dashboard to start
        time.sleep(2)
        
        # Start IDS monitoring
        print_info("Starting IDS Monitoring System...")
        ids_process = subprocess.Popen(
            [sys.executable, 'ids_full_system.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append(('IDS Monitor', ids_process))
        print_success(f"IDS Monitoring started (PID: {ids_process.pid})")
        
        print_header("SYSTEM RUNNING")
        print(f"{GREEN}✓ All services are running{RESET}")
        print(f"\n{BOLD}Access Points:{RESET}")
        print(f"  IDS Dashboard    : {BOLD}{dashboard_url}{RESET}")
        print(f"  ELK Analytics    : http://localhost:5601")
        print(f"  Email Reports    : Automatic (every 30 min)")
        print(f"\n{BOLD}Services Running:{RESET}")
        for name, proc in processes:
            print(f"  ✓ {name:20} (PID: {proc.pid})")
        
        print(f"\n{YELLOW}Press Ctrl+C to stop all services{RESET}\n")
        
        # Keep running and monitor processes
        while True:
            time.sleep(1)
            
            # Check if processes are still alive
            for name, proc in processes:
                if proc.poll() is not None:
                    print_error(f"{name} process has exited (PID: {proc.pid})")
    
    except KeyboardInterrupt:
        print_header("SHUTTING DOWN")
        print_info("Stopping all services...")
        
        for name, proc in processes:
            try:
                proc.terminate()
                print_info(f"Terminating {name} (PID: {proc.pid})...")
            except Exception as e:
                print_error(f"Error stopping {name}: {e}")
        
        # Wait for graceful shutdown
        for name, proc in processes:
            try:
                proc.wait(timeout=5)
                print_success(f"{name} stopped")
            except subprocess.TimeoutExpired:
                proc.kill()
                print_warning(f"{name} force-killed")
        
        print_success("All services stopped")
        sys.exit(0)
    
    except Exception as e:
        print_error(f"Error launching services: {e}")
        
        # Cleanup
        for name, proc in processes:
            try:
                proc.terminate()
            except:
                pass
        
        sys.exit(1)

if __name__ == '__main__':
    main()
