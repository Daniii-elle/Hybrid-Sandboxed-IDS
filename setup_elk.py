#!/usr/bin/env python3
"""
Helps configure ELK integration for the IDS system
"""

import os
import sys
import subprocess
import json
import urllib.request

def check_docker():
    """Check if Docker is available and running"""
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print("Docker is installed")

            # Check if Docker daemon is running
            result = subprocess.run(['docker', 'info'], capture_output=True, text=True)
            if result.returncode == 0:
                print("Docker daemon is running")
                return True
            else:
                print("Docker daemon is not running")
                print("Please start Docker Desktop and try again")
                return False
        else:
            print("Docker is not installed")
            return False
    except FileNotFoundError:
        print("Docker command not found")
        return False

def start_elk_containers():
    """Start ELK containers using Docker Compose"""
    print("Starting ELK containers...")

    compose_file = 'docker_compose.yml' if os.path.exists('docker_compose.yml') else 'docker_compose.yml'
    if not os.path.exists(compose_file):
        print(f"Compose file not found: {compose_file}")
        print("Please make sure docker_compose.yml or docker-compose.yml exists")
        return False

    compose_cmd = None
    for cmd in [['docker', 'compose'], ['docker_compose']]:
        try:
            result = subprocess.run(cmd + ['--version'], capture_output=True, text=True)
            if result.returncode == 0:
                compose_cmd = cmd
                break
        except FileNotFoundError:
            continue

    if compose_cmd is None:
        print("Docker Compose command not found")
        print("Please install Docker Compose or Docker CLI with compose support")
        return False

    result = subprocess.run(compose_cmd + ['-f', compose_file, 'up', '-d'], capture_output=True, text=True, cwd='.')

    if result.returncode == 0:
        print("ELK containers started successfully")
        print("Elasticsearch: http://localhost:9201")
        print("Kibana: http://localhost:5601")
        return True
    else:
        print("Failed to start ELK containers")
        print(f"Error: {result.stderr}")
        return False

def wait_for_elk_ready():
    """Wait for ELK services to be ready"""
    print("\nWaiting for ELK services to be ready...")

    import time

    max_attempts = 50
    for attempt in range(max_attempts):
        try:
            # Check Elasticsearch
            with urllib.request.urlopen('http://localhost:9201/_cluster/health', timeout=5) as response:
                body = response.read().decode('utf-8')
                health = json.loads(body)
                if health.get('status') in ['yellow', 'green']:
                    print("Elasticsearch is ready")

                    # Check Kibana
                    with urllib.request.urlopen('http://localhost:5601/api/status', timeout=5) as k_response:
                        if k_response.status == 200:
                            print("Kibana is ready")
                            return True
                        else:
                            print(f"Kibana not ready yet (attempt {attempt + 1}/{max_attempts})")
                else:
                    print(f"Elasticsearch status: {health.get('status')} (attempt {attempt + 1}/{max_attempts})")
        except Exception:
            print(f"Services not ready yet (attempt {attempt + 1}/{max_attempts})")

        time.sleep(5)

    print("ELK services failed to start within timeout")
    return False

def enable_elk_in_config():
    """Enable ELK in the IDS configuration"""
    config_file = 'ids_full_system.py'

    if not os.path.exists(config_file):
        print(f"Configuration file {config_file} not found")
        return False

    # Read current config
    with open(config_file, 'r') as f:
        content = f.read()

    # Replace ELK_ENABLED = False with True
    if 'ELK_ENABLED = False' in content:
        content = content.replace('ELK_ENABLED = False', 'ELK_ENABLED = True')
        print("Enabled ELK in IDS configuration")

        # Write back
        with open(config_file, 'w') as f:
            f.write(content)

        return True
    elif 'ELK_ENABLED = True' in content:
        print("ELK already enabled in configuration")
        return True
    else:
        print("Could not find ELK_ENABLED setting in config")
        return False

def test_elk_api():
    """Test the ELK API"""
    print("\n Testing ELK API...")

    try:
        result = subprocess.run([
            sys.executable, 'test_elk_api.py'
        ], capture_output=True, text=True, cwd='.')

        if result.returncode == 0:
            print("ELK API tests passed")
            return True
        else:
            print("ELK API tests failed")
            print(f"Output: {result.stdout}")
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error running ELK API tests: {e}")
        return False

def main():
    """Main setup function"""
    print("ELK Setup Helper for IDS System\n")

    # Check if we're in the right directory
    if not os.path.exists('ids_full_system.py'):
        print("Please run this script from the IDS project directory")
        sys.exit(1)

    # Step 1: Check Docker
    if not check_docker():
        print("\n To continue without Docker:")
        print("   1. Install Elasticsearch locally from https://www.elastic.co/downloads/elasticsearch")
        print("   2. Run the downloaded elasticsearch.bat")
        print("   3. Manually enable ELK_ENABLED = True in ids_full_system.py")
        sys.exit(1)

    # Step 2: Start containers
    if not start_elk_containers():
        sys.exit(1)

    # Step 3: Wait for services
    if not wait_for_elk_ready():
        sys.exit(1)

    # Step 4: Enable in config
    if not enable_elk_in_config():
        sys.exit(1)

    # Step 5: Test API
    if not test_elk_api():
        print("API tests failed, but ELK may still work")
        print("   You can try running the IDS system anyway")

    print("\nELK setup completed successfully!")
    print("\n Next steps:")
    print("   1. Run your IDS: python ids_full_system.py")
    print("   2. Access Kibana: http://localhost:5601")
    print("   3. Create index patterns for 'ids-*' indices")
    print("   4. Build dashboards for anomaly visualization")

if __name__ == "__main__":
    main()