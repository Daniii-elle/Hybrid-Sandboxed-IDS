"""
Smart Grid IDS Dashboard Web Application
=========================================
Flask-based web dashboard for non-technical stakeholders to view
security alerts and system status from all IDS data sources:
- Zeek/IDS anomalies (Isolation Forest)
- Suricata signature-based alerts
- Docker sandbox analysis results
- VirusTotal cloud analysis

Usage:
    python dashboard_app.py
    
Then visit: http://localhost:5000 (or http://<your-ip>:5000 from another machine)

The URL can be embedded in email reports so stakeholders can click
and view detailed results without technical knowledge.
"""

from flask import Flask, render_template, jsonify, request
from datetime import datetime, timedelta
import json
import os
import glob
import logging
from typing import List, Dict, Optional, Tuple
import platform

# Try to import ELK client
try:
    from elk_api import ELKClient
    ELK_AVAILABLE = True
except ImportError:
    ELK_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment helper (mirrors email_reporter.py and ids_full_system.py)
if platform.system() == "Windows":
    try:
        import winreg
    except ImportError:
        winreg = None


def _load_dotenv(dotenv_path: Optional[str] = None) -> None:
    """Load environment variables from a .env file into os.environ."""
    if dotenv_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dotenv_path = os.path.join(base_dir, ".env")

    if not os.path.exists(dotenv_path):
        return

    try:
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and os.getenv(key) is None:
                    os.environ[key] = value
    except Exception:
        pass


def _get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Read environment variable with Windows registry fallback."""
    _load_dotenv()

    value = os.getenv(name)
    if value:
        return value

    if platform.system() == "Windows" and winreg is not None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                value, _ = winreg.QueryValueEx(key, name)
                if value:
                    return value
        except (FileNotFoundError, OSError):
            pass

    return default


# ── Configuration ────────────────────────────────────────────────────────

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Server configuration
FLASK_PORT = int(_get_env("IDS_DASHBOARD_PORT") or "5000")
FLASK_HOST = _get_env("IDS_DASHBOARD_HOST") or "0.0.0.0"

# ELK configuration
ELK_HOST = _get_env("ELK_HOST") or "localhost"
ELK_PORT = int(_get_env("ELK_PORT") or "9201")
ELK_BASE_URL = f"http://{ELK_HOST}:{ELK_PORT}"

# Directories
RESULTS_DIR = "results"
LOGS_DIR = "logs"


# ── Data retrieval functions ──────────────────────────────────────────────

def get_anomalies_from_disk(limit: int = 50) -> List[Dict]:
    """
    Load recent anomalies from CSV files saved in results/ directory.
    Returns the most recent N anomalies.
    """
    anomalies = []
    
    if not os.path.exists(RESULTS_DIR):
        return anomalies
    
    # Find all anomaly CSV files
    pattern = os.path.join(RESULTS_DIR, "anomaly_*.csv")
    files = sorted(glob.glob(pattern), key=lambda x: os.path.getmtime(x), reverse=True)
    
    for file_path in files[:limit]:
        try:
            import pandas as pd
            df = pd.read_csv(file_path)
            if not df.empty:
                record = df.iloc[0].to_dict()
                record['file'] = os.path.basename(file_path)
                record['timestamp'] = datetime.fromtimestamp(
                    os.path.getmtime(file_path)
                ).isoformat()
                anomalies.append(record)
        except Exception as e:
            logger.warning(f"Failed to read anomaly file {file_path}: {e}")
    
    return anomalies


def get_sandbox_results(limit: int = 20) -> List[Dict]:
    """
    Load sandbox analysis results from JSON files in results/ directory.
    Returns VirusTotal cloud analysis results.
    """
    results = []
    
    if not os.path.exists(RESULTS_DIR):
        return results
    
    # Find cloud result JSON files
    pattern = os.path.join(RESULTS_DIR, "*_cloud.json")
    files = sorted(glob.glob(pattern), key=lambda x: os.path.getmtime(x), reverse=True)
    
    for file_path in files[:limit]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            result = {
                'file': os.path.basename(file_path),
                'timestamp': datetime.fromtimestamp(
                    os.path.getmtime(file_path)
                ).isoformat(),
                'raw_data': data
            }
            
            # Extract VirusTotal summary if available
            if 'virustotal' in data:
                vt_data = data['virustotal']
                if 'data' in vt_data:
                    attrs = vt_data['data'].get('attributes', {})
                    analysis = attrs.get('last_analysis_stats', {})
                    result['provider'] = 'VirusTotal'
                    result['malicious'] = analysis.get('malicious', 0)
                    result['suspicious'] = analysis.get('suspicious', 0)
                    result['undetected'] = analysis.get('undetected', 0)
                    result['hash'] = attrs.get('sha256', '')
                    result['url'] = f"https://www.virustotal.com/gui/file/{attrs.get('sha256', '')}"
            
            # Extract Hybrid Analysis summary if available
            elif 'hybrid_analysis' in data:
                ha_data = data['hybrid_analysis']
                result['provider'] = 'Hybrid Analysis'
                result['job_id'] = ha_data.get('job_id', '')
                result['hash'] = ha_data.get('sha256', '')
                result['url'] = f"https://www.hybrid-analysis.com/sample/{ha_data.get('sha256', '')}"
            
            results.append(result)
        except Exception as e:
            logger.warning(f"Failed to read sandbox result {file_path}: {e}")
    
    return results


def get_elk_data() -> Dict:
    """
    Query ELK for recent anomalies and alerts.
    Returns structured data from Elasticsearch indices.
    """
    elk_data = {
        'available': False,
        'anomalies': [],
        'alerts': [],
        'error': None
    }
    
    if not ELK_AVAILABLE:
        elk_data['error'] = "ELK client not available"
        return elk_data
    
    try:
        client = ELKClient(ELK_BASE_URL, timeout=10)
        
        # Check health
        if not client.health_check():
            elk_data['error'] = f"Cannot connect to Elasticsearch at {ELK_BASE_URL}"
            return elk_data
        
        elk_data['available'] = True
        
        # Query anomalies
        try:
            anomaly_hits = client.search('ids-anomalies', size=50)
            if anomaly_hits:
                elk_data['anomalies'] = [hit['_source'] for hit in anomaly_hits]
        except Exception as e:
            logger.warning(f"Failed to query anomalies from ELK: {e}")
        
        # Query alerts
        try:
            alert_hits = client.search('ids-alerts', size=50)
            if alert_hits:
                elk_data['alerts'] = [hit['_source'] for hit in alert_hits]
        except Exception as e:
            logger.warning(f"Failed to query alerts from ELK: {e}")
        
    except Exception as e:
        elk_data['error'] = f"ELK connection error: {e}"
    
    return elk_data


def get_suricata_alerts(limit: int = 50) -> List[Dict]:
    """
    Parse recent Suricata EVE JSON alerts from logs/eve.json.
    Returns the most recent N alerts.
    """
    alerts = []
    eve_log = os.path.join(LOGS_DIR, "eve.json")
    
    if not os.path.exists(eve_log):
        return alerts
    
    try:
        # Read all alerts and take the last N
        all_alerts = []
        with open(eve_log, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get('event_type') == 'alert':
                        alert = {
                            'timestamp': data.get('timestamp'),
                            'src_ip': data.get('src_ip'),
                            'dest_ip': data.get('dest_ip'),
                            'signature': data.get('alert', {}).get('signature', 'Unknown'),
                            'severity': data.get('alert', {}).get('severity', 4),
                            'protocol': data.get('proto', 'unknown').upper(),
                            'action': data.get('alert', {}).get('action', 'Unknown')
                        }
                        all_alerts.append(alert)
                except json.JSONDecodeError:
                    continue
        
        # Return most recent alerts
        alerts = all_alerts[-limit:] if all_alerts else []
    
    except Exception as e:
        logger.warning(f"Failed to parse Suricata alerts: {e}")
    
    return alerts


def calculate_threat_level(anomalies: List[Dict], alerts: List[Dict], sandbox: List[Dict]) -> Tuple[str, str, str]:
    """
    Determine overall threat level based on counts.
    
    Returns: (status, color, message)
    - status: "CRITICAL", "WARNING", "CAUTION", "CLEAR"
    - color: bootstrap color class (danger, warning, info, success)
    - message: human-readable description
    """
    anomaly_count = len(anomalies)
    alert_count = len(alerts)
    malicious_count = sum(1 for s in sandbox if s.get('malicious', 0) > 0)
    
    # Severity scoring
    if anomaly_count >= 10 or alert_count >= 5 or malicious_count > 0:
        return ("CRITICAL", "danger", 
                f"Immediate attention required: {anomaly_count} anomalies, "
                f"{alert_count} alerts, {malicious_count} malicious files detected")
    elif anomaly_count >= 3 or alert_count > 0:
        return ("WARNING", "warning",
                f"Suspicious activity detected: {anomaly_count} anomalies, "
                f"{alert_count} alerts")
    elif anomaly_count > 0:
        return ("CAUTION", "info",
                f"Minor anomalies detected ({anomaly_count}), all alerts clear")
    else:
        return ("ALL CLEAR", "success",
                "No significant threats detected - normal operation")


# ── Flask Routes ──────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    """Main dashboard page."""
    try:
        # Collect data from all sources
        anomalies = get_anomalies_from_disk(limit=20)
        alerts = get_suricata_alerts(limit=20)
        sandbox_results = get_sandbox_results(limit=15)
        elk_data = get_elk_data()
        
        # Combine ELK data if available
        if elk_data['available']:
            # Merge ELK anomalies with disk anomalies (avoid duplicates)
            elk_anomalies = elk_data.get('anomalies', [])
            anomalies.extend(elk_anomalies[:5])  # Add recent from ELK
            
            # Merge ELK alerts with disk alerts
            elk_alerts = elk_data.get('alerts', [])
            alerts.extend(elk_alerts[:5])
        
        # Calculate threat level
        threat_status, threat_color, threat_msg = calculate_threat_level(
            anomalies, alerts, sandbox_results
        )
        
        # Prepare context for template
        context = {
            'generated_at': datetime.now().strftime('%d %B %Y at %H:%M:%S'),
            'threat_status': threat_status,
            'threat_color': threat_color,
            'threat_message': threat_msg,
            'anomaly_count': len(anomalies),
            'alert_count': len(alerts),
            'sandbox_count': len(sandbox_results),
            'malicious_files': sum(1 for s in sandbox_results if s.get('malicious', 0) > 0),
            'anomalies': anomalies[:15],  # Show top 15
            'alerts': alerts[:15],
            'sandbox_results': sandbox_results[:15],
            'elk_available': elk_data['available'],
            'elk_error': elk_data.get('error'),
        }
        
        return render_template('dashboard.html', **context)
    
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return render_template('error.html', error=str(e)), 500


@app.route('/api/summary')
def api_summary():
    """JSON API endpoint for dashboard summary."""
    try:
        anomalies = get_anomalies_from_disk(limit=50)
        alerts = get_suricata_alerts(limit=50)
        sandbox_results = get_sandbox_results(limit=50)
        
        threat_status, threat_color, threat_msg = calculate_threat_level(
            anomalies, alerts, sandbox_results
        )
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'threat_level': threat_status,
            'anomalies': len(anomalies),
            'alerts': len(alerts),
            'sandbox_analyses': len(sandbox_results),
            'malicious_detected': sum(1 for s in sandbox_results if s.get('malicious', 0) > 0),
            'message': threat_msg
        })
    except Exception as e:
        logger.error(f"API summary error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/anomalies')
def api_anomalies():
    """JSON API endpoint for anomalies."""
    try:
        limit = request.args.get('limit', 50, type=int)
        anomalies = get_anomalies_from_disk(limit=limit)
        return jsonify(anomalies)
    except Exception as e:
        logger.error(f"API anomalies error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts')
def api_alerts():
    """JSON API endpoint for Suricata alerts."""
    try:
        limit = request.args.get('limit', 50, type=int)
        alerts = get_suricata_alerts(limit=limit)
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"API alerts error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/sandbox')
def api_sandbox():
    """JSON API endpoint for sandbox results."""
    try:
        limit = request.args.get('limit', 20, type=int)
        results = get_sandbox_results(limit=limit)
        return jsonify(results)
    except Exception as e:
        logger.error(f"API sandbox error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/health')
def health():
    """Health check endpoint for monitoring."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'flask_running': True
    }), 200


# ── Error handlers ────────────────────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('error.html', error="Page not found"), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {e}", exc_info=True)
    return render_template('error.html', error="Internal server error"), 500


# ── Main ──────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 70)
    print("  SMART GRID IDS DASHBOARD")
    print("=" * 70)
    print(f"  Starting Flask server on {FLASK_HOST}:{FLASK_PORT}")
    print(f"  Open in browser: http://localhost:{FLASK_PORT}")
    print(f"  Share URL: http://<your-ip>:{FLASK_PORT}")
    print("=" * 70)
    
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)
