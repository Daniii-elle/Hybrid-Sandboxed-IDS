import pandas as pd
import json
import time
import os
import platform
import joblib
import subprocess

from sklearn.ensemble import IsolationForest
from sandbox.virustotal_api import send_to_sandbox as send_to_virustotal_sandbox
from datetime import datetime
from email_reporter import send_ids_report
from elk_api import send_anomaly_to_elk, send_alert_to_elk, send_event_to_elk, get_elk_health, initialize_elk_indices

# Configurations
ZEEK_LOG = "logs/conn.log"
SURICATA_LOG = "logs/eve.json"
MODEL_FILE = "model.pkl"
ELK_ENABLED = True  # Set to True once I have Elasticsearch running

# Performance tuning
MAX_LOGS_PER_CYCLE = 1000  # Maximum logs to process per monitoring cycle
MAX_ANOMALIES_PER_CYCLE = 100  # Maximum anomalies to analyze per cycle
MONITORING_INTERVAL = 30  # Seconds between monitoring cycles
SANDBOX_ENABLED = True  # Set to False to skip sandbox analysis for faster performance
# Environment helpers
if platform.system() == "Windows":
    try:
        import winreg
    except ImportError:
        winreg = None


def _load_dotenv(dotenv_path=None):
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


def get_env_value(name, default=None):
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
        except FileNotFoundError:
            pass
        except OSError:
            pass

    return default
# Load Train Dataset
def train_model():
    print("Loading dataset...")

    train: pd.DataFrame = pd.read_csv("data/raw/unsw_train.csv")

    features = ['dur', 'sbytes', 'dbytes']
    train_data = train.loc[:, features].copy()
    train_data.columns = ['duration', 'src_bytes', 'dst_bytes']

    # Reduce memory usage
    train_data = train_data.sample(n=5000, random_state=42)
    train_data = train_data.fillna(0)
    print("Training Isolation Forest...")

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(train_data)

    joblib.dump(model, MODEL_FILE)
    print("Model trained and saved as model.pkl.")

# Parse Zeek Logs
def parse_zeek():
    records = []
    headers = []

    if not os.path.exists(ZEEK_LOG):
        print(f"Warning: {ZEEK_LOG} not found")
        return pd.DataFrame()

    try:
        with open(ZEEK_LOG, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip().strip('/x00')
                if not line or len(line) < 2:
                    continue
                
                # Try JSON first (if JSON logging is enabled)
                if line.startswith('{'):
                    try:
                        data = json.loads(line)
                        record = {
                            "ts": data.get("ts", 0),
                            "duration": float(data.get("duration", 0)),
                            "src_bytes": int(data.get("orig_bytes", 0)),
                            "dst_bytes": int(data.get("resp_bytes", 0))
                        }
                        records.append(record)
                        continue
                    except (json.JSONDecodeError, ValueError):
                        pass

                # Handle TSV format
                if line.startswith('#fields'):
                    headers = line.split('\t')[1:]  # strip the '#fields' prefix
                    continue
                if line.startswith('#'):
                    continue  # skip other comment lines like #separator, #types, etc.

                if headers:
                    values = line.split('\t')
                    if len(values) == len(headers):
                        data = dict(zip(headers, values))
                        try:
                            record = {
                                "ts": float(data.get("ts", 0)),
                                "duration": float(data.get("duration", 0) if data.get("duration", "-") != "-" else 0),
                                "src_bytes": int(data.get("orig_bytes", 0) if data.get("orig_bytes", "-") != "-" else 0),
                                "dst_bytes": int(data.get("resp_bytes", 0) if data.get("resp_bytes", "-") != "-" else 0)
                            }
                            records.append(record)
                        except ValueError as e:
                            print(f"Warning: Invalid data in Zeek log: {e}")

    except (FileNotFoundError, PermissionError) as e:
        print(f"Error reading Zeek log: {e}")
        return pd.DataFrame()

    return pd.DataFrame(records)

# Check Suricata
def check_suricata():
    alerts = []

    if not os.path.exists(SURICATA_LOG):
        print(f"Warning: {SURICATA_LOG} not found")
        return alerts

    try:
        with open(SURICATA_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)

                    if data.get("event_type") == "alert":
                        alert_info = {
                            "timestamp": data.get("timestamp"),
                            "src_ip": data.get("src_ip"),
                            "dest_ip": data.get("dest_ip"),
                            "signature": data.get("alert", {}).get("signature"),
                            "severity": data.get("alert", {}).get("severity"),
                            "protocol": data.get("proto")
                        }

                        alerts.append(alert_info)

                except json.JSONDecodeError:
                    continue
                except KeyError:
                    continue

    except Exception as e:
        print(f"Error reading Suricata log: {e}")

    return alerts

# Sandbox Function(Docker + Cloud)
def send_to_sandbox(file_name):
    try:
        print("Running local Docker sandbox...")
        print(f"Local sandbox file: {file_name}")

        host_path = os.path.abspath(file_name)
        container_dir = "/data"
        container_path = f"{container_dir}/{os.path.basename(host_path)}"

        vt_key = get_env_value("VIRUSTOTAL_API_KEY", "") or ""
        ha_key = get_env_value("HYBRID_ANALYSIS_API_KEY", "") or ""
        sandbox_service = get_env_value("SANDBOX_SERVICE", "virustotal") or "virustotal"

        print(f"Sandbox environment: VIRUSTOTAL_API_KEY set={bool(vt_key)}, HYBRID_ANALYSIS_API_KEY set={bool(ha_key)}, SANDBOX_SERVICE={sandbox_service}")

        env = os.environ.copy()
        env["VIRUSTOTAL_API_KEY"] = vt_key
        env["HYBRID_ANALYSIS_API_KEY"] = ha_key
        env["SANDBOX_SERVICE"] = sandbox_service

        try:
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{os.path.dirname(host_path)}:{container_dir}",
                    "-e", f"VIRUSTOTAL_API_KEY={vt_key}",
                    "-e", f"HYBRID_ANALYSIS_API_KEY={ha_key}",
                    "-e", f"SANDBOX_SERVICE={sandbox_service}",
                    "sandbox_env",
                    container_path
                ],
                capture_output=True,
                text=True,
                timeout=60,  # time given for docker to start
                env=env
            )

            output = result.stdout.strip()
            stderr = result.stderr.strip()
            if output:
                print(f"Local Sandbox Result: {output}")
            if stderr:
                print(f"Local Sandbox Error: {stderr}")

            if result.returncode != 0 and not output:
                return {"error": f"Local sandbox failed with exit code {result.returncode}", "stderr": stderr}

            # Decision logic - escalate suspicious files to cloud sandbox
            if "malicious" in output.lower() or "suspicious" in output.lower():
                print("Escalating to cloud sandbox...")
                cloud_result = send_to_virustotal_sandbox(file_name)
                cloud_result_path = None

                try:
                    os.makedirs("results", exist_ok=True)
                    base_name = os.path.splitext(os.path.basename(file_name))[0]
                    cloud_result_path = f"results/{base_name}_cloud.json"
                    with open(cloud_result_path, "w", encoding="utf-8") as f:
                        json.dump(cloud_result, f, indent=2)
                    print(f"Saved cloud API result to {cloud_result_path}")
                    print_cloud_api_summary(cloud_result_path)
                except Exception as save_error:
                    print(f"Warning: failed to save cloud result: {save_error}")

                if cloud_result_path:
                    print(f"Inspect the saved cloud JSON: {cloud_result_path}")
                return {
                    "local": output,
                    "cloud": cloud_result,
                    "cloud_result_path": cloud_result_path
                }
            else:
                print("Local sandbox did not flag the file as suspicious, so cloud escalation was not performed.")
                print("If you want to force cloud upload for debugging, set SANDBOX_SERVICE to virustotal or hybrid_analysis and run with a suspicious file name.")
                return {"local": output}

        except subprocess.TimeoutExpired:
            print("Local sandbox timed out after 10 seconds - skipping analysis")
            return {"error": "Local sandbox timeout", "timeout": True}

    except Exception as e:
        print(f"Sandbox error: {e}")
        return None


def print_cloud_api_summary(cloud_result_path):
    try:
        with open(cloud_result_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            if "virustotal" in data:
                vt = data["virustotal"]
                attributes = vt.get("data", {}).get("attributes", {})
                analysis_stats = attributes.get("last_analysis_stats", {})
                permalink = attributes.get("permalink")

                print("VirusTotal summary:", analysis_stats)
                if permalink:
                    print(f"View full analysis: {permalink}")
                else:
                    # For new uploads, construct permalink from hash
                    sha256 = attributes.get("sha256")
                    if sha256:
                        print(f"View analysis: https://www.virustotal.com/gui/file/{sha256}")

            elif "hybrid_analysis" in data:
                ha = data["hybrid_analysis"]
                job_id = ha.get("job_id")
                sha256 = ha.get("sha256")

                print("Hybrid Analysis submission successful")
                if job_id:
                    print(f"View analysis: https://www.hybrid-analysis.com/sample/{sha256}")
                print("Hybrid Analysis response keys:", list(ha.keys()))

            else:
                print("Cloud API response saved; top-level keys:", list(data.keys()))
        else:
            print("Cloud API response saved; unable to summarize JSON.")
    except Exception as e:
        print(f"Failed to read cloud API summary: {e}")

# Realtime Monitoring
def monitor():

    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)

    model = joblib.load(MODEL_FILE)
    last_processed_ts = 0  # Track last processed timestamp

    while True:
        df = parse_zeek()

        if df.empty:
            print("Waiting for Zeek logs...")
            time.sleep(5)
            continue

        # Filter to only new logs since last processing
        if 'ts' in df.columns:
            df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
            df = df[df['ts'] > last_processed_ts]
            if not df.empty:
                last_processed_ts = df['ts'].max()

        if df.empty:
            print("No new logs to process...")
            time.sleep(5)
            continue

        # Limit processing to last N entries to avoid overload
        if len(df) > MAX_LOGS_PER_CYCLE:  # 2000 logs can be too much for real-time processing
            df = df.tail(MAX_LOGS_PER_CYCLE)
            print(f"Processing last {MAX_LOGS_PER_CYCLE} logs (truncated for performance)")

        df = df.fillna(0)

        feature_columns = ['duration', 'src_bytes', 'dst_bytes']
        if not set(feature_columns).issubset(df.columns):
            missing = set(feature_columns) - set(df.columns)
            print(f"Missing required features for prediction: {missing}")
            time.sleep(10)
            continue

        prediction_df = df[feature_columns]
        predictions = model.predict(prediction_df)
        df['anomaly'] = predictions
        df['label'] = df['anomaly'].map({1: 'Normal', -1: 'Suspicious'})

        anomalies = df[df['label'] == "Suspicious"]

        # Limit anomalies processed per cycle
        if len(anomalies) > MAX_ANOMALIES_PER_CYCLE:
            anomalies = anomalies.head(MAX_ANOMALIES_PER_CYCLE)
            print(f"Processing {MAX_ANOMALIES_PER_CYCLE} anomalies (limited for performance)")

        # Check Suricata Alerts
        alerts = check_suricata()

        if not anomalies.empty:
            print(f"Anomaly Detected! ({len(anomalies)} found)")
            print(anomalies.tail())

            collected_sandbox = []  # gather sandbox results for the report
            for index, row in anomalies.iterrows():
                file_name = f"results/anomaly_{index}.csv"

                os.makedirs("results", exist_ok=True)
                row.to_frame().T.to_csv(file_name, index=False)

                # Send to sandbox (only if enabled)
                if SANDBOX_ENABLED:
                    sandbox_response = send_to_sandbox(file_name)
                    if sandbox_response:
                        collected_sandbox.append(sandbox_response)
                    if sandbox_response and sandbox_response.get("cloud_result_path"):
                        print(f"Cloud API findings saved: {sandbox_response['cloud_result_path']}")

                # Send to ELK
                if ELK_ENABLED:
                    send_anomaly_to_elk(row.to_dict())

        if alerts:
            print("Suricata Alerts:")
            for alert in alerts[-5:]:
                print("-", alert)
                if ELK_ENABLED:
                    send_alert_to_elk(alert)


        # Send email report
        send_ids_report(
            anomalies=anomalies.to_dict("records") if not anomalies.empty else [],
            alerts=alerts,
            sandbox_results=collected_sandbox if 'collected_sandbox' in locals() else [],
            report_period_minutes=MONITORING_INTERVAL // 60 if MONITORING_INTERVAL >= 60 else MONITORING_INTERVAL,
        )

# Main
if __name__ == "__main__":
    # Initialize ELK if enabled
    if ELK_ENABLED:
        print("Initializing ELK indices...")
        try:
            initialize_elk_indices()
            health = get_elk_health()
            if health.get('elasticsearch_healthy'):
                print("ELK system ready")
            else:
                print("ELK system not available, continuing without ELK")
                ELK_ENABLED = False
        except Exception as e:
            print(f"ELK initialization failed: {e}. Continuing without ELK.")
            ELK_ENABLED = True

    if not os.path.exists(MODEL_FILE):
        train_model()

    monitor()