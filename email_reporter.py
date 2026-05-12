# email_reporter.py
"""
Email Reporting Engine for Hybrid Sandboxed IDS
================================================
Composes and sends a plain-English security summary email to a
configured recipient.  Designed to be called from ids_full_system.py
after each monitoring cycle so that non-technical stakeholders can
understand what the system found without reading raw JSON logs.

Usage (from ids_full_system.py):
    from email_reporter import send_ids_report
    send_ids_report(anomalies=anomalies_list, alerts=suricata_alerts,
                    sandbox_results=sandbox_results_list)

Free-tier compatible:
- Uses Python's built-in smtplib (no third-party library needed).
- Works with any SMTP server that allows App Passwords or STARTTLS,
  e.g. Gmail, Outlook, Yahoo.
- For Gmail: enable 2-Step Verification, then create an App Password at
  https://myaccount.google.com/apppasswords and store it as the
  SMTP_PASSWORD environment variable.

References:
- Python smtplib docs: https://docs.python.org/3/library/smtplib.html
- Python email.mime docs: https://docs.python.org/3/library/email.mime.html
- Gmail App Passwords: https://support.google.com/accounts/answer/185833
"""

import smtplib
import os
import platform
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional

# ── Environment helper (mirrors the pattern already used in your codebase) ──

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
    """
    Read an environment variable from os.environ first, then from the
    Windows registry HKCU\\Environment as a fallback.  This mirrors the
    get_env_value() helper already used in virustotal_api.py and
    ids_full_system.py so that all secrets are kept out of source code.
    """
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


# ── SMTP Configuration (set these as environment variables, never in code) ──
#
#   SMTP_HOST     – e.g. "smtp.gmail.com"         (default shown below)
#   SMTP_PORT     – e.g. "587"                    (STARTTLS port)
#   SMTP_USER     – your sending email address
#   SMTP_PASSWORD – App Password or account password
#   REPORT_TO     – recipient email address
#   REPORT_FROM   – display name / from address   (defaults to SMTP_USER)
#
# Example (Linux/macOS, add to ~/.bashrc or ~/.zshrc):
#   export SMTP_HOST="smtp.gmail.com"
#   export SMTP_PORT="587"
#   export SMTP_USER="your.address@gmail.com"
#   export SMTP_PASSWORD="xxxx xxxx xxxx xxxx"   # Gmail App Password
#   export REPORT_TO="manager@example.com"
#
# Example (Windows PowerShell):
#   $env:SMTP_HOST="smtp.gmail.com"
#   $env:SMTP_PORT="587"
#   $env:SMTP_USER="your.address@gmail.com"
#   $env:SMTP_PASSWORD="xxxx xxxx xxxx xxxx"
#   $env:REPORT_TO="manager@example.com"

SMTP_HOST     = _get_env("SMTP_HOST", "smtp.gmail.com") or "smtp.gmail.com"
SMTP_PORT     = int(_get_env("SMTP_PORT", "587") or "587")
SMTP_USER     = _get_env("SMTP_USER")          # Required
SMTP_PASSWORD = _get_env("SMTP_PASSWORD")      # Required
REPORT_TO     = _get_env("REPORT_TO")          # Required – recipient
REPORT_FROM   = _get_env("REPORT_FROM") or SMTP_USER  # Optional
DASHBOARD_URL = _get_env("DASHBOARD_URL", "http://localhost:5000") or "http://localhost:5000"  # Flask dashboard URL


# ── Severity thresholds ──────────────────────────────────────────────────────
#
# These numbers translate raw anomaly/alert counts into simple traffic-light
# language (CRITICAL / WARNING / ALL CLEAR) so the recipient does not need
# to interpret raw metrics.
#
# Reference for threshold rationale:
#   Zhang et al. (2024) document that pure anomaly-based IDS systems in
#   cyber-physical environments can produce false-positive rates up to 35%.
#   Thresholds below are deliberately conservative so that only genuinely
#   elevated counts trigger a CRITICAL label.

_CRITICAL_ANOMALY_COUNT = 10   # ≥10 anomalies in one cycle → CRITICAL
_WARNING_ANOMALY_COUNT  = 3    # 3-9 anomalies               → WARNING
_CRITICAL_ALERT_COUNT   = 5    # ≥5 Suricata alerts          → CRITICAL


# ── Plain-English label maps ─────────────────────────────────────────────────

# Maps Suricata numeric severity (1 = highest) to readable words.
# Suricata uses 1 for critical, 2 for major, 3 for minor, 4 for info.
# Source: https://docs.suricata.io/en/suricata-7.0.11/rules/meta.html
_SEVERITY_LABELS = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Informational",
}

# Maps the IDS connection state codes Zeek writes into conn.log to
# human-readable descriptions.
# Source: https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html
_CONN_STATE_LABELS = {
    "SF":   "Completed normally",
    "S0":   "No response from target",
    "REJ":  "Connection refused",
    "RSTO": "Connection reset by originator",
    "RSTR": "Connection reset by target",
    "SH":   "Half-open (SYN only)",
    "OTH":  "Mid-stream traffic",
}


# ── Core helpers ─────────────────────────────────────────────────────────────

def _overall_status(anomaly_count: int, alert_count: int) -> str:
    """
    Return a single plain-English status word based on how many anomalies
    and Suricata alerts were detected in the reporting period.
    """
    if anomaly_count >= _CRITICAL_ANOMALY_COUNT or alert_count >= _CRITICAL_ALERT_COUNT:
        return "CRITICAL!!! — Immediate attention required"
    if anomaly_count >= _WARNING_ANOMALY_COUNT or alert_count > 0:
        return "WARNING!!! — Suspicious activity detected"
    return "ALL CLEAR! — No significant threats detected"


def _bytes_to_human(byte_count) -> str:
    """Convert a raw byte integer to a friendly string (KB, MB, GB)."""
    try:
        b = int(byte_count)
    except (TypeError, ValueError):
        return "unknown"
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def _duration_to_human(seconds) -> str:
    """Convert a float number of seconds into a readable duration string."""
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return "unknown"
    if s < 60:
        return f"{s:.1f} seconds"
    if s < 3600:
        return f"{s / 60:.1f} minutes"
    return f"{s / 3600:.1f} hours"


def _describe_anomaly(row: Dict, index: int) -> str:
    """
    Turn one anomaly dictionary (a Zeek conn.log record flagged by the
    Isolation Forest model) into a plain-English paragraph a manager
    can read.

    The Isolation Forest algorithm flags a connection as anomalous when
    its combination of duration, uploaded bytes, and downloaded bytes
    deviates significantly from the normal baseline learned from UNSW-NB15
    training data and the simulated Modbus/DNP3 traffic.
    Reference: Liu et al. (2009) https://doi.org/10.1109/ICDM.2008.17
    """
    src   = row.get("src_bytes", row.get("orig_bytes", 0))
    dst   = row.get("dst_bytes", row.get("resp_bytes", 0))
    dur   = row.get("duration", 0)
    state = _CONN_STATE_LABELS.get(str(row.get("conn_state", "")), "Unknown")

    return (
        f"  • Suspicious Connection #{index + 1}\n"
        f"    Data sent from source  : {_bytes_to_human(src)}\n"
        f"    Data received          : {_bytes_to_human(dst)}\n"
        f"    Connection lasted      : {_duration_to_human(dur)}\n"
        f"    Connection outcome     : {state}\n"
        f"    Why flagged            : This connection's traffic volume and/or\n"
        f"                            duration is unusually different from normal\n"
        f"                            smart grid communication patterns.\n"
    )


def _describe_alert(alert: Dict, index: int) -> str:
    """
    Turn one Suricata alert dictionary into a plain-English paragraph.

    Suricata compares live network packets against a library of known
    attack signatures (rules).  When a packet matches a rule, an alert
    is raised.  This layer catches threats that are already catalogued,
    such as known malware command-and-control beacons or Modbus protocol
    abuse patterns.
    Reference: OISF Suricata 7.0 https://docs.suricata.io/en/suricata-7.0.11/
    """
    sig      = alert.get("signature", "Unknown rule triggered")
    sev_raw  = alert.get("severity", 4)
    sev_text = _SEVERITY_LABELS.get(int(sev_raw), "Unknown")
    src_ip   = alert.get("src_ip", "Unknown source")
    dst_ip   = alert.get("dest_ip", "Unknown destination")
    proto    = str(alert.get("protocol", "Unknown")).upper()

    return (
        f"  • Known-Threat Alert #{index + 1}  [{sev_text}]\n"
        f"    Rule matched  : {sig}\n"
        f"    From          : {src_ip}  →  To: {dst_ip}\n"
        f"    Protocol      : {proto}\n"
        f"    What this means: The network security rule library recognised\n"
        f"                     a pattern consistent with a known attack type.\n"
    )


def _describe_sandbox(result: Dict, index: int) -> str:
    """
    Summarise one sandbox result dictionary in plain English.

    The sandbox works in two stages as described in Chapter 3 of the
    project report:
      1. A local Docker container executes or inspects the suspicious
         file/payload in complete isolation from the live system.
      2. If the local stage flags the sample as suspicious, it is
         submitted to the VirusTotal multi-engine cloud API which checks
         it against 70+ commercial antivirus engines.
    Reference: VirusTotal API https://docs.virustotal.com/reference/overview
    """
    local_verdict = str(result.get("local", "")).lower()
    cloud         = result.get("cloud", {}) or {}
    malicious_n   = cloud.get("malicious_count", 0)
    file_hash     = cloud.get("file_hash", "N/A")
    cloud_path    = result.get("cloud_result_path", "")

    if "malicious" in local_verdict or "suspicious" in local_verdict:
        local_summary = "Flagged as suspicious by the local isolated environment."
    elif "error" in local_verdict:
        local_summary = "Local environment could not complete the analysis."
    else:
        local_summary = "No immediate threat behaviour observed locally."

    if malicious_n:
        cloud_summary = (
            f"{malicious_n} out of 70+ antivirus engines on VirusTotal\n"
            f"    identified this as malicious.\n"
            f"    File fingerprint (SHA-256): {file_hash}"
        )
    elif cloud:
        cloud_summary = (
            f"VirusTotal returned 0 detections for this sample.\n"
            f"    File fingerprint (SHA-256): {file_hash}"
        )
    else:
        cloud_summary = "Not submitted to cloud analysis (local stage was inconclusive)."

    saved_note = f"\n    Full cloud report saved at: {cloud_path}" if cloud_path else ""

    return (
        f"  • Sandbox Analysis #{index + 1}\n"
        f"    Local result  : {local_summary}\n"
        f"    Cloud result  : {cloud_summary}{saved_note}\n"
    )


# ── Email body builder ───────────────────────────────────────────────────────

def _build_email_body(
    anomalies: List[Dict],
    alerts: List[Dict],
    sandbox_results: List[Dict],
    report_period_minutes: int,
) -> str:
    """
    Compose the complete plain-text email body.  The output intentionally
    avoids technical jargon so that any recipient — including grid operators,
    facility managers, or executive stakeholders — can understand the
    security posture without cybersecurity expertise.
    """
    now            = datetime.now().strftime("%d %B %Y at %H:%M:%S")
    status         = _overall_status(len(anomalies), len(alerts))
    anomaly_count  = len(anomalies)
    alert_count    = len(alerts)
    sandbox_count  = len(sandbox_results)

    # ── Header ──────────────────────────────────────────────────────────────
    lines = [
        "=" * 65,
        "  SMART GRID SECURITY SYSTEM — AUTOMATED REPORT",
        "=" * 65,
        f"  Report generated : {now}",
        f"  Monitoring period: Last {report_period_minutes} minutes",
        f"  Overall status   : {status}",
        "=" * 65,
        "",
        "WHAT IS THIS REPORT?",
        "-" * 65,
        "This email is sent automatically by the Hybrid Sandboxed",
        "Intrusion Detection System (IDS) installed to protect the",
        "smart grid network.  It summarises what the system observed",
        f"in the last {report_period_minutes} minutes in plain language.",
        "No action is needed if the status above says ALL CLEAR.",
        "If the status says WARNING or CRITICAL, please contact your",
        "cybersecurity team immediately.",
        "",
    ]

    # ── Section 1: Quick summary numbers ────────────────────────────────────
    lines += [
        "SUMMARY AT A GLANCE",
        "-" * 65,
        f"  Unusual connections flagged by AI  : {anomaly_count}",
        f"  Known attack signatures matched    : {alert_count}",
        f"  Files sent to isolated sandbox     : {sandbox_count}",
        "",
        "HOW DOES THE SYSTEM WORK? (brief explanation)",
        "-" * 65,
        "The system watches all network traffic on the smart grid using",
        "three layers of protection working together:",
        "",
        "  1. KNOWN-THREAT SCANNER (Suricata)",
        "     Compares every packet against a library of known attack",
        "     patterns — like a security guard checking a wanted list.",
        "",
        "  2. BEHAVIOUR ANALYSER (Isolation Forest AI)",
        "     Learns what normal grid traffic looks like and raises an",
        "     alarm when something behaves very differently — like",
        "     noticing an unusually large or long data transfer.",
        "",
        "  3. SANDBOX INSPECTOR (Docker + VirusTotal)",
        "     Any suspicious file or payload is run in a completely",
        "     isolated environment so it cannot harm the real system.",
        "     It is also checked against 70+ antivirus engines online.",
        "",
    ]

    # ── Section 2: Anomaly details ───────────────────────────────────────────
    lines += [
        f"SECTION 1 — UNUSUAL CONNECTIONS DETECTED  ({anomaly_count} total)",
        "-" * 65,
    ]
    if anomaly_count == 0:
        lines += [
            "  No unusual connections were detected during this period.",
            "  The AI model considers all observed traffic to be within",
            "  normal operating parameters.",
            "",
        ]
    else:
        lines.append(
            "  The AI detected the following connections whose traffic\n"
            "  patterns differ significantly from normal grid behaviour:\n"
        )
        for i, row in enumerate(anomalies):
            lines.append(_describe_anomaly(row, i))
        lines.append("")

    # ── Section 3: Suricata alert details ───────────────────────────────────
    lines += [
        f"SECTION 2 — KNOWN ATTACK SIGNATURES MATCHED  ({alert_count} total)",
        "-" * 65,
    ]
    if alert_count == 0:
        lines += [
            "  No known attack signatures were matched during this",
            "  monitoring period.",
            "",
        ]
    else:
        lines.append(
            "  The following known attack patterns were identified:\n"
        )
        for i, alert in enumerate(alerts):
            lines.append(_describe_alert(alert, i))
        lines.append("")

    # ── Section 4: Sandbox results ───────────────────────────────────────────
    lines += [
        f"SECTION 3 — SANDBOX ANALYSIS RESULTS  ({sandbox_count} total)",
        "-" * 65,
    ]
    if sandbox_count == 0:
        lines += [
            "  No files required sandbox analysis during this period.",
            "",
        ]
    else:
        lines.append(
            "  The following suspicious items were analysed in the\n"
            "  isolated sandbox environment:\n"
        )
        for i, result in enumerate(sandbox_results):
            lines.append(_describe_sandbox(result, i))
        lines.append("")

    # ── Footer ───────────────────────────────────────────────────────────────
    lines += [
        "=" * 65,
        "RECOMMENDED ACTIONS",
        "-" * 65,
    ]
    if _overall_status(anomaly_count, alert_count).startswith("✅"):
        lines += [
            "  No immediate action required.  Continue monitoring.",
        ]
    else:
        lines += [
            "  1. View detailed results in the security dashboard:",
            f"     {DASHBOARD_URL}",
            "",
            "  2. Forward this email to your cybersecurity team.",
            "  3. Do not dismiss alerts without professional review.",
            "  4. If operations seem abnormal, consider isolating the",
            "     affected network segment and contacting your ICS/OT",
            "     security specialist.",
            "  5. Full technical logs are available in the Kibana",
            "     dashboard at:  http://localhost:5601",
        ]

    lines += [
        "",
        "=" * 65,
        "QUICK LINKS",
        "-" * 65,
        f"  📊 Live Dashboard    : {DASHBOARD_URL}",
        f"  📈 ELK Analytics     : http://localhost:5601",
        f"  ✉️  Questions?         : Contact your security team",
        "",
        "=" * 65,
        "  This report was generated automatically by the",
        "  Hybrid Sandboxed IDS — Final Year Project",
        "  Danielle Mbala Erusiafe | 2023/A/CYB/0065",
        "  Miva Open University, Department of Cyber Security",
        "=" * 65,
    ]

    return "\n".join(lines)


# ── Public API ───────────────────────────────────────────────────────────────

def send_ids_report(
    anomalies: Optional[List[Dict]] = None,
    alerts: Optional[List[Dict]] = None,
    sandbox_results: Optional[List[Dict]] = None,
    report_period_minutes: int = 30,
    recipient_override: Optional[str] = None,
) -> bool:
    """
    Compose and send a plain-English IDS summary email.

    Parameters
    ----------
    anomalies : list of dicts
        Each dict is a Zeek conn.log row that the Isolation Forest model
        scored as anomalous (label == 'Suspicious').  This is the
        ``anomalies`` DataFrame converted via .to_dict('records') inside
        ids_full_system.py.

    alerts : list of dicts
        Each dict is one Suricata EVE JSON alert as returned by
        check_suricata() in ids_full_system.py.

    sandbox_results : list of dicts
        Each dict is the return value of send_to_sandbox() in
        ids_full_system.py, which may contain 'local', 'cloud',
        'malicious_count', 'file_hash', and 'cloud_result_path' keys.

    report_period_minutes : int
        How many minutes of monitoring this report covers.  Used only in
        the email body to give the reader context.  Defaults to 30,
        matching the MONITORING_INTERVAL = 30 setting in ids_full_system.py.

    recipient_override : str, optional
        If provided, sends the report to this address instead of the
        REPORT_TO environment variable.  Useful for testing.

    Returns
    -------
    bool
        True if the email was sent successfully, False otherwise.
    """
    # Sanitise inputs — treat None as empty list
    anomalies       = anomalies or []
    alerts          = alerts or []
    sandbox_results = sandbox_results or []

    # Check required SMTP settings
    if not SMTP_USER or not SMTP_PASSWORD:
        print(
            "[EmailReporter] ERROR: SMTP_USER and SMTP_PASSWORD environment "
            "variables must be set before emails can be sent.\n"
            "  Example (Linux):\n"
            "    export SMTP_USER='you@gmail.com'\n"
            "    export SMTP_PASSWORD='xxxx xxxx xxxx xxxx'  # Gmail App Password"
        )
        return False

    to_address = recipient_override or REPORT_TO
    if not to_address:
        print(
            "[EmailReporter] ERROR: REPORT_TO environment variable is not set. "
            "Set it to the recipient's email address."
        )
        return False

    # ── Build the email ──────────────────────────────────────────────────────
    body    = _build_email_body(anomalies, alerts, sandbox_results, report_period_minutes)
    status  = _overall_status(len(anomalies), len(alerts))

    # Subject line includes status so the recipient can triage at a glance
    # from their inbox without opening the email.
    subject = (
        f"[Smart Grid IDS] Security Report — "
        f"{datetime.now().strftime('%d %b %Y %H:%M')} — "
        f"{status.split('—')[0].strip()}"
    )

    # Build MIME message — plain text keeps it compatible with all email
    # clients and avoids spam filters that sometimes flag HTML emails.
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = REPORT_FROM or SMTP_USER
    msg["To"]      = to_address
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # ── Send via SMTP with STARTTLS ──────────────────────────────────────────
    # STARTTLS upgrades a plain connection to an encrypted one on port 587.
    # Reference: Python smtplib https://docs.python.org/3/library/smtplib.html
    try:
        print(f"[EmailReporter] Connecting to {SMTP_HOST}:{SMTP_PORT} ...")
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.ehlo()           # Identify ourselves to the server
            server.starttls()       # Upgrade to encrypted connection
            server.ehlo()           # Re-identify over encrypted channel
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_address, msg.as_string())

        print(f"[EmailReporter] ✔  Report sent to {to_address}")
        return True

    except smtplib.SMTPAuthenticationError:
        print(
            "[EmailReporter] ERROR: SMTP authentication failed.\n"
            "  • For Gmail, make sure you are using an App Password, not your\n"
            "    regular account password.\n"
            "  • App Passwords: https://myaccount.google.com/apppasswords"
        )
    except smtplib.SMTPConnectError:
        print(
            f"[EmailReporter] ERROR: Could not connect to {SMTP_HOST}:{SMTP_PORT}.\n"
            "  Check SMTP_HOST and SMTP_PORT environment variables."
        )
    except smtplib.SMTPException as exc:
        print(f"[EmailReporter] SMTP error: {exc}")
    except OSError as exc:
        print(f"[EmailReporter] Network error: {exc}")

    return False