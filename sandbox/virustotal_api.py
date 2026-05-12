import requests
import os
import hashlib
import platform

if platform.system() == "Windows":
    try:
        import winreg
    except ImportError:
        winreg = None


def get_env_value(name, default=None):
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

SANDBOX_SERVICE = get_env_value("SANDBOX_SERVICE", "virustotal")  # Options: virustotal, hybrid_analysis, local_only

# API Keys 
VIRUSTOTAL_API_KEY = get_env_value("VIRUSTOTAL_API_KEY")
HYBRID_ANALYSIS_API_KEY = get_env_value("HYBRID_ANALYSIS_API_KEY")

def send_to_sandbox(file_path):
    """Send file to selected sandbox service"""

    if SANDBOX_SERVICE == "virustotal":
        return send_to_virustotal(file_path)
    elif SANDBOX_SERVICE == "hybrid_analysis":
        return send_to_hybrid_analysis(file_path)
    elif SANDBOX_SERVICE == "local_only":
        return {"result": "Local analysis only - no cloud escalation"}
    else:
        return {"error": f"Unknown sandbox service: {SANDBOX_SERVICE}"}

def send_to_virustotal(file_path):
    """Send file to VirusTotal (free tier: 500 requests/day)"""
    print("Sending to VirusTotal...")

    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set"}

    try:
        # Calculate file hash
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        # Check if file already analyzed
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            detections = result["data"]["attributes"]["last_analysis_stats"]
            malicious = detections.get("malicious", 0)
            print(f"VirusTotal: {malicious} detections")
            return {"virustotal": result, "malicious_count": malicious, "file_hash": file_hash}

        # If not analyzed, upload file
        print("File not in VirusTotal database, uploading...")
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files=files
            )

        if response.status_code == 200:
            result = response.json()
            analysis_id = result.get("data", {}).get("id")
            print(f"VirusTotal analysis submitted ID: {analysis_id}")
            print("Note: Analysis may take 1-2 minutes. Re-run to get results.")
            return {"virustotal": result, "file_hash": file_hash, "status": "submitted"}
        else:
            return {"error": f"VirusTotal upload failed: {response.text}", "file_hash": file_hash}
        
    except Exception as e:
        return {"error": f"VirusTotal failed: {str(e)}"}

def send_to_hybrid_analysis(file_path):
    """Send file to Hybrid Analysis (free tier available)"""
    print("Sending to Hybrid Analysis...")

    if not HYBRID_ANALYSIS_API_KEY:
        return {"error": "HYBRID_ANALYSIS_API_KEY not set"}
    
    try:
        url = "https://www.hybrid-analysis.com/api/v2/submit/file"
        headers = {
            "api-key": HYBRID_ANALYSIS_API_KEY,
            "user-agent": "IDS_System/1.0"
        }

        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(url, headers=headers, files=files)

        if response.status_code == 201:
            result = response.json()
            print("Hybrid Analysis submission successful")
            return {"hybrid_analysis": result}
        else:
            return {"error": f"Hybrid Analysis failed: {response.text}"}
    except Exception as e:
        return {"error": f"Hybrid Analysis failed: {str(e)}"}
    

# Legacy Joe Sandbox function (kept for compatibility)
# def send_to_joe_sandbox(file_path):
#     """Original Joe Sandbox implementation"""
#     print("Sending to Joe Sandbox...")

#     API_KEY = os.getenv("JOE_API_KEY")
#     JOE_URL = "https://jbxcloud.joesecurity.org/api/v2/analysis/submit"

#     if not API_KEY:
#         return {"error": "JOE_API_KEY not set"}

#     try:
#         with open(file_path, "rb") as f:
#             response = requests.post(
#                 JOE_URL,
#                 headers={"Authorization": f"Bearer {API_KEY}"},
#                 files={"file": f}
#             )

#         if response.status_code == 200:
#             result = response.json()
#             print("Joe Sandbox analysis started")
#             return result
#         else:
#             return {"error": f"Joe Sandbox error: {response.text}"}

#     except Exception as e:
#         return {"error": f"Joe Sandbox failed: {str(e)}"}