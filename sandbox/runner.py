import os
import sys
import csv

print("Sandbox started - isolated execution environment")
file_arg = sys.argv[1] if len(sys.argv) > 1 else None
print(f"Sandbox received file: {file_arg}")

SUSPICIOUS_THRESHOLDS = {
    "src_bytes": 10000,   # >10KB source bytes
    "dst_bytes": 10000,   # >10KB destination bytes
    "duration": 5.0,       # >5 secs connection
}

def analyze_file(file_path):
    if not file_path or not os.path.exists(file_path):
        print("Error: File not found")
        return

    try:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    src_bytes = float(row.get("src_bytes", 0) or 0)
                    dst_bytes = float(row.get("dst_bytes", 0) or 0)
                    duration  = float(row.get("duration", 0) or 0)

                    flags = []
                    if src_bytes > SUSPICIOUS_THRESHOLDS["src_bytes"]:
                        flags.append(f"high src_bytes={src_bytes}")
                    if dst_bytes > SUSPICIOUS_THRESHOLDS["dst_bytes"]:
                        flags.append(f"high dst_bytes={dst_bytes}")
                    if duration > SUSPICIOUS_THRESHOLDS["duration"]:
                        flags.append(f"long duration={duration}s")

                    if flags:
                        print(f"Suspicious behavior detected - potential malware "
                              f"({', '.join(flags)})")
                    else:
                        print("Clean file - no threats detected")

                except (ValueError, TypeError):
                    continue

    except Exception as e:
        print(f"Analysis error: {e}")

analyze_file(file_arg)