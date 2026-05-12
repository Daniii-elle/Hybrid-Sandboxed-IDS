FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy sandbox files only....
COPY runner.py .
COPY virustotal_api.py .

# Install dependencies — added requests
RUN pip install --no-cache-dir requests pandas numpy scikit-learn joblib flask scapy

# Create data mount point
RUN mkdir -p /data

# Use ENTRYPOINT so file path argument is always passed through correctly
ENTRYPOINT ["python", "runner.py"]