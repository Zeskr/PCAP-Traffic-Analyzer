FROM python:3.11-slim

# Install system-level libpcap dependencies required by Scapy's C-backend
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pcap_analyzer.py .
ENTRYPOINT ["python3", "pcap_analyzer.py"]
