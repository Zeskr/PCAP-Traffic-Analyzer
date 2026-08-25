import argparse
import sys
import logging
# Suppress scapy IPv6 warnings for a pristine terminal output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, DNS, DNSQR, IP

def analyze_pcap(file_path):
    print(f"[*] Ingesting Network Capture: {file_path}")
    try:
        packets = rdpcap(file_path)
        print(f"[+] Successfully loaded {len(packets)} packets.\n")
    except Exception as e:
        print(f"[!] Error loading PCAP: {e}")
        sys.exit(1)

    print("[*] Initiating Heuristic Analysis for DNS Exfiltration...")
    anomalies_found = 0

    for pkt in packets:
        # Check if packet has an IP layer and a DNS Question Record
        if pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            src_ip = pkt[IP].src

            # Anomaly Threshold
            if len(query) > 60:
                print(f"[!] ANOMALY DETECTED: Extralong DNS Query")
                print(f"    Source IP: {src_ip}")
                print(f"    Query: {query}")
                anomalies_found += 1

    if anomalies_found == 0:
        print("[+] No DNS anomalies detected in this capture.")
    else:
        print(f"\n[!] Analysis Complete: {anomalies_found} potential exfiltration attempts flagged.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP Anomaly Detector")
    parser.add_argument("-f", "--file", required=True, help="Path to the .pcap file")
    args = parser.parse_args()
    analyze_pcap(args.file)
