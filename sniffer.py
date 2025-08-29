# Task 1: Basic Network Sniffer - CodeAlpha Internship
# Author: [ahmed haitham]
# Repository: CodeAlpha_NetworkSniffer

from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    """
    Function to process and display captured packets
    """
    if IP in packet:  # Check if packet has IP layer
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:  # TCP
            protocol = "TCP"
        elif proto == 17:  # UDP
            protocol = "UDP"
        elif proto == 1:  # ICMP
            protocol = "ICMP"
        else:
            protocol = str(proto)

        print(f"\n[+] New Packet Captured")
        print(f"    Source IP      : {ip_src}")
        print(f"    Destination IP : {ip_dst}")
        print(f"    Protocol       : {protocol}")

        # Show payload if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            try:
                payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
                if payload:
                    print(f"    Payload (raw)  : {payload[:50]}...")  # Show first 50 bytes
            except:
                pass

# Sniff network packets
print("🚀 Starting Basic Network Sniffer...")
print("Press Ctrl+C to stop.\n")
sniff(prn=process_packet, store=False)
