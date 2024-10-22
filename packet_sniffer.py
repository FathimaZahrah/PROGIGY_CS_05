from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process captured packets
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        if TCP in packet:
            proto_name = "TCP"
        elif UDP in packet:
            proto_name = "UDP"
        elif ICMP in packet:
            proto_name = "ICMP"
        else:
            proto_name = "Other"

        print(f"Source: {ip_src} -> Destination: {ip_dst} | Protocol: {proto_name}")

        # If you want to see more detailed information like payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}\n")

# Start packet sniffing
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
