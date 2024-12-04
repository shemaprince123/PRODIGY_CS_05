from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to handle each captured packet
def packet_handler(packet):
    if IP in packet:  # Check if the packet has an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Determine protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = proto

        # Print packet details
        print(f"\n[+] {protocol} Packet:")
        print(f"    Source IP: {src_ip}")
        print(f"    Destination IP: {dst_ip}")

        # Display payload (if available)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload: {payload.decode(errors='ignore')}")
        else:
            print("    No payload data.")

# Capture packets on the default network interface
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_handler, count=20)  # Capture 20 packets; modify as needed
