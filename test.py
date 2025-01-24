from scapy.all import sniff, wrpcap
from datetime import datetime

# Define a callback function to process captured packets
def packet_handler(packet):
    # Convert the timestamp to a readable format with milliseconds
    timestamp = datetime.fromtimestamp(packet.time).strftime('%S.%f')[:-3]
    print(f"Time: {timestamp}, Packet: {packet.summary()}")

# Capture packets
print("Starting packet capture. Press Ctrl+C to stop.")
packets = sniff(iface="Wi-Fi", count=500, prn=packet_handler)  # Capture 100 packets

# Save packets to a PCAP file
pcap_file = "captured_packets.pcap"
wrpcap(pcap_file, packets)
print(f"Packets saved to {pcap_file}")
