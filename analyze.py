import pyshark

# Read the PCAP file
pcap_file = "captured_packets.pcap"
cap = pyshark.FileCapture(pcap_file)

# Display captured packets
for packet in cap:
    print(packet)
