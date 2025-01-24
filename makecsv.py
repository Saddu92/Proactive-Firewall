import csv
from scapy.all import rdpcap

# Function to extract features from packets
def extract_features(packet):
    features = {}
    if packet.haslayer('IP'):
        features['Source IP'] = packet['IP'].src
        features['Destination IP'] = packet['IP'].dst
        features['Protocol'] = packet['IP'].proto
    else:
        features['Source IP'] = None
        features['Destination IP'] = None
        features['Protocol'] = None

    if packet.haslayer('TCP'):
        features['Source Port'] = packet['TCP'].sport
        features['Destination Port'] = packet['TCP'].dport
        features['Flags'] = str(packet['TCP'].flags)
    else:
        features['Source Port'] = None
        features['Destination Port'] = None
        features['Flags'] = None

    if packet.haslayer('UDP'):
        features['Source Port'] = packet['UDP'].sport
        features['Destination Port'] = packet['UDP'].dport

    features['Packet Length'] = len(packet)
    return features

# Read packets from a pcap file
packets = rdpcap('captured_packets.pcap')  # Replace with your pcap file path

# Extract features and save to CSV
output_file = 'packet_features.csv'
with open(output_file, mode='w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=[
        'Source IP', 'Destination IP', 'Protocol', 
        'Source Port', 'Destination Port', 'Flags', 'Packet Length'
    ])
    writer.writeheader()
    for packet in packets:
        features = extract_features(packet)
        writer.writerow(features)

print(f"Packet features saved to {output_file}")
