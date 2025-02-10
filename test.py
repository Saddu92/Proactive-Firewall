from scapy.all import sniff, wrpcap
from datetime import datetime
from collections import defaultdict

# Flow data dictionary
flows = defaultdict(lambda: {
    'src_ip': None, 'fwd_pkts': 0, 'bwd_pkts': 0,
    'fwd_len': 0, 'bwd_len': 0,
    'start_time': None, 'end_time': None
})

# Define a callback function to process captured packets
def packet_handler(packet):
    # Skip non-IP packets
    if not packet.haslayer('IP'):
        return

    # Extract source/destination IP, port, and protocol
    src_ip = packet['IP'].src
    dst_ip = packet['IP'].dst
    protocol = None
    dst_port = None
    syn_flag_cnt = 0

    if packet.haslayer('TCP'):
        protocol = 'TCP'
        dst_port = packet['TCP'].dport
        syn_flag_cnt = packet['TCP'].flags.S
    elif packet.haslayer('UDP'):
        protocol = 'UDP'
        dst_port = packet['UDP'].dport

    # Create a unique flow key based on src/dst IP, src/dst port, and protocol
    flow_key = (src_ip, dst_ip, dst_port, protocol)

    # Track flow metrics
    flow = flows[flow_key]
    flow['end_time'] = packet.time
    if flow['start_time'] is None:
        flow['start_time'] = packet.time
        flow['src_ip'] = src_ip  # Set the flow's source IP on the first packet

    # Count forward and backward packets and calculate lengths
    if src_ip == flow['src_ip']:
        flow['fwd_pkts'] += 1
        flow['fwd_len'] += len(packet)
    else:
        flow['bwd_pkts'] += 1
        flow['bwd_len'] += len(packet)

    # Calculate flow duration and bytes/sec
    flow_duration = flow['end_time'] - flow['start_time']
    flow_bytes_per_sec = (flow['fwd_len'] + flow['bwd_len']) / flow_duration if flow_duration > 0 else 0

    # Calculate forward and backward packet length means
    fwd_pkt_len_mean = flow['fwd_len'] / flow['fwd_pkts'] if flow['fwd_pkts'] > 0 else 0
    bwd_pkt_len_mean = flow['bwd_len'] / flow['bwd_pkts'] if flow['bwd_pkts'] > 0 else 0

    # Print the extracted details
    timestamp = datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')[:-3]
    print(f"Time: {timestamp}, "
          f"Destination Port: {dst_port}, "
          f"Protocol: {protocol}, "
          f"Flow Duration: {flow_duration:.2f}, "
          f"Total Forward Packets: {flow['fwd_pkts']}, "
          f"Total Backward Packets: {flow['bwd_pkts']}, "
          f"Forward Packet Length Mean: {fwd_pkt_len_mean:.2f}, "
          f"Backward Packet Length Mean: {bwd_pkt_len_mean:.2f}, "
          f"Flow Bytes/sec: {flow_bytes_per_sec:.2f}, "
          f"SYN Flag Count: {syn_flag_cnt}, "
          f"Packet Summary: {packet.summary()}")

# Capture packets
print("Starting packet capture. Press Ctrl+C to stop.")
packets = sniff(iface="Wi-Fi", count=500, prn=packet_handler)  # Capture 500 packets

# Save packets to a PCAP file
pcap_file = "captured_packets.pcap"
wrpcap(pcap_file, packets)
print(f"Packets saved to {pcap_file}")