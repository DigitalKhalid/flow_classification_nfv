''' 
Convert PCAP file to CSV:
    - 1. Read and Get all packets in a dictionary
    - 2. Create dataframe from dictionary
    - 3. Save dataframe to CSV file using Pandas
    - 4. This method is not suitable for very large PCAP files as all packets processed in a dictionary consumes a lot of memory
            then save to the CSV file at the end. If there is a problem during the process, no CSV file with a single packet will be created.
'''

from scapy.all import *
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
import pandas as pd


pcap_file = "mawi.pcap"

max_packets = float('inf')
processed_packet = 0
invalid_count = 0

packet_traces = {
    'timestamp': [],
    'src_ip': [],
    'dst_ip': [],
    'src_port': [],
    'dst_port': [],
    'protocol': [],
    'pkt_size': [],
    }

for packet, (sec, usec, wirelen, caplen) in RawPcapReader(pcap_file):
    processed_packet += 1

    try:
        if processed_packet >= max_packets:
            print(f'Extracted {processed_packet - invalid_count} ethernet packets out of {processed_packet} packets.')
            break

        # pcap_statistics['pkt_num'] += 1
        ether_packet = Ether(packet)
        a = 0

        if ether_packet[IP]:
            ip_packet = ether_packet[IP]
            protocol = ip_packet.fields['proto']
            ipv4_src = ip_packet.src
            ipv4_dst = ip_packet.dst
            sport = 0
            dport = 0

            if protocol == 17:
                udp_packet = ip_packet[UDP]
                sport = udp_packet.sport
                dport = udp_packet.dport

            if protocol == 6:
                tcp_packet = ip_packet[TCP]
                sport = tcp_packet.sport
                dport = tcp_packet.dport

        flow_key = (ipv4_dst, ipv4_src, dport, sport, protocol)

        packet_traces['timestamp'].append(sec)
        packet_traces['src_ip'].append(ipv4_src)
        packet_traces['dst_ip'].append(ipv4_dst)
        packet_traces['src_port'].append(sport)
        packet_traces['dst_port'].append(dport)
        packet_traces['protocol'].append(protocol)
        packet_traces['pkt_size'].append(wirelen)

        if processed_packet % 1000 == 0:
            print(f'Processed {processed_packet} packets')

    except:
        invalid_count += 1


# Export dataset csv.
output_file = 'parsed_packet_trace.csv'
df = pd.DataFrame.from_dict(packet_traces)
df.to_csv(output_file, index=False)