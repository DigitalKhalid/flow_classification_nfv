'''
Convert PCAP file to CSV:
    - 1. Create a blank file with defined column names 
    - 2. Read and get each packet from the PCAP file
    - 3. Append each packet to the new row of created file using CSV library
    - 4. This process is good for very large PCAP file and consumes less memory. If there is a problem during this process, we have
            CSV file with all packet data that has been processed. We can even stop the process when we need.
'''
from scapy.all import *
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
import pandas as pd
import csv

# path of pcap file to be converted to csv
pcap_file = "mawi.pcap"

# useful variables to track processing
max_packets = float('inf')
processed_packet = 0
invalid_count = 0

# path of output csv file
file_name = 'parsed_packet_trace_2.csv'

# Columns to be added at the first row of output file
columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'pkt_size']

# Add new file / overwrite the existing file if same filename is already exist 
output_file = open(file_name, 'w', newline='')
writer = csv.writer(output_file)
writer.writerow(columns)

# Set output file setting to append new lines
output_file = open(file_name, 'a', newline='')

# Itterate through pcap file
for packet, (sec, usec, wirelen, caplen) in RawPcapReader(pcap_file):
    processed_packet += 1

    try:
        if processed_packet >= max_packets:
            print(f'Extracted {processed_packet - invalid_count} ethernet packets out of {processed_packet} packets.')
            output_file.close()
            break

        # process only ethernet packets
        ether_packet = Ether(packet)

        if ether_packet[IP]:
            ip_packet = ether_packet[IP]
            protocol = ip_packet.fields['proto']
            ipv4_src = ip_packet.src
            ipv4_dst = ip_packet.dst

            if protocol == 17:
                udp_packet = ip_packet[UDP]
                sport = udp_packet.sport
                dport = udp_packet.dport

            if protocol == 6:
                tcp_packet = ip_packet[TCP]
                sport = tcp_packet.sport
                dport = tcp_packet.dport

        # Append packet information to the output file
        packet_trace = [sec, ipv4_src, ipv4_dst, sport, dport, protocol, wirelen]
        writer.writerow(packet_trace)

        # Showing progress while running the code
        if processed_packet % 10000 == 0:
            print(f'Processed {processed_packet} packets')

    except:
        # Count non ethernet packets
        invalid_count += 1