from scapy.all import Ether, IP, TCP, Raw, ICMP, wrpcap
import pandas as pd
import random
import warnings
from mininet.log import info


warnings.filterwarnings("ignore")

def load_trace_file():
    # trace_file = '../1. Data Preparation/parsed_packet_trace.csv'
    trace_file = '../1. Data Preparation/flows.csv'
    packets = pd.read_csv(trace_file)

    return packets


def gen_packet(src_ip, dst_ip, src_port, dst_port, protocol, pkt_size):
    # Generate packet
    packet = Ether(type=0x0800) / IP(src=src_ip, dst=dst_ip, proto=protocol) / TCP(sport=src_port, dport=dst_port) / ICMP()

    # Create a packet with padding to achieve the desired size
    padding_size = pkt_size - len(packet)
    padding = b'\x00' * padding_size

    packet = packet / Raw(load=padding)

    return packet


def get_packet_random(packets, host_ips, elephant_probability=[10, 1]):
    elephant = random.choices([0, 1], weights=elephant_probability, k=1)[0]
    packets = packets[packets['elephant'] == elephant]

    # Generate a random index within the range of available packets
    random_index = random.randint(0, len(packets) - 1)

    # Get the random packet at the generated index
    packet_info = packets.iloc[random_index]

    protocol = packet_info[0]
    src_port = packet_info[1]
    dst_port = packet_info[2]
    pkt_size = packet_info[3]

    random_ips = random.sample(host_ips, 2)
    src_ip = random_ips[0]
    dst_ip = random_ips[1]
    
    packet = gen_packet(src_ip, dst_ip, src_port, dst_port, protocol, pkt_size)

    return packet, elephant


def get_packet_sequenced(packets, host_ips, elephant_flows, mice_flows, elephant_probability=[10, 1]):
    elephant = random.choices([0, 1], weights=elephant_probability, k=1)[0]
    packets = packets[packets['elephant'] == elephant]

    # Get a sequenced index within the range of available packets
    seq_index = elephant_flows if elephant == 1 else mice_flows

    # Get the random packet at the generated index
    packet_info = packets.iloc[seq_index]

    protocol = packet_info[0]
    src_port = packet_info[1]
    dst_port = packet_info[2]
    pkt_size = packet_info[3]

    random_ips = random.sample(host_ips, 2)
    src_ip = random_ips[0]
    dst_ip = random_ips[1]
    
    packet = gen_packet(src_ip, dst_ip, src_port, dst_port, protocol, pkt_size)

    return packet, elephant


if __name__ == '__main__':
    host_ips = [
        '10.0.0.1',
        '10.0.0.2',
        '10.0.0.3',
        '10.0.0.4',
        '10.0.0.5',
    ]

    packets = load_trace_file()
    packet = get_packet(packets, host_ips)

    # Access packet information
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    protocol = packet[IP].proto
    pkt_size = len(packet)

    # Print packet information
    print("Source IP:", src_ip)
    print("Destination IP:", dst_ip)
    print("Source Port:", src_port)
    print("Destination Port:", dst_port)
    print("Protocol:", protocol)
    print("Packet Size:", pkt_size)
    print(packet)