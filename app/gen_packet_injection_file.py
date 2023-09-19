from scapy.all import Ether, IP, TCP, Raw, ICMP, wrpcap
import pandas as pd
import random
import warnings
from mininet.log import info
from vn_settings import *
import csv
import numpy as np


warnings.filterwarnings("ignore")

def load_trace_file():
    flows_file = 'datasets/flows_4.csv'
    trace_file = 'datasets/mawi_packet_trace_original.csv'

    packets = pd.read_csv(trace_file)
    flows = pd.read_csv(flows_file)

    return packets, flows


def get_data_size(src_ip, dst_ip, src_port, dst_port, protocol, pkt_size):
    # Generate packet
    packet = Ether(type=0x0800) / IP(src=src_ip, dst=dst_ip, proto=protocol) / TCP(sport=src_port, dport=dst_port) / ICMP()

    # Create a packet with padding to achieve the desired size
    padding_size = pkt_size - len(packet)
    data_size = padding_size if padding_size > 0 else 0
    data_size = data_size + 8

    return data_size


def get_flow_random(packets, elephant_probability=[10, 1]):
    elephant = random.choices([0, 1], weights=elephant_probability, k=1)[0]
    packets = packets[packets['elephant'] == elephant]

    # Generate a random index within the range of available packets
    random_index = random.randint(0, len(packets) - 1)

    # Get the random packet at the generated index
    packet_info = packets.iloc[random_index]

    src_ip = packet_info[2]
    dst_ip = packet_info[3]
    protocol = packet_info[4]
    src_port = packet_info[5]
    dst_port = packet_info[6]
    pkt_size = packet_info[7]

    return src_ip, dst_ip, protocol, src_port, dst_port, pkt_size, elephant


def get_flow_sequential(packets, elephant_flows, mice_flows, elephant_probability=[10, 1]):
    elephant = random.choices([0, 1], weights=elephant_probability, k=1)[0]
    packets = packets[packets['elephant'] == elephant]

    # Get a sequenced index within the range of available packets
    seq_index = elephant_flows if elephant == 1 else mice_flows

    # Get the random packet at the generated index
    packet_info = packets.iloc[seq_index]

    src_ip = packet_info[2]
    dst_ip = packet_info[3]
    protocol = packet_info[4]
    src_port = packet_info[5]
    dst_port = packet_info[6]
    pkt_size = packet_info[7]

    return src_ip, dst_ip, protocol, src_port, dst_port, pkt_size, elephant

def get_sort(time, last_time):
    if time - last_time == 0:
        serial = 0.01
    elif time - last_time > 0:
        serial = time - last_time
    else:
        serial = 0

    return serial


def get_flow_packets(packets, host_ips, src_ip, dst_ip, protocol, src_port, dst_port, pkt_size, elephant):
    flow_packets = packets.query(f'src_ip=="{src_ip}" & dst_ip=="{dst_ip}" & protocol=={protocol} & src_port=={src_port} & dst_port=={dst_port}').head(7)

    if len(flow_packets) > 0:
        flow_packets['last_pkt_time'] = flow_packets['timestamp'].shift(1)

        # flow_packets['iat'] = flow_packets['timestamp'] - flow_packets['last_pkt_time']
        flow_packets['iat'] = np.vectorize(get_sort)(flow_packets['timestamp'], flow_packets['last_pkt_time'])

        random_ips = random.sample(host_ips, 2)
        src_ip = random_ips[0]
        dst_ip = random_ips[1]

        flow_packets['src_ip'] = src_ip
        flow_packets['dst_ip'] = dst_ip
        
        flow_packets['elephant'] = elephant

        flow_packets['data_size'] = np.vectorize(get_data_size)(src_ip, dst_ip, src_port, dst_port, protocol, pkt_size)
    
    return flow_packets


def gen_injection_file(host_ips):
    print('Loading data.............')
    packets, flows = load_trace_file()

    # packets = packets.query('protocol==6 | protocol==17')

    output_file = 'datasets/packet_injection1.csv'

    columns = ['iat', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'pkt_size', 'data_size', 'elephant']

    injection_file = open(output_file, 'w', newline='')
    writer = csv.writer(injection_file)
    writer.writerow(columns)
    injection_file.close()

    total_flows = inj_flows_count

    elephant_flows = 0
    mice_flows = 0

    created_packets = 0

    while total_flows > elephant_flows + mice_flows:
        # get flow from flows file
        if pkt_injection_type == 'sequential':
            src_ip, dst_ip, protocol, src_port, dst_port, pkt_size, elephant = get_flow_sequential(flows, elephant_flows, mice_flows, injection_ratio)
        else:
            src_ip, dst_ip, protocol, src_port, dst_port, pkt_size, elephant = get_flow_random(flows, injection_ratio)

        # search first 7 packets of flow from packets file
        flow_packets = get_flow_packets(packets, host_ips, src_ip, dst_ip, protocol, src_port, dst_port, pkt_size, elephant)

        # Append dataframe to a csv file
        if len(flow_packets) > 0:
            flow_packets = flow_packets[columns]
            # if created_packets == 0:
            flow_packets.to_csv(output_file, mode='a', index=False, header=False)
            # else:
            #     flow_packets.to_csv(output_file, mode='a', index=False, header=False)

            created_packets = created_packets + len(flow_packets)

            if elephant == 1:
                elephant_flows = elephant_flows + 1
            else:
                mice_flows = mice_flows + 1

            print(f'Packets created: {created_packets}, Elephant Flows: {elephant_flows}, Mice Flow: {mice_flows}')

    print('Done')




if __name__ == '__main__':
    host_ips = [
        '10.0.0.1',
        '10.0.0.2',
        '10.0.0.3',
        '10.0.0.4',
        '10.0.0.5',
    ]

    gen_injection_file(host_ips)