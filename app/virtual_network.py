from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import info, setLogLevel
from mininet.link import TCLink
import warnings
import time
import datetime
from packet_injection import load_trace_file
from topology import SimpleTopology
import csv
from vn_settings import *


warnings.filterwarnings("ignore")
setLogLevel( 'info' )

def inject_packets(net, start_time, network_duration, packets, host_ips, log_file):
    packet_count = 0
    elephant = 0
    mice = 0

    while time.time() < start_time + network_duration:
        if packet_count < len(packets):
            # pkt_iat = random.uniform(0, pkt_injection_time)
            # time.sleep(pkt_iat)
            packet_info = packets.iloc[packet_count]
            packet_count = packet_count + 1
            
            send_packet(net, packet_info, host_ips, log_file)
        
        else:
            break
        
    return packet_count, elephant, mice


def send_packet(net, packet, host_ips, log_file):
    src_ip = packet[1]
    dst_ip = packet[2]
    src_port = packet[3]
    dst_port = packet[4]
    protocol = packet[5]
    pkt_size = packet[6]
    data_size = packet[7]
    elephant = packet[8]

    proto = '' if protocol == 6 else ' -1' if protocol == 17 else ' -2'
    data_size = f' -d {data_size}' if data_size > 0 else ''

    host = net.get(f'h{host_ips.index(src_ip) + 1}')
    cmd = f'hping3 -c 1 -s {src_port} -p {dst_port}{data_size}{proto} --numeric {dst_ip}'
    host.cmd(cmd)
    
    # Add Log
    log = [time.time(), src_ip, dst_ip, src_port, dst_port, protocol, pkt_size, elephant]
    info(f'\nInjection Log: {log}\n')
    add_log(log, log_file)


def add_log(log, log_file):   
    with open(log_file, 'a', newline = '') as logs:
        writer = csv.writer(logs)
        writer.writerow(log)


def write_summary(summary_file, hosts_ips, start_time, packet_count, elephants, mice):
    summary = open(summary_file, "w")

    summary.write(f'\nVirtual Network Simulation Summary by Digital Khalid\n')
    summary.write('\n==============================================================================================================\n')
    summary.write('Network Overview:\n')
    summary.write('==============================================================================================================\n')
    summary.write('Virtual Network: Mininet\n')
    summary.write('Controller: Ryu\n')
    summary.write('No. of Switches: 1\n')
    summary.write(f'No. of Hosts: {len(hosts_ips)}\n')
    summary.write(f'Host IP Addresses: {hosts_ips}\n')
    summary.write('\n==============================================================================================================\n')
    summary.write('Packet Injection Overview:\n')
    summary.write('==============================================================================================================\n')
    summary.write(f'Start Time: {get_time(start_time)}\n')
    summary.write(f'End Time: {get_time(time.time())}\n')
    summary.write(f'Total Packets Injected: {packet_count}\n')
    summary.write(f'Actual Elephants Injected: {elephants}\n')
    summary.write(f'Actual Mice Injected: {mice}\n')
    summary.write(f'Packets injected using the flows file extracted from the MAWI dataset.\n')
    summary.write(f'Flows extracted from dataset is labeled as elephant flows which are greater than 100MB.\n')
    summary.write(f'There are two cost effective decision tree models used. One for classification at ingress\n')
    summary.write(f'port of switch and the other is used for re-classification of flows on controller side.\n')
    summary.write(f'The first model is trained on dataset extracted from MAWI and the other one is trained on the\n')
    summary.write(f'the same dataset using 7 packet features and statistical features..\n')
    # summary.write(f'The packets injected from the flows file in {injection_order} order.\n')
    summary.close()


def get_time(timestamp):
    datetime_obj = datetime.datetime.fromtimestamp(timestamp)
    dt = datetime_obj.strftime("%d-%m-%Y %H:%M:%S")

    return dt
    

def main(hosts, network_duration):
    topo = SimpleTopology(hosts)
    controller = RemoteController('ryu', ip='127.0.0.1', port=6633, protocols="OpenFlow13")
    net = Mininet(topo, controller=controller, link=TCLink)

    # Start the network
    net.start()

    # set host IP addresses
    host_ips = topo.set_ip_addresses(net, hosts)
    info(f'host ips: {host_ips}\n')

    print('Loading packet trace file.....')
    packets = load_trace_file()
    packets = packets.sort_values(by='iat', ascending=True)

    start_time = time.time()

    info(f'Packet injection starts at {datetime.datetime.fromtimestamp(start_time).strftime("%d-%m-%Y %H:%M:%S")}')
    info(f' and will stop at {datetime.datetime.fromtimestamp(start_time + network_duration).strftime("%d-%m-%Y %H:%M:%S")}\n')

    log_file = f'logs/log_injected_packets.csv'
    columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'pkt_size', 'elephant']

    with open(log_file, 'w', newline = '') as logs:
        writer = csv.writer(logs)
        writer.writerow(columns)
    
    # net.interact()
    packet_count, elephant, mice, = inject_packets(net, start_time, network_duration, packets, host_ips, log_file)

    summary_file = f'logs/summary.txt'
    write_summary(summary_file, host_ips, start_time, packet_count, elephant, mice)

    # Stop the network
    net.stop()


if __name__ == '__main__':
    main(vn_hosts, vn_duration)