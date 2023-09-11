from scapy.all import sendp, Dot1Q, TCP
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import info, setLogLevel
from mininet.link import TCLink
import warnings
import time
import datetime
from packet_injection import load_trace_file, get_packet_random, get_packet_sequenced
from topology import SimpleTopology
import random
from scapy.all import IP
import csv


warnings.filterwarnings("ignore")
setLogLevel( 'info' )
        
def inject_packets(net, start_time, network_duration, packets, host_ips, vnf, log_file):
    elephants = 0
    mice = 0
    classified_elephant = 0
    classified_mice = 0
    miss_elephants = 0
    miss_mice = 0

    while time.time() < start_time + network_duration:
        pkt_iat = random.uniform(0, 0.05) # packet inter arival time having random value between 0 and 2 seconds
        time.sleep(pkt_iat)

        packet, data_size, elephant, injection_order = get_packet_sequenced(packets, host_ips, elephants, mice, [10, 1])
        if elephant == 1:
            elephants = elephants + 1
            info(f'Elephants: {elephants}')

        else:
            mice = mice + 1
            info(f'Mice: {mice}')

        send_packet(net, packet, data_size, host_ips, elephant, 1, log_file)

        # tagged_packet = vnf.classify_packet(packet)

        # if tagged_packet[Dot1Q].vlan == 1:
        #     send_packet(net, tagged_packet, data_size, host_ips, elephant, 1, log_file)
        #     classified_elephant = classified_elephant + 1
        #     miss_elephants + 1 if elephant == 0 else None
        #     info('')

        # elif tagged_packet[Dot1Q].vlan == 0:
        #     send_packet(net, tagged_packet, data_size, host_ips, elephant, 0, log_file)
        #     classified_mice = classified_mice + 1
        #     miss_mice + 1 if elephant == 1 else None
        #     info('')

    return elephants, mice, injection_order


def send_packet(net, packet, data_size, host_ips, actual_elephant, classified_elephant, log_file):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    protocol = packet[IP].proto
    pkt_size = len(packet)

    proto = '' if protocol == 6 else ' -1' if protocol == 17 else ' -2'
    data_size = f' -d {data_size}' if data_size > 0 else ''

    host = net.get(f'h{host_ips.index(src_ip) + 1}')
    cmd = f'hping3 -c 1 -s {src_port} -p {dst_port}{data_size}{proto} {dst_ip}'
    # info(f'{host} sending packet: {cmd}')
    host.cmd(cmd)
    
    # Add Log
    log = [time.time(), src_ip, dst_ip, src_port, dst_port, protocol, pkt_size, actual_elephant]
    info(f'\nInjection Log: {log}\n')
    add_log(log, log_file)


def add_log(log, log_file):   
    with open(log_file, 'a', newline = '') as logs:
        writer = csv.writer(logs)
        writer.writerow(log)


def write_summary(summary_file, hosts_ips, start_time, elephants, mice, injection_order):
    summary = open(summary_file, "w")

    summary.write(f'\nVirtual Network Simulation Summary by Digital Khalid\n')
    summary.write('\n==============================================================================================================\n')
    summary.write('Network Overview:\n')
    summary.write('==============================================================================================================\n')
    summary.write('Virtual Network: Mininet\n')
    summary.write('Controller: Ryu\n')
    summary.write('No. of Switches: 01\n')
    summary.write(f'No. of Hosts: {len(hosts_ips)}\n')
    summary.write(f'Host IP Addresses: {hosts_ips}\n')
    summary.write('==============================================================================================================\n')
    summary.write('Packet Injection Overview:\n')
    summary.write('==============================================================================================================\n')
    summary.write(f'Start Time: {get_time(start_time)}\n')
    summary.write(f'End Time: {get_time(time.time())}\n')
    summary.write(f'Total Packets Injected: {elephants + mice}\n')
    summary.write(f'Actual Elephants Injected: {elephants}\n')
    summary.write(f'Actual Mice Injected: {mice}\n')
    summary.write(f'Packets injected from the unique flows file extracted from the MAWI dataset.\n')
    summary.write(f'Flows extraction from dataset is labeled as elephant flows which are greater than 100MB.\n')
    summary.write(f'There are two cost effective decision tree models used. One for classification at ingress\n')
    summary.write(f'port of switch and the other is used for re-classification of flows on controller side.\n')
    summary.write(f'The first model is trained on dataset extracted from MAWI and the other one is trained on the.\n')
    summary.write(f'misclassifications extracted from the first model. This ensures the accuracy of overall classification process.\n')
    summary.write(f'The packets injected from the flows file in {injection_order} order.\n')
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

    vnf = net.get('vnf1')

    packets = load_trace_file()
    print('Loading packet trace file.....')

    start_time = time.time()

    info(f'Packet injection starts at {datetime.datetime.fromtimestamp(start_time).strftime("%d-%m-%Y %H:%M:%S")}')
    info(f' and will stop at {datetime.datetime.fromtimestamp(start_time + network_duration).strftime("%d-%m-%Y %H:%M:%S")}\n')

    log_file = f'logs/log_injected_flows.csv'
    columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'pkt_size', 'actual_elephant', 'predicted_elephant']
    with open(log_file, 'w', newline = '') as logs:
        writer = csv.writer(logs)
        writer.writerow(columns)
    
    # net.interact()
    elephants, mice, injection_order = inject_packets(net, start_time, network_duration, packets, host_ips, vnf, log_file)

    summary_file = f'logs/summary.txt'
    write_summary(summary_file, host_ips, start_time, elephants, mice, injection_order)

    # Stop the network
    net.stop()


if __name__ == '__main__':
    main(3, 30)