from scapy.all import sendp, Dot1Q, TCP
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import info, setLogLevel
from mininet.link import TCLink
import warnings
import time
from datetime import datetime
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

        packet, elephant = get_packet_sequenced(packets, host_ips, elephants, mice, [10, 1])
        if elephant == 1:
            elephants = elephants + 1

        else:
            mice = mice + 1

        # info(f'Elephants: {elephants}, Mice: {mice}')
        tagged_packet = vnf.classify_packet(packet)

        if tagged_packet[Dot1Q].vlan == 1:
            send_packet(net, tagged_packet, host_ips, 's1-eth2', elephant, 1, log_file)
            classified_elephant = classified_elephant + 1
            miss_elephants + 1 if elephant == 0 else None
            info('')

        elif tagged_packet[Dot1Q].vlan == 0:
            send_packet(net, tagged_packet, host_ips, 's1-eth3', elephant, 0, log_file)
            classified_mice = classified_mice + 1
            miss_mice + 1 if elephant == 1 else None
            info('')


def send_packet(net, packet, host_ips, interface, actual_elephant, classified_elephant, log_file):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    protocol = packet[IP].proto
    pkt_size = len(packet)

    proto = '' if protocol == 6 else ' -1' if protocol == 17 else ' -2'
    signature = ' -e "elephant"' if classified_elephant == 1 else ''

    host = net.get(f'h{host_ips.index(src_ip) + 1}')
    cmd = f'hping3 -c 1 -s {src_port} -p {dst_port} -d {pkt_size}{proto}{signature} {dst_ip}'
    info(f'{host} sending packet: {cmd}')
    host.cmd(cmd)
    
    # Add Log
    log = [time.time(), src_ip, dst_ip, src_port, dst_port, protocol, pkt_size, actual_elephant, classified_elephant]
    info(f'\nLog: {log}\n')
    add_log(log, log_file)


def add_log(log, log_file):   
    with open(log_file, 'a', newline = '') as logs:
        writer = csv.writer(logs)
        writer.writerow(log)


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

    info(f'Packet injection starts at {datetime.fromtimestamp(start_time).strftime("%d-%m-%Y %H:%M:%S")}')
    info(f' and will stop at {datetime.fromtimestamp(start_time + network_duration).strftime("%d-%m-%Y %H:%M:%S")}\n')

    log_file = f'logs/log_injected_flows_{int(start_time)}.csv'
    columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'pkt_size', 'actual_elephant', 'predicted_elephant']
    add_log(columns, log_file)
    
    # net.interact()
    inject_packets(net, start_time, network_duration, packets, host_ips, vnf, log_file)

    # Stop the network
    net.stop()


if __name__ == '__main__':
    main(2, 100)