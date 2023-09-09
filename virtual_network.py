from scapy.all import sendp, Dot1Q, TCP
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import info, setLogLevel
from mininet.link import TCLink
import warnings
import time
from datetime import datetime
from packet_injection import load_trace_file, get_packet
from topology import SimpleTopology
import random
from scapy.all import IP
import csv


warnings.filterwarnings("ignore")
setLogLevel( 'info' )
        
def inject_packets(net, start_time, network_duration, packets, host_ips, vnf, log_file):
    elephant_flows = 0
    mice_flows = 0

    while time.time() < start_time + network_duration:
        pkt_iat = random.uniform(0, 0.2) # packet inter arival time having random value between 0 and 2 seconds
        time.sleep(pkt_iat)

        packet = get_packet(packets, host_ips, [10, 1])

        tagged_packet = vnf.classify_packet(packet)

        if tagged_packet[Dot1Q].vlan == 1:
            send_packet(net, tagged_packet, host_ips, 's1-eth1', 1, log_file)
            elephant_flows = elephant_flows + 1
            info('')

        elif tagged_packet[Dot1Q].vlan == 0:
            send_packet(net, tagged_packet, host_ips, 's1-eth2', 0, log_file)
            mice_flows = mice_flows + 1
            info('')


def send_packet(net, packet, host_ips, interface, elephant, log_file):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    protocol = packet[IP].proto
    pkt_size = len(packet)

    proto = '' if protocol == 6 else ' -1' if protocol == 17 else ' -2'

    host = net.get(f'h{host_ips.index(src_ip) + 1}')
    cmd = f'hping3 -c 1 -s {src_port} -p {dst_port} -d {pkt_size}{proto} {dst_ip}'
    info(f'{host} sending packet: {cmd}')
    host.cmd(cmd)
    
    # Add Log
    log = [time.time(), src_ip, dst_ip, src_port, dst_port, protocol, pkt_size, elephant]
    add_log(log, log_file)


def add_log(log, log_file):   
    with open(log_file, 'a', newline = '') as logs:
        writer = csv.writer(logs)
        writer.writerow(log)


def main(hosts, network_duration):
    topo = SimpleTopology(hosts)
    controller = RemoteController('ryu', ip='127.0.0.1', port=6633)
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

    log_file = f'log_injected_flows_{int(start_time)}.csv'
    inject_packets(net, start_time, network_duration, packets, host_ips, vnf, log_file)

    # net.interact()
    # Stop the network
    net.stop()


if __name__ == '__main__':
    main(10, 100)