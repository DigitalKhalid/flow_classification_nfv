from scapy.all import sendp, Dot1Q
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


warnings.filterwarnings("ignore")
setLogLevel( 'info' )
        

def main():
    hosts = 10
    topo = SimpleTopology(hosts)
    net = Mininet(topo, controller=RemoteController, link=TCLink)

    # Start the network
    net.start()

    # set host IP addresses
    host_ips = topo.set_ip_addresses(net, hosts)
    info(f'host ips: {host_ips}\n')

    # Get references to the nodes
    vnf = net.get('vnf1')
    s1 = net.get('s1')

    s1.cmd('ifconfig s1-eth1 mtu 5000 up')

    packets = load_trace_file()
    print('Loading packet trace file.....')

    elephant_flows = 0
    mice_flows = 0

    start_time = time.time()
    injection_duration = 60 # Duration of total packet injection in seconds

    info(f'Packet injection starts at {datetime.fromtimestamp(start_time).strftime("%d-%m-%Y %H:%M:%S")}')
    info(f' and will stop at {datetime.fromtimestamp(start_time + injection_duration).strftime("%d-%m-%Y %H:%M:%S")}\n')

    while time.time() < start_time + injection_duration:
        pkt_iat = random.uniform(0, 1) # packet inter arival time having random value between 0 and 2 seconds
        time.sleep(pkt_iat)

        packet = get_packet(packets, host_ips, [10, 1])

        tagged_packet = vnf.classify_packet(packet)

        if tagged_packet[Dot1Q].vlan == 1:
            elephant_flows = elephant_flows + 1
            info(f'Total elephant: {elephant_flows}, Total Mice: {mice_flows}\n')

        elif tagged_packet[Dot1Q].vlan == 0:
            sendp(packet, iface='s1-eth1')

            mice_flows = mice_flows + 1
            info(f'Total elephant: {elephant_flows}, Total Mice: {mice_flows}\n')

    # net.interact()

    # Stop the network
    net.stop()


if __name__ == '__main__':
    main()