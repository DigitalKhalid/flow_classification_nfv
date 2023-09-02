from scapy.all import sendp, Dot1Q
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import info, setLogLevel
from mininet.link import TCLink
from mininet.util import irange
import warnings
import time
from packet_injection import load_trace_file, get_packet
from topology import SimpleTopology, FatTreeTopology


warnings.filterwarnings("ignore")
setLogLevel( 'info' )
        

def main():
    k = 2  # Number of pods
    p = 2  # Number of hosts per switch

    topo = FatTreeTopology(k, p)
    # topo = SimpleTopology()
    net = Mininet(topo, controller=RemoteController, link=TCLink)

    # Start the network
    net.start()

    topo.set_ip_addresses(net, k, p)
    vnfs = [net.get(f'vnf{i}{j}' for i in irange(0, k - 1) for j in irange(1, k/2))]
    # Get references to the nodes
    # h1 = net.get('h1')
    # h2 = net.get('h2')
    # h3 = net.get('h3')
    # h4 = net.get('h4')
    # h5 = net.get('h5')
    # vnf = net.get('vnf1')

    # s1 = net.get('s1')

    # # Apply IP addresses to nodes
    # h1.setIP('10.0.0.1')
    # h2.setIP('10.0.0.2')
    # h3.setIP('10.0.0.3')
    # h4.setIP('10.0.0.4')
    # h5.setIP('10.0.0.5')

    # vnf.setIP('10.0.0.6')

    # s1.cmd('ifconfig s1-eth1 mtu 5000 up')

    packets = load_trace_file()
    print('Loading packet trace file.....')

    elephant_flows = 0
    mice_flows = 0

    while True:
        # time.sleep(2)
        packet = get_packet(packets, [10, 1])

        elephant_flow = vnf.classify_packet(packet)
        info(f'\nElephant Flow: {True if elephant_flow else False}\n')

        if elephant_flow:
            # add vlan tag as 1 for elephant flows
            packet = packet / Dot1Q(vlan=1)
            info('\nElephant packet, will be handled by controller.\n')
            
            # info(f'Sending packet to switch......')
            # sendp(packet, iface='s1-eth1')

            elephant_flows = elephant_flows + 1
            info(f'Total elephant: {elephant_flows}, Total Mice: {mice_flows}')

        elif not elephant_flow:
            # add vlan tag as 0 for mice flows
            packet = packet / Dot1Q(vlan=0)
            info(f'Switch sending the packet to the destination......')
            sendp(packet, iface='s1-eth1')

            mice_flows = mice_flows + 1
            info(f'Total elephant: {elephant_flows}, Total Mice: {mice_flows}')

    # net.interact()

    # Stop the network
    net.stop()


if __name__ == '__main__':
    main()