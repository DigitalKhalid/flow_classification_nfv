from mininet.topo import Topo
from mininet.util import irange
# from vnf_classifier import FlowClassifier
from mininet.node import OVSSwitch


# Create a custom Mininet topology with the FlowClassifier VNF
class SimpleTopology(Topo):
    def build(self, hosts):
        switch = self.addSwitch('s1', cls=OVSSwitch, protocols="OpenFlow13")
        # classifier = self.addHost( 'vnf1', ip='10.0.1.1', cls=FlowClassifier)

        # self.addLink( classifier, switch )

        for i in irange(1, hosts):
            host = self.addHost(f'h{i}')
            self.addLink(host, switch)       

    # set ip addresses for the hosts
    def set_ip_addresses(self, net, hosts):
        ip_addresses = []

        for i in irange(1, hosts):
            host = net.get(f'h{i}')
            ip = f'10.0.0.{i}'
            host.setIP(ip)
            ip_addresses.append(ip)

        return ip_addresses
