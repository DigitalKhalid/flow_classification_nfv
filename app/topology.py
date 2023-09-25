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

class SFCTopology(Topo):
    def build(self, hosts):
        switch1 = self.addSwitch('s1', cls=OVSSwitch, protocols="OpenFlow13")
        switch2 = self.addSwitch('s2', cls=OVSSwitch, protocols="OpenFlow13")

        sfc1 = self.addHost('sf1', ip = '10.0.1.1')
        
        self.addLink( switch1, sfc1 )
        self.addLink( sfc1, switch2 )

        for i in irange(1, hosts):
            host = self.addHost(f'h{i}')
            self.addLink(host, switch1) 
            self.addLink(switch2, host)

    # set ip addresses for the hosts
    def set_ip_addresses(self, net, hosts):
        ip_addresses = []

        for i in irange(1, hosts):
            host = net.get(f'h{i}')
            ip = f'10.0.0.{i}'
            host.setIP(ip)
            ip_addresses.append(ip)

        return ip_addresses