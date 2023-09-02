from mininet.topo import Topo
from mininet.util import irange
from vnf_classifier import FlowClassifier
from mininet.log import info


# Create a custom Mininet topology with the FlowClassifier VNF
class SimpleTopology(Topo):
    def build(self):
        Host1 = self.addHost( 'h1' )
        Host2 = self.addHost( 'h2' )
        Host3 = self.addHost( 'h3' )
        Host4 = self.addHost( 'h4' )
        Host5 = self.addHost( 'h5' )
        
        classifier = self.addHost( 'vnf1', cls=FlowClassifier)

        switch = self.addSwitch('s1')

        # Add links
        self.addLink( Host1, switch )
        self.addLink( Host2, switch )
        self.addLink( Host3, switch )
        self.addLink( Host4, switch )
        self.addLink( Host5, switch )
        self.addLink( classifier, switch)


from mininet.topo import Topo


class FatTreeTopology(Topo):
    def build(self, k=2, p=2):
        # Ensure that k is even for a balanced fat tree
        assert k % 2 == 0

        # Lists to hold switches in each layer
        core_switches = []
        aggregation_switches = []
        edge_switches = []
        vnf_classifiers = []
        hosts = []

        # Create core switches
        for i in irange(1, k):
            core_switch = self.addSwitch(f'cs{i}')
            core_switches.append(core_switch)

        info(f'Core Switches: {core_switches}')

        # Create aggregation switches
        for i in irange(1, k):
            for j in irange(1, k/2):
                aggregation_switch = self.addSwitch(f'as{i}{j}')
                aggregation_switches.append(aggregation_switch)

        info(f'Aggregation Switches: {aggregation_switches}')

        # Create edge switches and hosts           
        for i in irange(0, k - 1):
            for j in irange(1, k/2):
                edge_switch = self.addSwitch(f'es{i}{j}')
                edge_switches.append(edge_switch)
            
                # add VNF host and connect with the edge switch
                vnf = self.addHost(f'vnf{i}{j}')
                vnf_classifiers.append(vnf)
                self.addLink(vnf, edge_switch)

                # add hosts and connect with the edge switch
                for h in irange(1, p):
                    host = self.addHost(f'h{i}{j}{h}')
                    hosts.append(host)
                    self.addLink(host, edge_switch)

        info(f'Edge Switches: {edge_switches}')
        info(f'VNF Classifiers: {vnf_classifiers}')
        info(f'Hosts: {hosts}')

        # Connect edge switches to aggregation switches
        a = 0
        for i in range(len(aggregation_switches)):
            self.addLink(aggregation_switches[i], core_switches[a])
            a = a + 1
            self.addLink(aggregation_switches[i], core_switches[a])
            a = a + 1

            if a == k - 1:
                a = 0


        x = k/2 - 1
        for i in range(k):
            for j in range(i*k/2, x+(i*k/2)):
                for t in range(i*k/2, x+(i*k/2)):
                    self.addLink(edge_switches[j], aggregation_switches[t])
                        

    # set ip addresses for the hosts
    def set_ip_addresses(net, k=2, p=2):
        ip_addresses = []
        host_ip = 1

        for i in irange(1, k):
            for j in irange(1, k/2):
                for h in irange(1, p):
                    host = net.get(f'h{i}{j}{h}')
                    ip = f'10.0.{i}.{host_ip}/24'
                    host.setIP(ip)
                    host_ip += 1
                    ip_addresses.append(ip)

        return ip_addresses