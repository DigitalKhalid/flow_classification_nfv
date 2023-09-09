from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI

class SimpleTopology(Topo):
    def build(self):
        # Add two hosts and one switch
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch('s1')

        # Add links between hosts and the switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)

def create_simple_topology():
    topo = SimpleTopology()
    # controller = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo, controller=None)
    net.start()
    s1 = net.get('s1')
    s1.setIP('10.0.0.3', intf='s1-eth1')
    CLI(net)  # Opens Mininet's command-line interface
    net.stop()

if __name__ == '__main__':
    create_simple_topology()