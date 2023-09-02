from scapy.all import IP, TCP, Dot1Q
from mininet.node import Node
from mininet.log import info
import joblib
import warnings


warnings.filterwarnings("ignore")

# Load the ML model from the model.pkl file
model = joblib.load('model_dt.pkl')
scaler = joblib.load('model_dt_scaler.pkl')


# Define a custom VNF class that performs flow classification
class FlowClassifier(Node):
    def __init__(self, name, intf=None, **kwargs):
        super().__init__(name, **kwargs)
        self.model = model
        self.scaler = scaler

    def classify_packet(self, packet):
        features = {
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'protocol': packet[IP].proto,
                'first_pkt_size': len(packet),
        }

        features = [value for value in features.values()]

        # Scale the features
        features = self.scaler.transform([features])

        # Perform flow classification using the ML model
        predicted_class = self.model.predict(features)[0]     

        if predicted_class:
            # add vlan tag as 1 for elephant flows
            packet = packet / Dot1Q(vlan=1)
            info('\nSwitch communicates with the controller to handle this packet.\n')

        elif not predicted_class:
            # add vlan tag as 0 for mice flows
            packet = packet / Dot1Q(vlan=0)
            info(f'\nSwitch directly sending the packet to the destination......\n')
        
        return packet