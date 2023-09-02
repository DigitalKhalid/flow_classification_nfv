from scapy.all import IP, TCP
from mininet.node import Node
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
        
        return predicted_class