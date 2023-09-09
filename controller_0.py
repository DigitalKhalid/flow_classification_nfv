from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0
from ryu.lib.packet import packet, ethernet, ether_types, in_proto, ipv4, icmp, tcp, udp
from ryu import cfg
import joblib
import logging
import warnings


warnings.filterwarnings("ignore")

class FlowClassifier(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowClassifier, self).__init__(*args, **kwargs)

        # Set the IP address and port of the Ryu controller
        self.controller_ip = '127.0.0.1'
        self.controller_port = 6633

        # Load the pre-trained machine learning model
        self.model = joblib.load('model_dt_step_2_2.pkl')
        # self.scaler = joblib.load('model_dt_scaler_step_2_2.pkl')
        self.scaler = joblib.load('model_dt_scaler.pkl')


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install flow rule for elephant packets
        # match = parser.OFPMatch(dl_vlan = 1)
        # ethertype_ipv4 = ether_types.ETH_TYPE_IP  # EtherType value for IPv4
        # ip_version_ipv4 = 4  # IPv4 version

        # # Create an OpenFlow match object to match IPv4 packets
        # match = parser.OFPMatch(eth_type=ethertype_ipv4, ip_proto=ip_version_ipv4)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFP_NO_BUFFER)]
        self.add_flow(datapath, ofproto.OFP_DEFAULT_PRIORITY, match, actions)


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
        #                         match=match, instructions=instructions)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=priority,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        # self.logger.info(f'Ether Packet: {eth_pkt}')
        # self.logger.info(f'IP Packet: {ip_pkt}')
        print(f'Ether Packet: {hex(eth_pkt)}')
        print(f'IP Packet: {ip_pkt}')

        # pkt_ipv4 = pkt.get_protocols(ipv4.ipv4)
        # if pkt_ipv4 == None:
        #     print('None')
        # else:
        # eth_pkt = ethernet.ethernet(msg.data)
            # print(pkt_ipv4)
        # Check if the Ethernet frame contains an IP packet
        # if eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
        #     ip_pkt = eth_pkt.data

            # Extract the protocol
            # proto = ip_pkt.proto

            # print(f'Protocol: {proto}')
        # Extract relevant features from the packet/flow
        features = self.extract_features(msg)
        # features = [value for value in features.values()]
        # features = [[x] for x in features]
        features = self.scaler.transform([features])

        # Use the machine learning model to predict flow type
        elephant = self.model.predict(features)[0]

        # Print a message indicating that a packet has been received
        self.logger.info(f'Controller classifies the flow as {"Elephant" if elephant else "Mice"}')
        print(f'Controller classifies the flow as {"Elephant" if elephant else "Mice"}')

        # Take action based on the prediction
        if elephant:
            # Handle elephant flow (e.g., apply QoS policy)
            self.handle_elephant_flow(msg)


    def extract_features(self, msg):
        # Parse the Ethernet frame from the packet
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        # eth_pkt = ethernet.ethernet(msg.data)

        # Check if the Ethernet frame contains an IP packet
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = eth_pkt.data

            # Extract the protocol
            proto = ip_pkt.proto

            # Check if the IP packet contains a TCP or UDP packet
            if proto == 6: # For TCP packet
                tp_pkt = ip_pkt.data
                src_port = tp_pkt.src_port
                dst_port = tp_pkt.dst_port

            elif proto == 17: # For UDP packet
                tp_pkt = ip_pkt.data
                src_port = tp_pkt.src_port
                dst_port = tp_pkt.dst_port

            else: # For Other Packets
                src_port = 0
                dst_port = 0

            # Extract the packet size (length)
            pkt_size = len(msg.data)

            features = [src_port, dst_port, proto, pkt_size]
            print(features)
            return features

    def handle_elephant_flow(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        interface = 's1-eth2'

        output_port = self.get_port_by_name(datapath, interface)

        # Print a message indicating that a packet has been received
        self.logger.info(f'Sending packet through the interface {interface}')

        if output_port is not None:
            actions = [parser.OFPActionOutput(output_port)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
                actions=actions)
            datapath.send_msg(out)






    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def packet_in_handler(self, ev):
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     in_port = msg.match['in_port']

    #     # Print a message indicating that a packet has been received
    #     self.logger.info("Packet received by the controller")

    #     pkt = packet.Packet(msg.data)
    #     eth_pkt = pkt.get_protocol(ethernet.ethernet)

    #     # Modify this logic based on your use case
    #     if eth_pkt:
    #         # Create an Ethernet frame with the same payload and headers
    #         new_eth_pkt = ethernet.ethernet(eth_pkt.dst, eth_pkt.src, eth_pkt.ethertype)
    #         new_pkt = packet.Packet()
    #         new_pkt.add_protocol(new_eth_pkt)
    #         new_pkt.serialize()

    #         # Specify the output port
    #         out_port = 2  # Modify this to the desired output port

    #         actions = [parser.OFPActionOutput(out_port, ofproto.OFPCML_NO_BUFFER)]
    #         out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
    #                                    in_port=in_port, actions=actions, data=new_pkt.data)
    #         datapath.send_msg(out)