from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet, ether_types, in_proto, ipv4, icmp, tcp, udp
import joblib
import warnings


warnings.filterwarnings("ignore")

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Load the pre-trained machine learning model
        self.model = joblib.load('model_dt_step_2_2.pkl')
        self.scaler = joblib.load('model_dt_scaler_step_2_2.pkl')


    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        # Parse the Ethernet frame from the packet
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # Check if the Ethernet frame contains an IP packet
        if eth_pkt:
            if eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)

                # Extract the protocol
                proto = ip_pkt.proto
                src_port = 0
                dst_port = 0

                # Check if the IP packet contains a TCP or UDP packet
                if proto == 6: # For TCP packet
                    tp_pkt = pkt.get_protocol(tcp.tcp)
                    src_port = tp_pkt.src_port
                    dst_port = tp_pkt.dst_port

                elif proto == 17: # For UDP packet
                    up_pkt = pkt.get_protocol(udp.udp)
                    src_port = up_pkt.src_port
                    dst_port = up_pkt.dst_port

                # Extract the packet size (length)
                pkt_size = len(msg.data)

                self.logger.info(f'\nSource Port: {src_port}, Destination Port: {dst_port}, Protocol: {proto}, Pkt Size: {pkt_size}\n')


                features = [src_port, dst_port, proto, pkt_size]
                features = self.scaler.transform([features])

                # Use the machine learning model to predict flow type
                elephant = self.model.predict(features)[0]

                # Print a message indicating that a packet has been received
                self.logger.info(f'Controller classifies the flow as {"Elephant" if elephant else "Mice"}')

                # Take action based on the prediction
                if elephant:
                    # Handle elephant flow (e.g., apply QoS policy)
                    self.handle_elephant_flow(msg)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)


    def handle_elephant_flow(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # interface = 's1-eth2'

        # output_port = self.get_port_by_name(datapath, interface)

        # # Print a message indicating that a packet has been received
        # self.logger.info(f'Sending packet through the interface {interface}')

        # if output_port is not None:
        #     actions = [parser.OFPActionOutput(output_port)]
        #     out = parser.OFPPacketOut(
        #         datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
        #         actions=actions)
        #     datapath.send_msg(out)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)

        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)

        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)

        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)