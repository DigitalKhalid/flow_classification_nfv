from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, udp
from ryu.lib.packet import ether_types
import joblib
import warnings
import csv
import time
import datetime


warnings.filterwarnings("ignore")

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.elephant = {}

        self.start_time = int(time.time())
        self.ingress_elephants = 0
        self.ingress_mice = 0
        self.controller_elephants = 0
        self.controller_mice = 0
        self.elephant_flowrules = 0
        self.mice_flowrules = 0
        
        # Load the machine learning model for ingress port
        self.model_i = joblib.load('model_dt.pkl')
        self.scaler_i = joblib.load('model_dt_scaler.pkl')

        # Load the machine learning model for controller
        self.model_c = joblib.load('model_dt_step_2_2.pkl')
        self.scaler_c = joblib.load('model_dt_scaler_step_2_2.pkl')

        self.log_file = f'logs/log_classified_flows.csv'
        columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'pkt_size', 'ingress_elephant', 'controller_elephant']
        with open(self.log_file, 'w', newline = '') as logs:
            writer = csv.writer(logs)
            writer.writerow(columns)

        self.summary_file = f'logs/summary.txt'
        self.summary_created = False


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
            
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        self.elephant.setdefault(dpid, {})
            
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Check if the Ethernet frame contains an IP packet
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            # Extract the protocol
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
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

            # self.logger.info(f'\nPacket injected to ingress port ML model with Features:\nSource Port: {src_port}, Destination Port: {dst_port}, Protocol: {proto}, Pkt Size: {pkt_size}\n')

            features = [src_ip, dst_ip, src_port, dst_port, proto, pkt_size]
            
            # Use the machine learning model to predict flow type at ingress port
            features_norm = self.scaler_i.transform([features[2:6]])
            elephant = self.model_i.predict(features_norm)
            elephant = elephant[0]
            # self.logger.info(f'Ingress Port classifies the flow as {"Elephant" if elephant else "Mice"}')

            # Take action based on the prediction
            if elephant:
                self.ingress_elephants = self.ingress_elephants + 1
                self.handle_elephant_flow(msg, dpid, features, in_port, src, dst, out_port)

            else:
                self.ingress_mice = self.ingress_mice + 1

                if self.ingress_mice % 2 != 0:
                    # Add Log
                    log = [time.time(), src_ip, dst_ip, src_port, dst_port, proto, pkt_size, 0, 0]
                    self.add_log(log, self.log_file)

                self.handle_mice_flow(msg, dpid, features, in_port, src, dst, out_port)


        # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        #     # verify if we have a valid buffer_id, if yes avoid to send both
        #     # flow_mod & packet_out
        #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        #         return
        #     else:
        #         self.add_flow(datapath, 1, match, actions)

        else:
            self.send(msg, actions)


    def handle_elephant_flow(self, msg, dpid, features, input_port, src_mac, dst_mac, output_port):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        src_ip = features[0]
        dst_ip = features[1]
        src_port = features[2]
        dst_port = features[3]
        proto = features[4]
        pkt_size = features[5]

        elephant_pkt = f'{src_port}-{dst_port}-{proto}' #features[2:5]
        self.elephant[dpid][elephant_pkt] = 1
        
        # Use the machine learning model to predict flow type at controller side
        features_norm = self.scaler_c.transform([features[2:6]])
        elephant = self.model_c.predict(features_norm)
        elephant = elephant[0]
        # self.logger.info(f'Controller classifies the flow as {"Elephant" if elephant else "Mice"}')
        
        # Take action based on the prediction
        if elephant:
            self.controller_elephants = self.controller_elephants + 1

            if self.controller_mice % 2 != 0:
                # Add Log
                log = [time.time(), src_ip, dst_ip, src_port, dst_port, proto, pkt_size, 1, 1]
                self.add_log(log, self.log_file)

            actions = [parser.OFPActionOutput(output_port)]
            
            # Add flow rule for elephant flows to avoid packet in again
            if elephant_pkt in self.elephant[dpid]:
                self.elephant_flowrules = self.elephant_flowrules + 1
                self.logger.info(f'Flow rule added to avoid same elephant packet in next time.')

                if proto == 6:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto, tcp_src=src_port, tcp_dst=dst_port)

                elif proto == 17:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto, udp_src=src_port, udp_dst=dst_port)

                if proto == 6 or proto == 17:
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)

            # Send packet to the destination
            self.send(msg, actions)

        else:
            self.controller_mice = self.controller_mice + 1

            if self.controller_mice % 2 != 0:
                # Add Log
                log = [time.time(), src_ip, dst_ip, src_port, dst_port, proto, pkt_size, 1, 0]
                self.add_log(log, self.log_file)

            self.handle_mice_flow(msg, dpid, features, input_port, src_mac, dst_mac, output_port)


    def handle_mice_flow(self, msg, dpid, features, input_port, src_mac, dst_mac, output_port):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        src_ip = features[0]
        dst_ip = features[1]
        src_port = features[2]
        dst_port = features[3]
        proto = features[4]
        pkt_size = features[5]

        mice_pkt = f'{src_port}-{dst_port}-{proto}' #features[2:5]
        self.elephant[dpid][mice_pkt] = 0

        actions = [parser.OFPActionOutput(output_port)]
        
        # Add flow rule for mice flows to avoid packet in again
        if mice_pkt in self.elephant[dpid]:
            self.mice_flowrules = self.mice_flowrules + 1
            self.logger.info(f'Flow rule added to avoid same mice packet-in next time.')

            if proto == 6:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto, tcp_src=src_port, tcp_dst=dst_port)
            elif proto == 17:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=proto, udp_src=src_port, udp_dst=dst_port)

            if proto == 6 or proto == 17:
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)

        # Send packet to the destination
        self.send(msg, actions)


    def send(self, msg, actions):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=data)
        datapath.send_msg(out)


    def add_log(self, log, log_file): 
        self.logger.info(f'\nClassification Log: {log}\n')  

        with open(log_file, 'a', newline = '') as logs:
            writer = csv.writer(logs)
            writer.writerow(log)


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
            # self.write_summary()

        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)

        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

        if self.summary_created == False:
            self.write_summary()
            self.summary_created = True
            

    def get_time(self, timestamp):
        datetime_obj = datetime.datetime.fromtimestamp(timestamp)
        dt = datetime_obj.strftime("%d-%m-%Y %H:%M:%S")

        return dt
    

    def write_summary(self):
        summary = open(self.summary_file, "a")
        self.logger.info('Writing summary file')
        summary.writelines([
            '\n==============================================================================================================\n',
            'Classification Overview:\n',
            '==============================================================================================================\n',
            f'Total Flows: {(self.ingress_elephants + self.ingress_mice)//2}\n',
            f'Elephant Flows classified at Ingress Port: {self.ingress_elephants//2}\n',
            f'Mice Flows classified at Ingress Port: {self.ingress_mice//2}\n',
            f'Elephant Flows classified by controller: {self.controller_elephants//2}\n',
            f'Mice Flows classified by controller: {self.controller_mice//2}\n',
            f'Total flows finally classified as Elephant: {self.controller_elephants//2}\n',
            f'Total flows finally classified as mice: {(self.controller_mice//2) + (self.ingress_mice//2)}\n',
            f'Flow rules installed to avoid repeated packet-in for classified elephants flows: {self.elephant_flowrules//2}\n',
            f'Flow rules installed to avoid repeated packet-in for classified mice flows: {self.mice_flowrules//2}\n',
            ''
        ])

        summary.close()