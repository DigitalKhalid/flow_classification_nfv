from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, in_proto
from ryu.lib.packet import ethernet, ipv4, tcp, udp
from ryu.lib.packet import ether_types
import joblib
import warnings
import csv
import time
import datetime
import numpy as np


warnings.filterwarnings("ignore")


class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.elephant = {}
        self.flows = {}

        self.start_time = int(time.time())
        self.ingress_elephants = 0
        self.ingress_mice = 0
        self.controller_elephants = 0
        self.controller_mice = 0
        self.elephant_flowrules = 0
        self.mice_flowrules = 0
        
        # Load the machine learning model for ingress port
        self.model_i = joblib.load('models/model_dt.pkl')
        self.scaler_i = joblib.load('models/model_dt_scaler.pkl')

        # Load the machine learning model for controller
        self.model_c = joblib.load('models/model_dtc_controller.pkl')
        self.scaler_c = joblib.load('models/model_dtc_scaler_controller.pkl')

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

        self.flows.setdefault(datapath.id, {})

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

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.elephant.setdefault(dpid, {})
            
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
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
                
                flow_key = f'{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}'

                if flow_key not in self.flows[dpid]:
                    # Use the machine learning model to predict flow type at ingress port
                    features_norm = self.scaler_i.transform([features[2:6]])
                    elephant = self.model_i.predict(features_norm)
                    elephant = elephant[0]

                    self.logger.info(f'Ingress Port classifies the flow as {"Elephant" if elephant else "Mice"}')

                    # Take action based on the prediction
                    if elephant:
                        self.ingress_elephants = self.ingress_elephants + 1
                        self.handle_elephant_flow(msg, dpid, features, out_port)

                    else:
                        self.ingress_mice = self.ingress_mice + 1

                        if self.ingress_mice % 2 != 0:
                            # Add Log
                            log = [time.time(), src_ip, dst_ip, src_port, dst_port, proto, pkt_size, 0, 0]
                            self.add_log(log, self.log_file)

                        self.handle_mice_flow(msg, dpid, features, out_port)
                
                else:
                    if self.flows[dpid][flow_key]['elephant'] == 1:
                        self.handle_elephant_flow(msg, dpid, features, out_port)

        else:
            self.send(msg, actions)


    def handle_elephant_flow(self, msg, dpid, features, output_port):
        src_ip = features[0]
        dst_ip = features[1]
        src_port = features[2]
        dst_port = features[3]
        proto = features[4]
        pkt_size = features[5]

        flow_key = f'{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}'

        if flow_key in self.flows[dpid]:
            if len(self.flows[dpid][flow_key]['sizes']) < 7:
                self.flows[dpid][flow_key]['sizes'].append(pkt_size)
                self.flows[dpid][flow_key]['arrival_time'].append(time.time())
                self.logger.info(f'Adding pkt to the flows dictionary. Pkts added: {len(self.flows[dpid][flow_key]["sizes"])}')

                if len(self.flows[dpid][flow_key]['sizes']) == 7:
                    elephant = self.predict_elephant(dpid, flow_key, features)
                    self.handle_controller_elephant_flow(msg, elephant, features, output_port)
                else:
                    return
            
            elif len(self.flows[dpid][flow_key]['sizes']) == 7:
                elephant = self.predict_elephant(dpid, flow_key, features)
                self.handle_controller_elephant_flow(msg, elephant, features, output_port)
        
        else:
            self.logger.info('Elephant flow added to the flow dictionary....')
            self.flows[dpid].setdefault(flow_key, {})
            self.flows[dpid][flow_key].setdefault('sizes', [])
            self.flows[dpid][flow_key].setdefault('arrival_time', [])
            self.flows[dpid][flow_key]['sizes'] = [pkt_size]
            self.flows[dpid][flow_key]['arrival_time'].append(time.time())
            self.flows[dpid][flow_key]['elephant'] = 1


    def predict_elephant(self, dpid, flow_key, features):
        # Use the machine learning model to predict flow type at controller side
        max_iat = np.max(self.flows[dpid][flow_key]['arrival_time'])
        mean_iat = np.mean(self.flows[dpid][flow_key]['arrival_time'])
        duration = self.flows[dpid][flow_key]['arrival_time'][-1] - self.flows[dpid][flow_key]['arrival_time'][0]
        sizes = self.flows[dpid][flow_key]['sizes']
        total_size = sum(sizes)

        all_features = features[2:5] + sizes
        all_features.append(total_size)
        all_features.append(max_iat)
        all_features.append(mean_iat)
        all_features.append(duration)

        features_norm = self.scaler_c.transform([all_features])
        elephant = self.model_c.predict(features_norm)
        elephant = elephant[0]

        return elephant


    def handle_controller_elephant_flow(self, msg, elephant, features, output_port):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        src_ip = features[0]
        dst_ip = features[1]
        src_port = features[2]
        dst_port = features[3]
        proto = features[4]
        pkt_size = features[5]
        
        # Take action based on the prediction
        if elephant:
            self.controller_elephants = self.controller_elephants + 1

            if self.controller_mice % 2 != 0:
                # Add Log
                log = [time.time(), src_ip, dst_ip, src_port, dst_port, proto, pkt_size, 1, 1]
                self.add_log(log, self.log_file)

            actions = [parser.OFPActionOutput(output_port)]
            
            # Add flow rule for elephant flows to avoid packet in again
            self.elephant_flowrules = self.elephant_flowrules + 1
            self.logger.info(f'Flow rule added to avoid same elephant packet in next time.')

            if proto == in_proto.IPPROTO_TCP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=proto, tcp_src=src_port, tcp_dst=dst_port)

            elif proto == in_proto.IPPROTO_UDP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=proto, udp_src=src_port, udp_dst=dst_port)

            if proto == in_proto.IPPROTO_TCP or proto == in_proto.IPPROTO_UDP:
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

            self.handle_mice_flow(msg, dpid, features, output_port)


    def handle_mice_flow(self, msg, dpid, features, output_port):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        src_ip = features[0]
        dst_ip = features[1]
        src_port = features[2]
        dst_port = features[3]
        proto = features[4]
        pkt_size = features[5]

        actions = [parser.OFPActionOutput(output_port)]

        flow_key = f'{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}'

        if flow_key not in self.flows[dpid]:
            self.logger.info('Mice flow added to the flow dictionary....')
            self.flows[dpid].setdefault(flow_key, {})
            self.flows[dpid][flow_key]['elephant'] = 0

            # Add flow rule for mice flows to avoid packet in again
            self.mice_flowrules = self.mice_flowrules + 1
            self.logger.info(f'Flow rule added to avoid same mice packet-in next time.')

            if proto == in_proto.IPPROTO_TCP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=proto, tcp_src=src_port, tcp_dst=dst_port)
            elif proto == in_proto.IPPROTO_UDP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=proto, udp_src=src_port, udp_dst=dst_port)

            if proto == in_proto.IPPROTO_TCP or proto == in_proto.IPPROTO_UDP:
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
        self.logger.info(f'Flows Dict: {len(self.flows)}')

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
            # f'Flow rules installed to avoid repeated packet-in for classified elephants flows: {self.elephant_flowrules//2}\n',
            # f'Flow rules installed to avoid repeated packet-in for classified mice flows: {self.mice_flowrules//2}\n',
            ''
        ])

        summary.close()