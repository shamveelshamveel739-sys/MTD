import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib import hub
from random import randint, seed
from time import time

# Custom Event for time out
class EventMessage(event.EventBase):
    '''Create a custom event with a provided message'''
    def __init__(self, message):
        print("Creating Event")
        super(EventMessage, self).__init__()
        self.msg = message

# Main Application
class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventMessage]
    R2V_Mappings = { "10.0.0.1": "", "10.0.0.2": "", "10.0.0.3": "", "10.0.0.4": "", "10.0.0.5": "", "10.0.0.6": "", "10.0.0.7": "", "10.0.0.8": "" }
    V2R_Mappings = {}
    AuthorizedEntities = ['10.0.0.1']
    Resources = [
        "10.0.0.9", "10.0.0.10", "10.0.0.11", "10.0.0.12",
        "10.0.0.13", "10.0.0.14", "10.0.0.15", "10.0.0.16",
        "10.0.0.17", "10.0.0.18", "10.0.0.19", "10.0.0.20",
        "10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24",
        "10.0.0.25", "10.0.0.26", "10.0.0.27", "10.0.0.28",
        "10.0.0.29", "10.0.0.30", "10.0.0.31", "10.0.0.32",
        "10.0.0.33", "10.0.0.34", "10.0.0.35", "10.0.0.36"
    ]

    def start(self):
        super(MovingTargetDefense, self).start()
        self.threads.append(hub.spawn(self.TimerEventGen))

    def TimerEventGen(self):
        while True:
            self.send_event_to_observers(EventMessage("TIMEOUT"))
            hub.sleep(30)

    def __init__(self, *args, **kwargs):
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = set()
        self.HostAttachments = {}
        self.offset_of_mappings = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handleSwitchFeatures(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths.add(datapath)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def EmptyTable(self, datapath):
        ofProto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        flow_mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofProto.OFPFC_DELETE, 0, 0, 1, ofProto.OFPCML_NO_BUFFER, ofProto.OFPP_ANY, ofProto.OFPG_ANY, 0, match=match, instructions=[])
        datapath.send_msg(flow_mod)
    
    @set_ev_cls(EventMessage)
    def update_resources(self, ev):
        seed(time())
        pseudo_ranum = randint(0, len(self.Resources) - 1)
        print("Random Number:", pseudo_ranum)
        for key in self.R2V_Mappings.keys():
            self.R2V_Mappings[key] = self.Resources[pseudo_ranum]
            pseudo_ranum = (pseudo_ranum + 1) % len(self.Resources)
        self.V2R_Mappings = {v: k for k, v in self.R2V_Mappings.items()}
        print("**********", self.R2V_Mappings, "***********")
        print("**********", self.V2R_Mappings, "***********")
        for curSwitch in self.datapaths:
            self.EmptyTable(curSwitch)
            parser = curSwitch.ofproto_parser
            match = parser.OFPMatch()
            ofProto = curSwitch.ofproto
            actions = [parser.OFPActionOutput(ofProto.OFPP_CONTROLLER, ofProto.OFPCML_NO_BUFFER)]
            self.add_flow(curSwitch, 0, match, actions)
    
    def isRealIPAddress(self, ipAddr):
        return ipAddr in self.R2V_Mappings.keys()
    
    def isVirtualIPAddress(self, ipAddr):
        return ipAddr in self.R2V_Mappings.values()
    
    def isDirectContact(self, datapath, ipAddr):
        if ipAddr in self.HostAttachments.keys():
            if self.HostAttachments[ipAddr] == datapath:
                return True
            else:
                return False
        return True

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            if hard_timeout is None:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst, hard_timeout=hard_timeout)
        else:
            if hard_timeout is None:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handlePacketInEvents(self, ev):
        actions = []
        pktDrop = False
        
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        arp_Obj = pkt.get_protocol(arp.arp)
        icmp_Obj = pkt.get_protocol(ipv4.ipv4)
        
        if arp_Obj:
            src = arp_Obj.src_ip
            dst = arp_Obj.dst_ip
            if self.isRealIPAddress(src) and src not in self.HostAttachments.keys():
                self.HostAttachments[src] = datapath.id
            
            if self.isRealIPAddress(src):
                match = parser.OFPMatch(eth_type=0x0806, in_port=in_port, arp_spa=src, arp_tpa=dst)
                spa = self.R2V_Mappings[src] 
                print("Changing SRC REAL IP {} ---> Virtual SRC IP {}".format(src, spa))
                actions.append(parser.OFPActionSetField(arp_spa=spa))
            
            if self.isVirtualIPAddress(dst):
                match = parser.OFPMatch(eth_type=0x0806, in_port=in_port, arp_tpa=dst, arp_spa=src)
                if self.isDirectContact(datapath=datapath.id, ipAddr=self.V2R_Mappings[dst]):
                    tpa = self.V2R_Mappings[dst]
                    print("Changing DST Virtual IP {} ---> REAL DST IP {}".format(dst, tpa))
                    actions.append(parser.OFPActionSetField(arp_tpa=tpa))
            
            elif self.isRealIPAddress(dst):
                match = parser.OFPMatch(eth_type=0x0806, in_port=in_port, arp_spa=src, arp_tpa=dst)
                if not self.isDirectContact(datapath=datapath.id, ipAddr=dst):
                    pktDrop = True
                    print("Dropping from", dpid)
            else:
                pktDrop = True

        elif icmp_Obj:
            print("ICMP PACKET FOUND!")
            src = icmp_Obj.src
            dst = icmp_Obj.dst
            if self.isRealIPAddress(src) and src not in self.HostAttachments.keys():
                self.HostAttachments[src] = datapath.id

            if self.isRealIPAddress(src):
                match = parser.OFPMatch(eth_type=0x0800, in_port=in_port, ipv4_src=src, ipv4_dst=dst)
                ipSrc = self.R2V_Mappings[src]
                print("Changing SRC REAL IP {} ---> Virtual SRC IP {}".format(src, ipSrc))
                actions.append(parser.OFPActionSetField(ipv4_src=ipSrc))

            if self.isVirtualIPAddress(dst):
                match = parser.OFPMatch(eth_type=0x0800, in_port=in_port, ipv4_dst=dst, ipv4_src=src)
                if self.isDirectContact(datapath=datapath.id, ipAddr=self.V2R_Mappings[dst]):
                    ipDst = self.V2R_Mappings[dst]
                    print("Changing DST Virtual IP {} ---> Real DST IP {}".format(dst, ipDst))
                    actions.append(parser.OFPActionSetField(ipv4_dst=ipDst))
            
            elif self.isRealIPAddress(dst):
                match = parser.OFPMatch(eth_type=0x0806, in_port=in_port, arp_spa=src, arp_tpa=dst)
                if not self.isDirectContact(datapath=datapath.id, ipAddr=dst):
                    pktDrop = True
                    print("Dropping from", dpid)
            else:
                pktDrop = True

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        if not pktDrop:
            actions.append(parser.OFPActionOutput(out_port))
        if out_port != ofproto.OFPP_FLOOD:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
