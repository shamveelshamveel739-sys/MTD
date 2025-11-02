import json
from ryu.base import app_manager
from ryu.controller import ofp_event, event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
from random import randint, seed
from time import time

# For mapping real IPs to MACs (populate appropriately based on your topology)
HOST_MAC_TABLE = {
    '10.0.0.1': '00:00:00:00:00:01',
    '10.0.0.2': '00:00:00:00:00:02',
    '10.0.0.3': '00:00:00:00:00:03',
    '10.0.0.4': '00:00:00:00:00:04',
    '10.0.0.5': '00:00:00:00:00:05',
    '10.0.0.6': '00:00:00:00:00:06',
    '10.0.0.7': '00:00:00:00:00:07',
    '10.0.0.8': '00:00:00:00:00:08'
}

class EventMessage(event.EventBase):
    def __init__(self, message):
        print("Creating Event")
        super(EventMessage, self).__init__()
        self.msg = message

class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventMessage]
    R2V_Mappings = { ip: "" for ip in HOST_MAC_TABLE }
    V2R_Mappings = {}
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
        self.prev_R2V_Mappings = {}

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
        flow_mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofProto.OFPFC_DELETE, 0, 0, 1,
                                    ofProto.OFPCML_NO_BUFFER, ofProto.OFPP_ANY, ofProto.OFPG_ANY,
                                    0, match=match, instructions=[])
        datapath.send_msg(flow_mod)

    def remove_flow(self, datapath, match):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY, match=match)
        datapath.send_msg(mod)

    def send_gratuitous_arp(self, real_ip, virtual_ip, datapath):
        parser = datapath.ofproto_parser
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=0x0806,
            src=HOST_MAC_TABLE[real_ip],
            dst='ff:ff:ff:ff:ff:ff'))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=HOST_MAC_TABLE[real_ip],
            src_ip=virtual_ip,
            dst_mac='ff:ff:ff:ff:ff:ff',
            dst_ip=virtual_ip))
        pkt.serialize()
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)],
            data=pkt.data
        )
        datapath.send_msg(out)

    @set_ev_cls(EventMessage)
    def update_resources(self, ev):
        seed(time())
        pseudo_ranum = randint(0, len(self.Resources) - 1)
        self.prev_R2V_Mappings = self.R2V_Mappings.copy()
        for key in self.R2V_Mappings.keys():
            self.R2V_Mappings[key] = self.Resources[pseudo_ranum]
            pseudo_ranum = (pseudo_ranum + 1) % len(self.Resources)
        self.V2R_Mappings = {v: k for k, v in self.R2V_Mappings.items()}
        print("Mapping updated! New:", self.R2V_Mappings, "Previous:", self.prev_R2V_Mappings)

        for curSwitch in self.datapaths:
            self.EmptyTable(curSwitch)
            parser = curSwitch.ofproto_parser
            ofProto = curSwitch.ofproto
            # Rewrite flows for all hosts
            for real_ip in self.R2V_Mappings.keys():
                prev_virtual_ip = self.prev_R2V_Mappings.get(real_ip)
                new_virtual_ip = self.R2V_Mappings[real_ip]
                # remove old mapping flows
                if prev_virtual_ip != "":
                    match_remove = parser.OFPMatch(ipv4_src=prev_virtual_ip)
                    self.remove_flow(curSwitch, match_remove)
                # install new mapping (allow always)
                match_new = parser.OFPMatch(ipv4_src=new_virtual_ip)
                actions_new = [parser.OFPActionSetField(ipv4_src=new_virtual_ip),
                               parser.OFPActionOutput(ofProto.OFPP_NORMAL)]
                self.add_flow(curSwitch, 1, match_new, actions_new)
                # send ARP update
                self.send_gratuitous_arp(real_ip, new_virtual_ip, curSwitch)

    def isRealIPAddress(self, ipAddr):
        return ipAddr in self.R2V_Mappings.keys()

    def isVirtualIPAddress(self, ipAddr):
        return ipAddr in self.R2V_Mappings.values() or ipAddr in self.prev_R2V_Mappings.values()

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
                real_dst = self.V2R_Mappings.get(dst)
                if not real_dst:
                    real_dst = [k for k,v in self.prev_R2V_Mappings.items() if v == dst][0] if dst in self.prev_R2V_Mappings.values() else None
                if real_dst and self.isDirectContact(datapath=datapath.id, ipAddr=real_dst):
                    print("Changing DST Virtual IP {} ---> REAL DST IP {}".format(dst, real_dst))
                    actions.append(parser.OFPActionSetField(arp_tpa=real_dst))
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
                real_dst = self.V2R_Mappings.get(dst)
                if not real_dst:
                    real_dst = [k for k,v in self.prev_R2V_Mappings.items() if v == dst][0] if dst in self.prev_R2V_Mappings.values() else None
                if real_dst and self.isDirectContact(datapath=datapath.id, ipAddr=real_dst):
                    print("Changing DST Virtual IP {} ---> Real DST IP {}".format(dst, real_dst))
                    actions.append(parser.OFPActionSetField(ipv4_dst=real_dst))
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
