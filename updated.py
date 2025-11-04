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

GRACE_PERIOD = 20  # seconds to keep old mappings active

class EventMessage(event.EventBase):
    def __init__(self, message):
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
        self.active_flows = {}  # track active sessions keyed by (src_ip,dst_ip)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handleSwitchFeatures(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        self.datapaths.add(datapath)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                          datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def EmptyTable(self, datapath):
        ofProto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(datapath=datapath, command=ofProto.OFPFC_DELETE,
                                out_port=ofProto.OFPP_ANY, out_group=ofProto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=None, idle_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            if hard_timeout is None and idle_timeout is None:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst,
                                        hard_timeout=hard_timeout if hard_timeout else 0,
                                        idle_timeout=idle_timeout if idle_timeout else 0)
        else:
            if hard_timeout is None and idle_timeout is None:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                                        hard_timeout=hard_timeout if hard_timeout else 0,
                                        idle_timeout=idle_timeout if idle_timeout else 0)
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
        self.logger.info("Mapping updated! New: %s Previous: %s", self.R2V_Mappings, self.prev_R2V_Mappings)

        for datapath in self.datapaths:
            self.EmptyTable(datapath)
            parser = datapath.ofproto_parser
            ofProto = datapath.ofproto

            # Install flows for all active flows allowing seamless translation between old and new virtual IPs
            for (src_ip, dst_ip) in self.active_flows.keys():
                old_dst_virtual = self.prev_R2V_Mappings.get(dst_ip, None)
                new_dst_virtual = self.R2V_Mappings.get(dst_ip, None)

                if new_dst_virtual:
                    match_new = parser.OFPMatch(ipv4_src=self.R2V_Mappings[src_ip], ipv4_dst=new_dst_virtual)
                    actions_new = [parser.OFPActionOutput(ofProto.OFPP_NORMAL)]
                    self.add_flow(datapath, 20, match_new, actions_new)

                # Flow for old dst virtual IP with grace period and header rewrite to new dst IP
                # Rewrite destination IP from old virtual to new virtual for ongoing sessions
                if old_dst_virtual and old_dst_virtual != new_dst_virtual:
                    match_old = parser.OFPMatch(ipv4_src=self.R2V_Mappings[src_ip], ipv4_dst=old_dst_virtual)
                    # Add set_field action for rewriting IPv4 destination address
                    actions_old = [
                        parser.OFPActionSetField(ipv4_dst=new_dst_virtual),
                        parser.OFPActionOutput(ofProto.OFPP_NORMAL)
                    ]
                    self.add_flow(datapath, 15, match_old, actions_old, hard_timeout=GRACE_PERIOD)

                # Similarly do for source IP translation - incoming packets rewriting source IPs for continuity
                old_src_virtual = self.prev_R2V_Mappings.get(src_ip, None)
                new_src_virtual = self.R2V_Mappings.get(src_ip, None)
                if new_src_virtual:
                    match_new_src = parser.OFPMatch(ipv4_src=new_src_virtual, ipv4_dst=self.R2V_Mappings[dst_ip])
                    actions_new_src = [parser.OFPActionOutput(ofProto.OFPP_NORMAL)]
                    self.add_flow(datapath, 20, match_new_src, actions_new_src)

                if old_src_virtual and old_src_virtual != new_src_virtual:
                    match_old_src = parser.OFPMatch(ipv4_src=old_src_virtual, ipv4_dst=self.R2V_Mappings[dst_ip])
                    actions_old_src = [
                        parser.OFPActionSetField(ipv4_src=new_src_virtual),
                        parser.OFPActionOutput(ofProto.OFPP_NORMAL)
                    ]
                    self.add_flow(datapath, 15, match_old_src, actions_old_src, hard_timeout=GRACE_PERIOD)

            # Send gratuitous ARP for new IPs too
            for real_ip in self.R2V_Mappings.keys():
                self.send_gratuitous_arp(real_ip, self.R2V_Mappings[real_ip], datapath)

    def isRealIPAddress(self, ipAddr):
        return ipAddr in self.R2V_Mappings.keys()

    def isVirtualIPAddress(self, ipAddr):
        return ipAddr in self.R2V_Mappings.values() or ipAddr in self.prev_R2V_Mappings.values()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handlePacketInEvents(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        arp_obj = pkt.get_protocol(arp.arp)
        icmp_obj = pkt.get_protocol(ipv4.ipv4)

        # Track active flows (src_ip, dst_ip) on each packet in - update only for real IPs
        if arp_obj:
            src_ip = arp_obj.src_ip
            dst_ip = arp_obj.dst_ip

            if self.isRealIPAddress(src_ip):
                self.active_flows[(src_ip, dst_ip)] = time()

        elif icmp_obj:
            src_ip = icmp_obj.src
            dst_ip = icmp_obj.dst

            if self.isRealIPAddress(src_ip):
                self.active_flows[(src_ip, dst_ip)] = time()

        # Classic L2 learning switch logic preserved
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = []
        if not out_port == ofproto.OFPP_FLOOD:
            actions.append(parser.OFPActionOutput(out_port))
        else:
            actions.append(parser.OFPActionOutput(out_port))

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, parser.OFPMatch(eth_src=src, eth_dst=dst), actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 1, parser.OFPMatch(eth_src=src, eth_dst=dst), actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                                 actions=actions, data=data)
        datapath.send_msg(out)
