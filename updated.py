from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.controller.event import EventBase
import json
import random
from ryu.lib.packet import ether_types

# -------- Host Info --------
HOST_MAC_TABLE = {
    "10.0.0.1": "00:00:00:00:00:01",
    "10.0.0.2": "00:00:00:00:00:02",
    "10.0.0.3": "00:00:00:00:00:03",
    "10.0.0.4": "00:00:00:00:00:04",
}
HOST_PORT_TABLE = {
    "00:00:00:00:00:01": 1,
    "00:00:00:00:00:02": 2,
    "00:00:00:00:00:03": 3,
    "00:00:00:00:00:04": 4,
}

# -------- Virtual IP Pool --------
VIRTUAL_IP_POOL = ["10.0.0.101", "10.0.0.102", "10.0.0.103", "10.0.0.104"]


class EventMessage(EventBase):
    def __init__(self, msg):
        super(EventMessage, self).__init__()
        self.msg = msg


class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventMessage]

    def __init__(self, *args, **kwargs):
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = set()
        self.R2V_Mappings = {}
        self.V2R_Mappings = {}
        self.prev_R2V_Mappings = {}
        self.virtual_macs = {}  # map virtual_ip -> virtual_mac
        self.mapping_interval = 10
        self.logger.info("=== MTD Controller started ===")

        # Initialize mappings immediately
        self.initialize_mappings()

        # Start background timer
        self.monitor_thread = hub.spawn(self._mapping_timer)

    # -------------------- INITIALIZATION --------------------
    def initialize_mappings(self):
        hosts = list(HOST_MAC_TABLE.keys())
        for i, real_ip in enumerate(hosts):
            virt_ip = VIRTUAL_IP_POOL[i % len(VIRTUAL_IP_POOL)]
            self.R2V_Mappings[real_ip] = virt_ip
            self.V2R_Mappings[virt_ip] = real_ip
            # create fake virtual MAC (just modify last byte)
            real_mac = HOST_MAC_TABLE[real_ip]
            virt_mac = real_mac[:-2] + format(0xA0 + i, "02x")
            self.virtual_macs[virt_ip] = virt_mac

        self.logger.info("Initial R2V: %s", json.dumps(self.R2V_Mappings))
        self.logger.info("Initial V2R: %s", json.dumps(self.V2R_Mappings))
        self.logger.info("Initial virtual MACs: %s", json.dumps(self.virtual_macs))

    # -------------------- SWITCH EVENTS --------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handleSwitchFeatures(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.datapaths.add(dp)
        self.logger.info("Switch connected: %s", dp.id)

        # Send PacketIn for unmatched packets
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions, note="Controller flow")

        # Immediately install NAT rules
        self.update_flows(dp)

    def add_flow(self, datapath, priority, match, actions, note=""):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
        if note:
            self.logger.debug(f"Flow added ({note}): {match}")

    # -------------------- PACKET HANDLER --------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        in_port = msg.match['in_port']

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.handle_arp(dp, in_port, eth, arp_pkt)
            return

        # normal L2 learning
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data
        )
        dp.send_msg(out)

    # -------------------- ARP HANDLING --------------------
    def handle_arp(self, dp, port, eth, arp_pkt):
        parser = dp.ofproto_parser
        if arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip
            self.logger.debug("ARP request for %s from %s", target_ip, arp_pkt.src_ip)

            # Reply for real IPs
            if target_ip in HOST_MAC_TABLE:
                mac = HOST_MAC_TABLE[target_ip]
                self.reply_arp(dp, port, eth.src, arp_pkt.src_ip, target_ip, mac)

            # Reply for virtual IPs
            elif target_ip in self.V2R_Mappings:
                virt_mac = self.virtual_macs.get(target_ip)
                self.reply_arp(dp, port, eth.src, arp_pkt.src_ip, target_ip, virt_mac)

    def reply_arp(self, dp, out_port, dst_mac, dst_ip, src_ip, src_mac):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=ofp.OFPP_CONTROLLER, actions=actions, data=p.data))
        self.logger.info(f"Sent ARP reply: {src_ip} is at {src_mac}")

    # -------------------- NAT / FLOW UPDATES --------------------
    def update_flows(self, dp):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Clear old flows except controller rule
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))

        # Reinstall controller rule
        self.add_flow(dp, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)],
                      note="Controller rule")

        # Install real<->virtual NAT rules
        for real_ip, virt_ip in self.R2V_Mappings.items():
            real_mac = HOST_MAC_TABLE[real_ip]
            virt_mac = self.virtual_macs[virt_ip]
            port = HOST_PORT_TABLE[real_mac]

            # real -> virtual
            match1 = parser.OFPMatch(eth_type=0x0800, ipv4_src=real_ip)
            actions1 = [parser.OFPActionSetField(ipv4_src=virt_ip),
                        parser.OFPActionSetField(eth_src=virt_mac),
                        parser.OFPActionOutput(ofp.OFPP_NORMAL)]
            self.add_flow(dp, 20, match1, actions1, note=f"real->virtual {real_ip}->{virt_ip}")

            # virtual -> real
            match2 = parser.OFPMatch(eth_type=0x0800, ipv4_dst=virt_ip)
            actions2 = [parser.OFPActionSetField(ipv4_dst=real_ip),
                        parser.OFPActionSetField(eth_dst=real_mac),
                        parser.OFPActionOutput(port)]
            self.add_flow(dp, 20, match2, actions2, note=f"virtual->real {virt_ip}->{real_ip}")

    # -------------------- TIMER --------------------
    def _mapping_timer(self):
        while True:
            hub.sleep(self.mapping_interval)
            self.randomize_mappings()

    def randomize_mappings(self):
        old = self.R2V_Mappings.copy()
        new_R2V = {}
        new_V2R = {}
        hosts = list(HOST_MAC_TABLE.keys())
        shuffled = VIRTUAL_IP_POOL.copy()
        random.shuffle(shuffled)

        for i, real_ip in enumerate(hosts):
            virt_ip = shuffled[i]
            new_R2V[real_ip] = virt_ip
            new_V2R[virt_ip] = real_ip

        self.R2V_Mappings = new_R2V
        self.V2R_Mappings = new_V2R
        self.logger.info("Mappings updated: %s", json.dumps(new_R2V))

        # Update all switches
        for dp in self.datapaths:
            self.update_flows(dp)
