import json
import random
import logging
from time import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.lib import hub


# ----------------- Host and Virtual IP Pools -----------------
HOST_MAC_TABLE = {
    "10.0.0.1": "00:00:00:00:00:01",
    "10.0.0.2": "00:00:00:00:00:02",
    "10.0.0.3": "00:00:00:00:00:03",
    "10.0.0.4": "00:00:00:00:00:04",
}

VIRTUAL_IPS = [
    "10.0.0.101", "10.0.0.102", "10.0.0.103", "10.0.0.104",
    "10.0.0.105", "10.0.0.106", "10.0.0.107", "10.0.0.108"
]

SHUFFLE_INTERVAL = 20  # seconds


class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = set()

        # Initialize mapping tables
        self.r2v = {}
        self.v2r = {}
        self.prev_r2v = {}

        self.initialize_mappings()

        self.logger.setLevel(logging.INFO)
        self.logger.info("=== MTD Controller started ===")
        self.logger.info(f"Initial R2V: {self.r2v}")

        # Spawn background task for dynamic shuffling
        self.shuffle_thread = hub.spawn(self.periodic_shuffle)

    # ----------------- INITIAL SETUP -----------------
    def initialize_mappings(self):
        """Initial static mapping of real -> virtual"""
        real_ips = list(HOST_MAC_TABLE.keys())
        random.shuffle(VIRTUAL_IPS)
        for i, real in enumerate(real_ips):
            self.r2v[real] = VIRTUAL_IPS[i]
        self.v2r = {v: k for k, v in self.r2v.items()}

    # ----------------- FLOW MANAGEMENT -----------------
    def add_flow(self, dp, priority, match, actions, buffer_id=None, note=""):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = dict(datapath=dp, priority=priority, match=match, instructions=inst)
        if buffer_id:
            kwargs["buffer_id"] = buffer_id

        dp.send_msg(parser.OFPFlowMod(**kwargs))
        self.logger.debug("Flow added: %s (%s)", match, note)

    def empty_table(self, dp):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch()
        ))
        self.logger.info(f"Cleared flow table on dp={dp.id}")

    # ----------------- ARP HANDLING -----------------
    def send_gratuitous_arp(self, dp, real_ip, virt_ip):
        parser = dp.ofproto_parser
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=0x0806,
            src=HOST_MAC_TABLE[real_ip],
            dst='ff:ff:ff:ff:ff:ff'
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=HOST_MAC_TABLE[real_ip],
            src_ip=virt_ip,
            dst_mac='ff:ff:ff:ff:ff:ff',
            dst_ip=virt_ip
        ))
        pkt.serialize()
        actions = [parser.OFPActionOutput(dp.ofproto.OFPP_FLOOD)]
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        ))
        self.logger.info(f"Sent GARP for real={real_ip}, virt={virt_ip}")

    # ----------------- PERIODIC SHUFFLE -----------------
    def periodic_shuffle(self):
        while True:
            hub.sleep(SHUFFLE_INTERVAL)
            self.shuffle_mappings()

    def shuffle_mappings(self):
        """Randomly shuffle virtual IP assignments"""
        self.prev_r2v = self.r2v.copy()
        real_ips = list(self.r2v.keys())
        virt_list = list(self.r2v.values())
        random.shuffle(virt_list)
        self.r2v = dict(zip(real_ips, virt_list))
        self.v2r = {v: k for k, v in self.r2v.items()}

        self.logger.info(f"Mappings shuffled! NEW={self.r2v} PREV={self.prev_r2v}")

        # Reinstall flows on all datapaths
        for dp in self.datapaths:
            self.program_flows(dp)

    # ----------------- SWITCH EVENTS -----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths.add(dp)
        self.logger.info(f"Switch connected: dp={dp.id}")

        parser = dp.ofproto_parser
        self.add_flow(dp, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                              dp.ofproto.OFPCML_NO_BUFFER)],
                      note="send all to controller")
        self.program_flows(dp)

    def program_flows(self, dp):
        """Reprogram flow table based on current mappings"""
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        self.empty_table(dp)
        real_ips = list(HOST_MAC_TABLE.keys())

        # Bypass for real-to-real traffic
        for src in real_ips:
            for dst in real_ips:
                if src == dst:
                    continue
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src, ipv4_dst=dst)
                self.add_flow(dp, 50, match,
                              [parser.OFPActionOutput(ofp.OFPP_NORMAL)],
                              note="real->real bypass")

        # Add NAT rules
        for real, virt in self.r2v.items():
            # Outbound (real → virt)
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=real)
            actions = [parser.OFPActionSetField(ipv4_src=virt),
                       parser.OFPActionOutput(ofp.OFPP_NORMAL)]
            self.add_flow(dp, 40, match, actions, note="outbound NAT")

            # Inbound (virt → real)
            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=virt)
            actions = [parser.OFPActionSetField(ipv4_dst=real),
                       parser.OFPActionOutput(ofp.OFPP_NORMAL)]
            self.add_flow(dp, 40, match, actions, note="inbound NAT")

            # Send gratuitous ARP for discovery
            self.send_gratuitous_arp(dp, real, virt)

    # ----------------- PACKET-IN HANDLER -----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # ARP request handler
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip
            real_ip = self.v2r.get(target_ip)
            if real_ip:
                reply = packet.Packet()
                reply.add_protocol(ethernet.ethernet(
                    ethertype=0x0806,
                    dst=eth.src,
                    src=HOST_MAC_TABLE[real_ip]
                ))
                reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=HOST_MAC_TABLE[real_ip],
                    src_ip=target_ip,
                    dst_mac=arp_pkt.src_mac,
                    dst_ip=arp_pkt.src_ip
                ))
                reply.serialize()
                actions = [parser.OFPActionOutput(in_port)]
                dp.send_msg(parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=ofp.OFPP_CONTROLLER,
                    actions=actions,
                    data=reply.data
                ))
                self.logger.debug(f"Replied to ARP: {target_ip} is {HOST_MAC_TABLE[real_ip]}")
                return

        # Basic L2 learning (flood if unknown)
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if msg.buffer_id != ofp.OFP_NO_BUFFER:
            self.add_flow(dp, 1, parser.OFPMatch(eth_src=eth.src, eth_dst=eth.dst),
                          actions, buffer_id=msg.buffer_id)
        else:
            dp.send_msg(parser.OFPPacketOut(datapath=dp, in_port=in_port,
                                            actions=actions, data=msg.data))
