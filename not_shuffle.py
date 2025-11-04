from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, icmp
from ryu.lib.packet import ether_types


class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MovingTargetDefense, self).__init__(*args, **kwargs)

        # Initial real-to-virtual mappings
        self.r2v = {
            "10.0.0.1": "10.0.0.101",
            "10.0.0.2": "10.0.0.102",
            "10.0.0.3": "10.0.0.103",
            "10.0.0.4": "10.0.0.104"
        }
        self.v2r = {v: k for k, v in self.r2v.items()}

        # IP-MAC table for ARP responses
        self.ip_mac_table = {
            "10.0.0.1": "00:00:00:00:00:01",
            "10.0.0.2": "00:00:00:00:00:02",
            "10.0.0.3": "00:00:00:00:00:03",
            "10.0.0.4": "00:00:00:00:00:04",
            "10.0.0.101": "00:00:00:00:00:a1",
            "10.0.0.102": "00:00:00:00:00:a2",
            "10.0.0.103": "00:00:00:00:00:a3",
            "10.0.0.104": "00:00:00:00:00:a4",
        }

        self.logger.info("=== MTD Controller started ===")
        self.logger.info(f"Initial R2V: {self.r2v}")
        self.logger.info(f"Initial V2R: {self.v2r}")

    # ---------------------------------------------------------
    # Handle switch connection
    # ---------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Send all ARP packets to controller
        match_arp = parser.OFPMatch(eth_type=0x0806)
        self.add_flow(datapath, 10, match_arp,
                      [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])

        self.logger.info("Switch connected. Default flows installed.")

    # ---------------------------------------------------------
    # Add Flow
    # ---------------------------------------------------------
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    # ---------------------------------------------------------
    # Packet-In Handler
    # ---------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Handle ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            pkt_arp = pkt.get_protocol(arp.arp)
            self.handle_arp(datapath, eth, pkt_arp, in_port)
            return

        # Handle IPv4
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            self.logger.info(f"IPv4 Packet-In: {src_ip} → {dst_ip}")

            # NAT translation (Virtual <-> Real)
            if dst_ip in self.v2r:
                new_dst_ip = self.v2r[dst_ip]
            elif src_ip in self.r2v:
                new_dst_ip = self.r2v[src_ip]
            else:
                self.logger.info(f"Unknown mapping for {src_ip}->{dst_ip}")
                return

            self.logger.info(f"Translating {src_ip} → {new_dst_ip}")

            # Forward packet
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)

    # ---------------------------------------------------------
    # ARP Handler
    # ---------------------------------------------------------
    def handle_arp(self, datapath, eth_pkt, arp_pkt, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        dst_ip = arp_pkt.dst_ip
        src_ip = arp_pkt.src_ip

        # Look for known IP
        if dst_ip not in self.ip_mac_table:
            self.logger.info(f"ARP request for unknown IP {dst_ip}")
            return

        dst_mac = self.ip_mac_table[dst_ip]
        src_mac = eth_pkt.src

        self.logger.info(f"ARP Reply: {dst_ip} is at {dst_mac}")

        # Build ARP reply
        e = ethernet.ethernet(dst=src_mac, src=dst_mac, ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4,
                    opcode=arp.ARP_REPLY,
                    src_mac=dst_mac, src_ip=dst_ip,
                    dst_mac=src_mac, dst_ip=src_ip)

        pkt_out = packet.Packet()
        pkt_out.add_protocol(e)
        pkt_out.add_protocol(a)
        pkt_out.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt_out.data
        )
        datapath.send_msg(out)
