from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.ofproto import ether
from ryu.lib import hub
import random
import time


class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MovingTargetDefense, self).__init__(*args, **kwargs)

        # Define initial host info (real IPs, MACs)
        self.real_hosts = {
            '10.0.0.1': '00:00:00:00:00:01',
            '10.0.0.2': '00:00:00:00:00:02',
            '10.0.0.3': '00:00:00:00:00:03',
            '10.0.0.4': '00:00:00:00:00:04'
        }

        # Virtual IP pool
        self.virtual_ips = ['10.0.0.101', '10.0.0.102', '10.0.0.103', '10.0.0.104']

        # Real-to-virtual and virtual-to-real maps
        self.mapping = dict(zip(self.real_hosts.keys(), self.virtual_ips))
        self.reverse_mapping = {v: k for k, v in self.mapping.items()}

        # Data path and port tracking
        self.datapath = None
        self.ports = []

        # Start background thread for IP shuffling
        self.shuffle_thread = hub.spawn(self._shuffle_mappings_periodically)

        self.logger.info("=== MTD Controller started ===")
        self.logger.info(f"Initial Mapping: {self.mapping}")

    # -------------------------------
    # Handle switch connection
    # -------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info("Switch connected and default flow added")

    # -------------------------------
    # Packet-in handler (ARP & IP)
    # -------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.handle_arp(datapath, in_port, eth, arp_pkt)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.handle_ipv4(datapath, in_port, eth, ip_pkt)
            return

    # -------------------------------
    # Handle ARP requests/replies
    # -------------------------------
    def handle_arp(self, datapath, in_port, eth, a):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Save all unique ports for later use
        if in_port not in self.ports:
            self.ports.append(in_port)

        if a.opcode == arp.ARP_REQUEST:
            if a.dst_ip in self.reverse_mapping:
                real_ip = self.reverse_mapping[a.dst_ip]
                mac = self.real_hosts[real_ip]

                # Reply to ARP
                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(
                    ethertype=ether.ETH_TYPE_ARP,
                    src=mac,
                    dst=eth.src
                ))
                pkt.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=mac,
                    src_ip=a.dst_ip,
                    dst_mac=eth.src,
                    dst_ip=a.src_ip
                ))
                pkt.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=pkt.data
                )
                datapath.send_msg(out)

                self.logger.info(f"Replied to ARP for virt={a.dst_ip}, real={real_ip}")

    # -------------------------------
    # Handle IPv4 forwarding
    # -------------------------------
    def handle_ipv4(self, datapath, in_port, eth, ip_pkt):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        if src_ip in self.reverse_mapping:
            src_real = self.reverse_mapping[src_ip]
        else:
            src_real = src_ip

        if dst_ip in self.reverse_mapping:
            dst_real = self.reverse_mapping[dst_ip]
        else:
            dst_real = dst_ip

        self.logger.info(f"IPv4 packet: {src_real} -> {dst_real}")

    # -------------------------------
    # Add OpenFlow rule
    # -------------------------------
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # -------------------------------
    # Shuffle IP mappings periodically
    # -------------------------------
    def _shuffle_mappings_periodically(self):
        while True:
            hub.sleep(60)  # shuffle interval
            self.shuffle_mappings()

    # -------------------------------
    # Shuffle logic
    # -------------------------------
    def shuffle_mappings(self):
        if not self.datapath:
            return

        # Randomly permute virtual IPs
        prev = self.mapping.copy()
        random.shuffle(self.virtual_ips)
        self.mapping = dict(zip(self.real_hosts.keys(), self.virtual_ips))
        self.reverse_mapping = {v: k for k, v in self.mapping.items()}

        self.logger.info(f"Mappings shuffled: {self.mapping}")

        # Clear all previous flows
        parser = self.datapath.ofproto_parser
        ofproto = self.datapath.ofproto
        mod = parser.OFPFlowMod(datapath=self.datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY)
        self.datapath.send_msg(mod)
        self.logger.info("Cleared old flow table")

        # Send new GARPs to announce virtual IPs
        for real_ip, virt_ip in self.mapping.items():
            mac = self.real_hosts[real_ip]
            self.send_gratuitous_arp(self.datapath, real_ip, virt_ip, mac, self.ports)

    # -------------------------------
    # Send Gratuitous ARP (GARP)
    # -------------------------------
    def send_gratuitous_arp(self, datapath, real_ip, virt_ip, mac, ports):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether.ETH_TYPE_ARP,
            src=mac,
            dst='ff:ff:ff:ff:ff:ff'
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=mac,
            src_ip=virt_ip,
            dst_mac='00:00:00:00:00:00',
            dst_ip=virt_ip
        ))
        pkt.serialize()

        for p in ports:
            actions = [parser.OFPActionOutput(p)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=pkt.data
            )
            datapath.send_msg(out)
            self.logger.info(f"Sent GARP for real={real_ip}, virt={virt_ip} on port {p}")
