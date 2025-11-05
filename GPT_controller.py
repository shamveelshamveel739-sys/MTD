# mtd_vip_controller.py
#
# Aggressive MTD cutover ("TERMINATE_AND_RESUME"):
#  - VIP-based service exposure (clients only see VIPs).
#  - ARP proxy for VIPs => pings/traffic to VIPs work.
#  - Per-5tuple NAT rules (client->VIP->real and reverse).
#  - Periodic VIP->real reshuffle.
#  - On shuffle: delete old per-5tuple rules so new flows switch instantly.
#  - Optional "nudges" (enabled) to speed app-level reconnection:
#       * TCP: send RSTs both ways (best effort).
#       * UDP/ICMP: send ICMP dst-unreachable to client.
#
# Quick demo:
#   ryu-manager mtd_vip_controller.py
#   sudo mn --topo single,2 --controller=remote,ip=127.0.0.1 --switch ovs,protocols=OpenFlow13
#   mininet> h1 ifconfig h1-eth0 10.0.0.1/24 up
#   mininet> h2 ifconfig h2-eth0 10.0.0.2/24 up
#   mininet> h1 ping -c3 10.0.255.2
#   (watch reshuffles every SHUFFLE_INTERVAL seconds)
#
# Notes:
#   - Works best when both endpoints are behind the same edge switch.
#   - For multi-switch, mirror per-5tuple rules to the egress switch to the real host
#     (left as an extension depending on your topology discovery).

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
from ryu.lib.packet import ether_types
from ryu.lib import hub

import random
import struct
import time

# -------------------------
# Config
# -------------------------

VIP_POOL = ["10.0.255.1", "10.0.255.2", "10.0.255.3", "10.0.255.4"]
REAL_HOSTS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

VIRTUAL_MAC = "aa:bb:cc:dd:ee:ff"

# Shuffle cadence
SHUFFLE_INTERVAL = 45

# Per-flow timeouts (we delete flows on shuffle anyway)
FLOW_IDLE_TIMEOUT = 120
FLOW_HARD_TIMEOUT = 0

# Aggressive cutover
PERSISTENCE_MODE = "TERMINATE_AND_RESUME"  # fixed as requested

# Grace window allowing old+new VIP maps for NEW flows (useful if you’re mirroring rules across switches)
GRACE_SECONDS = 0

# Nudges to force/retry quickly (best-effort)
NUDGE_TCP_RST = True
NUDGE_ICMP_UNREACH = True

class MTDVipController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MTDVipController, self).__init__(*args, **kwargs)
        self.dp_mac_table = {}   # dpid -> {mac: port}
        self.real_hosts = {ip: {"mac": None, "dpid": None, "port": None} for ip in REAL_HOSTS}

        # initial VIP->real mapping
        self.vip_map = {}
        for i, vip in enumerate(VIP_POOL):
            if i < len(REAL_HOSTS):
                self.vip_map[vip] = REAL_HOSTS[i]
        self.real_to_vips = self._invert_map(self.vip_map)

        # Track installed per-5tuple rules so we can remove them on shuffle
        # cookie -> meta
        self.cookie_counter = 1
        self.cookie_index = {}  # cookie -> {"dpid", "vip", "real", "five_tuple":(sip,dip,proto,sp,dp)}

        # For nudges, keep a lightweight observation of last seen mac/port per (dpid, ip)
        self.last_ip_loc = {}  # (dpid, ip) -> {"mac": mac, "port": port}

        self.mtd_thread = hub.spawn(self._mtd_loop)

    # ------------------- helpers -------------------

    def _invert_map(self, m):
        inv = {}
        for vip, rip in m.items():
            inv.setdefault(rip, set()).add(vip)
        return inv

    def _next_cookie(self):
        c = self.cookie_counter
        self.cookie_counter += 1
        # never zero
        if c == 0:
            c = 1
        return c

    def _select_new_mapping(self):
        reals = REAL_HOSTS[:]
        random.shuffle(reals)
        new_map = {}
        for i, vip in enumerate(VIP_POOL):
            if i < len(reals):
                new_map[vip] = reals[i]
        return new_map

    def _get_dp_by_dpid(self, dpid):
        return getattr(self, f"dp_{dpid}", None)

    # ------------------- MTD loop -------------------

    def _mtd_loop(self):
        while True:
            hub.sleep(SHUFFLE_INTERVAL)
            old_map = self.vip_map.copy()
            self.vip_map = self._select_new_mapping()
            self.real_to_vips = self._invert_map(self.vip_map)
            self.logger.info("[MTD] New VIP map: %s", self.vip_map)

            # Aggressive cutover: delete per-5tuple rules tied to the old mapping
            self._purge_5tuple_rules_related_to(old_map)

            if GRACE_SECONDS > 0:
                self.logger.info("[MTD] Grace window %ss (old+new accept for NEW flows).", GRACE_SECONDS)
                hub.sleep(GRACE_SECONDS)

    def _purge_5tuple_rules_related_to(self, old_map):
        to_delete = []
        # collect cookies to delete
        for cookie, meta in list(self.cookie_index.items()):
            vip = meta.get("vip")
            real = meta.get("real")
            if vip in old_map and old_map[vip] == real:
                to_delete.append((cookie, meta))

        if not to_delete:
            return

        self.logger.info("[MTD] Removing %d old per-5tuple rules (fast cutover).", len(to_delete))

        # group by datapath
        dp_groups = {}
        for cookie, meta in to_delete:
            dp_groups.setdefault(meta["dpid"], []).append((cookie, meta))

        for dpid, items in dp_groups.items():
            dp = self._get_dp_by_dpid(dpid)
            if not dp:
                continue
            parser = dp.ofproto_parser
            ofp = dp.ofproto

            # delete flows
            for cookie, meta in items:
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    cookie=cookie,
                    cookie_mask=(2**64 - 1),
                    command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    table_id=0
                )
                dp.send_msg(mod)
                self.cookie_index.pop(cookie, None)

            # send nudges after deletion to hasten reconnection (best-effort)
            if NUDGE_TCP_RST or NUDGE_ICMP_UNREACH:
                for _, meta in items:
                    self._nudge_endpoints(dp, meta)

    # ------------------- switch bootstrap -------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        setattr(self, f"dp_{dpid}", dp)

        self.dp_mac_table.setdefault(dpid, {})

        # table-miss to controller
        self._add_flow(dp, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

        # punt ARP
        self._add_flow(dp, 5, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
                       [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

        # punt IPv4 first packets (let us install per-5tuple NAT)
        self._add_flow(dp, 4, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP),
                       [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

        self.logger.info("Switch %s initial rules installed.", dpid)

    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0, cookie=0):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle, hard_timeout=hard, cookie=cookie)
        dp.send_msg(mod)

    # ------------------- packet-in -------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        in_port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        # L2 learn
        self.dp_mac_table.setdefault(dpid, {})
        self.dp_mac_table[dpid][eth.src] = in_port

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(dp, msg, pkt, in_port)
            return

        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if not ip4:
            return

        # Track last seen for nudges
        self.last_ip_loc[(dpid, ip4.src)] = {"mac": eth.src, "port": in_port}

        # Learn real host side
        self._maybe_learn_real(dp, in_port, eth.src, ip4.src)

        # VIP path?
        if ip4.dst in self.vip_map:
            real_ip = self.vip_map[ip4.dst]
            real_info = self.real_hosts.get(real_ip, {})
            real_mac = real_info.get("mac")
            out_port = None
            if real_mac and real_info.get("dpid") == dpid:
                out_port = self.dp_mac_table[dpid].get(real_mac)
            if out_port is None:
                out_port = ofp.OFPP_FLOOD

            # l4 discriminator
            l4 = pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp) or pkt.get_protocol(icmp.icmp)
            self._install_bi_nat_rules(dp, in_port, out_port, ip4, eth, vip=ip4.dst, real=real_ip, l4=l4)

            # forward this packet with NAT now
            actions = self._nat_actions_client_to_server(dp, eth, vip=ip4.dst, real=real_ip, out_port=out_port, real_mac=real_mac)
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return

        # Non-VIP traffic: basic L2 forwarding
        dst_port = self.dp_mac_table[dpid].get(eth.dst)
        actions = [parser.OFPActionOutput(dst_port)] if dst_port else [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    # ------------------- ARP (VIP proxy) -------------------

    def _handle_arp(self, dp, msg, pkt, in_port):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        eth = pkt.get_protocol(ethernet.ethernet)
        a = pkt.get_protocol(arp.arp)
        if not a:
            return

        if a.opcode == arp.ARP_REQUEST and a.dst_ip in self.vip_map:
            # reply: VIP -> VIRTUAL_MAC
            self._send_arp_reply(dp, src_mac=VIRTUAL_MAC, dst_mac=eth.src,
                                 src_ip=a.dst_ip, dst_ip=a.src_ip, out_port=in_port)
            return

        # otherwise flood
        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port,
                                  actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)], data=msg.data)
        dp.send_msg(out)

    def _send_arp_reply(self, dp, src_mac, dst_mac, src_ip, dst_ip, out_port):
        e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4,
                    opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        dp.send_packet_out(in_port=dp.ofproto.OFPP_CONTROLLER,
                           actions=[dp.ofproto_parser.OFPActionOutput(out_port)],
                           data=p.data)

    # ------------------- learning -------------------

    def _maybe_learn_real(self, dp, in_port, mac, ip):
        if ip in self.real_hosts:
            info = self.real_hosts[ip]
            if info.get("mac") != mac or info.get("port") != in_port or info.get("dpid") != dp.id:
                self.real_hosts[ip] = {"mac": mac, "port": in_port, "dpid": dp.id}
                self.logger.info("Learned real host %s -> mac %s at dp %s port %s", ip, mac, dp.id, in_port)

    # ------------------- NAT rule install -------------------

    def _install_bi_nat_rules(self, dp, in_port_client, out_port_server, ip4, eth, vip, real, l4):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        sip, dip = ip4.src, ip4.dst  # dip is VIP
        proto = ip4.proto

        # Default L4 selector
        l4_sel = {"ip_proto": proto}
        sport = dport = None
        if isinstance(l4, tcp.tcp):
            l4_sel = {"ip_proto": 6, "tcp_src": l4.src_port, "tcp_dst": l4.dst_port}
            sport, dport = l4.src_port, l4.dst_port
        elif isinstance(l4, udp.udp):
            l4_sel = {"ip_proto": 17, "udp_src": l4.src_port, "udp_dst": l4.dst_port}
            sport, dport = l4.src_port, l4.dst_port
        elif isinstance(l4, icmp.icmp):
            l4_sel = {"ip_proto": 1}
        # else: keep generic ip_proto

        # 1) client->VIP match -> rewrite to real (and out)
        match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=sip, ipv4_dst=dip, **l4_sel)
        actions1 = self._nat_actions_client_to_server(dp, eth, vip=vip, real=real,
                                                      out_port=out_port_server,
                                                      real_mac=self.real_hosts.get(real, {}).get("mac"))
        ck1 = self._next_cookie()
        self._add_flow(dp, 100, match1, actions1, idle=FLOW_IDLE_TIMEOUT, hard=FLOW_HARD_TIMEOUT, cookie=ck1)
        self.cookie_index[ck1] = {"dpid": dp.id, "vip": vip, "real": real, "five_tuple": (sip, dip, l4_sel.get("ip_proto"), sport, dport)}

        # 2) real->client match -> rewrite src to VIP (and out)
        client_port_guess = self.dp_mac_table[dp.id].get(eth.src)
        out2 = client_port_guess if client_port_guess is not None else ofp.OFPP_FLOOD
        match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=real, ipv4_dst=sip, **l4_sel)
        actions2 = self._nat_actions_server_to_client(dp, vip=vip, real=real, out_port=out2)
        ck2 = self._next_cookie()
        self._add_flow(dp, 100, match2, actions2, idle=FLOW_IDLE_TIMEOUT, hard=FLOW_HARD_TIMEOUT, cookie=ck2)
        self.cookie_index[ck2] = {"dpid": dp.id, "vip": vip, "real": real, "five_tuple": (real, sip, l4_sel.get("ip_proto"), dport, sport)}

    def _nat_actions_client_to_server(self, dp, eth, vip, real, out_port, real_mac):
        parser = dp.ofproto_parser
        actions = []
        if real_mac:
            actions.append(parser.OFPActionSetField(eth_dst=real_mac))
        actions.append(parser.OFPActionSetField(ipv4_dst=real))
        actions.append(parser.OFPActionOutput(out_port))
        return actions

    def _nat_actions_server_to_client(self, dp, vip, real, out_port):
        parser = dp.ofproto_parser
        return [
            parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
            parser.OFPActionSetField(ipv4_src=vip),
            parser.OFPActionOutput(out_port)
        ]

    # ------------------- Nudges (best-effort) -------------------

    def _nudge_endpoints(self, dp, meta):
        """
        Try to speed cutover by poking endpoints of old flows.
        - For TCP: send RST in both directions.
        - For UDP/ICMP: send ICMP Dest Unreachable to client.
        """
        dpid = meta["dpid"]
        vip = meta["vip"]
        real = meta["real"]
        (sip, dip, ip_proto, sport, dport) = meta["five_tuple"]  # sip->dip direction was in installed rule

        # Identify where client/real currently are (ports on this switch)
        cli_loc = self.last_ip_loc.get((dpid, sip), {})
        srv_info = self.real_hosts.get(real, {})
        srv_loc = {"mac": srv_info.get("mac"), "port": srv_info.get("port")} if srv_info.get("dpid") == dpid else {}

        if ip_proto == 6 and NUDGE_TCP_RST:
            # TCP RST client<-server and server<-client (sequence numbers are best-effort; many stacks accept)
            if cli_loc.get("port") is not None:
                self._send_tcp_rst(dp, src_mac=VIRTUAL_MAC, dst_mac=cli_loc["mac"], src_ip=vip, dst_ip=sip,
                                   src_port=dport or 0, dst_port=sport or 0, out_port=cli_loc["port"])
            if srv_loc.get("port") is not None and srv_loc.get("mac") is not None:
                # RST towards real server using client's apparent 5-tuple reversed
                self._send_tcp_rst(dp, src_mac=srv_loc["mac"], dst_mac=srv_loc["mac"],  # eth src/dst don't matter much here; use out_port
                                   src_ip=sip, dst_ip=real, src_port=sport or 0, dst_port=dport or 0,
                                   out_port=srv_loc["port"])
        elif ip_proto in (17, 1) and NUDGE_ICMP_UNREACH:
            # ICMP dest-unreachable to client (from VIP)
            if cli_loc.get("port") is not None:
                self._send_icmp_unreach(dp, src_mac=VIRTUAL_MAC, dst_mac=cli_loc["mac"], src_ip=vip, dst_ip=sip,
                                        out_port=cli_loc["port"])

    def _send_tcp_rst(self, dp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, out_port):
        """Craft a minimal TCP RST packet and emit via PacketOut (best-effort)."""
        e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_IP)
        ip = ipv4.ipv4(dst=dst_ip, src=src_ip, proto=6)
        # RST|ACK with zero seq/ack; many stacks tear down anyway in local emulation
        t = tcp.tcp(src_port=src_port, dst_port=dst_port, bits=(tcp.TCP_RST | tcp.TCP_ACK), seq=0, ack=0, window_size=0)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(t)
        p.serialize()
        dp.send_packet_out(in_port=dp.ofproto.OFPP_CONTROLLER,
                           actions=[dp.ofproto_parser.OFPActionOutput(out_port)],
                           data=p.data)

    def _send_icmp_unreach(self, dp, src_mac, dst_mac, src_ip, dst_ip, out_port):
        """Send ICMP Destination Unreachable (Code 1: host unreachable)."""
        e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_IP)
        ip = ipv4.ipv4(dst=dst_ip, src=src_ip, proto=1)
        ic = icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE,
                       csum=0, data=icmp.dest_unreach(data=b''))
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(ic)
        p.serialize()
        dp.send_packet_out(in_port=dp.ofproto.OFPP_CONTROLLER,
                           actions=[dp.ofproto_parser.OFPActionOutput(out_port)],
                           data=p.data)
