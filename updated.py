import json, logging
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

GRACE_PERIOD = 20  # seconds

class EventMessage(event.EventBase):
    def __init__(self, message):
        super(EventMessage, self).__init__()
        self.msg = message

class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventMessage]

    # real -> virtual
    R2V_Mappings = { ip: "" for ip in HOST_MAC_TABLE }
    # virtual -> real
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
        # Optional: force DEBUG level from inside the app (still use CLI flags)
        self.logger.setLevel(logging.DEBUG)
        self.threads.append(hub.spawn(self.TimerEventGen))

    def TimerEventGen(self):
        while True:
            self.send_event_to_observers(EventMessage("TIMEOUT"))
            hub.sleep(30)

    def __init__(self, *args, **kwargs):
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = set()
        self.prev_R2V_Mappings = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handleSwitchFeatures(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        self.datapaths.add(dp)
        self.logger.info("Switch connected: dp=%s", dp.id)
        self.add_flow(dp, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                              dp.ofproto.OFPCML_NO_BUFFER)])

    def EmptyTable(self, dp):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      match=parser.OFPMatch()))
        self.logger.debug("Emptied flow table on dp=%s", dp.id)

    def add_flow(self, dp, priority, match, actions,
                 buffer_id=None, hard_timeout=None, idle_timeout=None, note=""):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=dp, priority=priority, match=match, instructions=inst)
        if buffer_id is not None:
            kwargs['buffer_id'] = buffer_id
        if hard_timeout is not None:
            kwargs['hard_timeout'] = hard_timeout
        if idle_timeout is not None:
            kwargs['idle_timeout'] = idle_timeout
        mod = parser.OFPFlowMod(**kwargs)
        dp.send_msg(mod)
        self.logger.debug("Flow add dp=%s prio=%s match=%s actions=%s note=%s",
                          dp.id, priority, match, actions, note)

    def send_gratuitous_arp(self, real_ip, virtual_ip, dp):
        parser = dp.ofproto_parser
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806,
                                           src=HOST_MAC_TABLE[real_ip],
                                           dst='ff:ff:ff:ff:ff:ff'))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=HOST_MAC_TABLE[real_ip],
                                 src_ip=virtual_ip,
                                 dst_mac='ff:ff:ff:ff:ff:ff',
                                 dst_ip=virtual_ip))
        pkt.serialize()
        dp.send_msg(parser.OFPPacketOut(datapath=dp,
                                        buffer_id=dp.ofproto.OFP_NO_BUFFER,
                                        in_port=dp.ofproto.OFPP_CONTROLLER,
                                        actions=[parser.OFPActionOutput(dp.ofproto.OFPP_FLOOD)],
                                        data=pkt.data))
        self.logger.info("GARP sent: real=%s virt=%s on dp=%s", real_ip, virtual_ip, dp.id)

    @set_ev_cls(EventMessage)
    def update_resources(self, ev):
        # Rotate mappings deterministically and log the table
        seed(time())
        start = randint(0, len(self.Resources) - 1)
        self.prev_R2V_Mappings = self.R2V_Mappings.copy()
        idx = start
        for real in self.R2V_Mappings.keys():
            self.R2V_Mappings[real] = self.Resources[idx]
            idx = (idx + 1) % len(self.Resources)
        self.V2R_Mappings = {v: k for k, v in self.R2V_Mappings.items()}
        self.logger.info("Mapping updated: NEW=%s PREV=%s",
                         json.dumps(self.R2V_Mappings), json.dumps(self.prev_R2V_Mappings))

        # Reprogram all datapaths with stateless NAT + bypass
        for dp in self.datapaths:
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            self.EmptyTable(dp)

            # Bypass: real->real traffic should not be rewritten (lets 'h1 ping h2' work)
            real_ips = list(HOST_MAC_TABLE.keys())
            for src_real in real_ips:
                for dst_real in real_ips:
                    if src_real == dst_real:
                        continue
                    m = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_real, ipv4_dst=dst_real)
                    self.add_flow(dp, 60, m, [parser.OFPActionOutput(ofp.OFPP_NORMAL)],
                                  note="bypass real->real")

            # NAT rules for each host
            for real_ip, new_virt in self.R2V_Mappings.items():
                prev_virt = self.prev_R2V_Mappings.get(real_ip)

                # Inbound: to current virtual => rewrite to real
                m = parser.OFPMatch(eth_type=0x0800, ipv4_dst=new_virt)
                a = [parser.OFPActionSetField(ipv4_dst=real_ip),
                     parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                self.add_flow(dp, 50, m, a, note=f"inbound v->{real_ip}")

                # Outbound: from real => rewrite source to current virtual (but not when dst is real; bypass above handles that)
                m = parser.OFPMatch(eth_type=0x0800, ipv4_src=real_ip)
                a = [parser.OFPActionSetField(ipv4_src=new_virt),
                     parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                self.add_flow(dp, 45, m, a, note=f"outbound {real_ip}->v")

                # Grace support for previous virtual
                if prev_virt and prev_virt != new_virt:
                    m = parser.OFPMatch(eth_type=0x0800, ipv4_dst=prev_virt)
                    a = [parser.OFPActionSetField(ipv4_dst=real_ip),
                         parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                    self.add_flow(dp, 40, m, a, hard_timeout=GRACE_PERIOD,
                                  note=f"grace inbound prev_v->{real_ip}")

                    m = parser.OFPMatch(eth_type=0x0800, ipv4_src=real_ip)
                    a = [parser.OFPActionSetField(ipv4_src=prev_virt),
                         parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                    self.add_flow(dp, 40, m, a, hard_timeout=GRACE_PERIOD,
                                  note=f"grace outbound {real_ip}->prev_v")

                # ARP refresh
                self.send_gratuitous_arp(real_ip, new_virt, dp)
                if prev_virt and prev_virt != new_virt:
                    self.send_gratuitous_arp(real_ip, prev_virt, dp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handlePacketInEvents(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_obj = pkt.get_protocol(arp.arp)

        # ARP responder for current and previous virtual IPs
        if arp_obj and arp_obj.opcode == arp.ARP_REQUEST:
            target_ip = arp_obj.dst_ip
            real_ip = self.V2R_Mappings.get(target_ip)
            if not real_ip:
                for r, pv in self.prev_R2V_Mappings.items():
                    if pv == target_ip:
                        real_ip = r
                        break
            if real_ip:
                reply = packet.Packet()
                reply.add_protocol(ethernet.ethernet(ethertype=0x0806,
                                                     dst=eth.src,
                                                     src=HOST_MAC_TABLE[real_ip]))
                reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                           src_mac=HOST_MAC_TABLE[real_ip],
                                           src_ip=target_ip,
                                           dst_mac=arp_obj.src_mac,
                                           dst_ip=arp_obj.src_ip))
                reply.serialize()
                dp.send_msg(parser.OFPPacketOut(datapath=dp,
                                                buffer_id=ofp.OFP_NO_BUFFER,
                                                in_port=ofp.OFPP_CONTROLLER,
                                                actions=[parser.OFPActionOutput(in_port)],
                                                data=reply.data))
                self.logger.debug("ARP reply: %s is-at %s (dp=%s)", target_ip, HOST_MAC_TABLE[real_ip], dp.id)
                return

        # Simple L2 learning
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(eth_src=eth.src, eth_dst=eth.dst)
        if msg.buffer_id != ofp.OFP_NO_BUFFER:
            self.add_flow(dp, 1, match, actions, buffer_id=msg.buffer_id, note="L2 learn")
        else:
            self.add_flow(dp, 1, match, actions, note="L2 learn")
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                                        actions=actions, data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None))
        self.logger.debug("packet_in dp=%s in_port=%s eth_src=%s eth_dst=%s out=%s",
                          dp.id, in_port, eth.src, eth.dst, out_port)
