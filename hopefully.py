from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, ipv4
import random
import time

class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.real_to_virtual = {}
        self.virtual_to_real = {}
        self.datapaths = {}
        self.host_macs = {}
        self.shuffle_interval = 10  # seconds between shuffles
        self.shuffle_thread = hub.spawn(self.shuffle_loop)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.datapaths[dp.id] = dp
        self.logger.info(f"Switch {dp.id} connected")

        # default table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.logger.info('Registering datapath: %016x', dp.id)
                self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.logger.info('Unregistering datapath: %016x', dp.id)
                del self.datapaths[dp.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88cc:
            return  # LLDP ignore

        dst = eth.dst
        src = eth.src
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port
        self.host_macs[src] = in_port

        # learn host IPs through ARP or IPv4
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if arp_pkt:
            self.learn_host(arp_pkt.src_ip, src)
            self.logger.info(f"Learned {arp_pkt.src_ip} on {src}")
            if arp_pkt.opcode == arp.ARP_REQUEST:
                self.handle_arp_request(dp, in_port, arp_pkt)
            return
        elif ip_pkt:
            self.learn_host(ip_pkt.src, src)

        # forwarding
        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(dp, 1, match, actions, idle_timeout=30)

        out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        dp.send_msg(out)

    def learn_host(self, ip, mac):
        if ip not in self.real_to_virtual:
            virt = self.generate_virtual_ip(ip)
            self.real_to_virtual[ip] = virt
            self.virtual_to_real[virt] = ip
            self.logger.info(f"New mapping: {ip} → {virt}")

    def generate_virtual_ip(self, real_ip):
        base = real_ip.split('.')
        base[3] = str(100 + random.randint(1, 50))
        return '.'.join(base)

    def handle_arp_request(self, dp, port, arp_pkt):
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip
        self.logger.debug(f"ARP Request {src_ip} → {dst_ip}")

        if dst_ip in self.virtual_to_real:
            real_ip = self.virtual_to_real[dst_ip]
            virt_mac = "00:00:00:00:00:%02x" % int(real_ip.split('.')[-1])
            arp_reply = packet.Packet()
            arp_reply.add_protocol(ethernet.ethernet(
                ethertype=0x0806,
                dst=arp_pkt.src_mac,
                src=virt_mac))
            arp_reply.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=virt_mac,
                src_ip=dst_ip,
                dst_mac=arp_pkt.src_mac,
                dst_ip=src_ip))
            arp_reply.serialize()
            dp.send_packet_out(
                buffer_id=0xffffffff,
                in_port=dp.ofproto.OFPP_CONTROLLER,
                actions=[dp.ofproto_parser.OFPActionOutput(port)],
                data=arp_reply.data)
            self.logger.debug(f"Sent ARP reply {dst_ip} → {src_ip}")

    def shuffle_loop(self):
        while True:
            hub.sleep(self.shuffle_interval)
            try:
                if len(self.real_to_virtual) < 2:
                    continue
                old_map = dict(self.real_to_virtual)
                reals = list(self.real_to_virtual.keys())
                random.shuffle(reals)
                new_map = dict(zip(old_map.keys(), reals))
                self.real_to_virtual = new_map
                self.virtual_to_real = {v: k for k, v in new_map.items()}
                self.logger.info(f"Mappings shuffled: {self.real_to_virtual}")
                self.reinstall_flows_safe()
            except Exception as e:
                self.logger.error(f"Error during shuffle: {e}")

    def reinstall_flows_safe(self):
        for dp in list(self.datapaths.values()):
            try:
                if not dp.ports:
                    self.logger.warning("Ports not ready, retrying flow install...")
                    hub.sleep(2)
                    if not dp.ports:
                        self.logger.warning("Ports still not ready, skipping this round")
                        continue
                self.logger.info("Clearing and reinstalling flows...")
                self.clear_flows(dp)
                self.install_default_flows(dp)
            except Exception as e:
                self.logger.error(f"Error reinstalling flows: {e}")

    def clear_flows(self, dp):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        mod = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY)
        dp.send_msg(mod)
        self.logger.info(f"Cleared old flows on dp {dp.id}")

    def install_default_flows(self, dp):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
