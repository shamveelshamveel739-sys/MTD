from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import random
import time
from threading import Thread

class PortShuffleMTD(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PortShuffleMTD, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.port_map = {}  # To track original_port -> shuffled_port mapping per datapath
        self.shuffle_interval = 30  # seconds
        self.datapaths = {}
        self.running = True
        # Start background thread to shuffle ports periodically
        t = Thread(target=self._shuffle_ports_periodically)
        t.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.port_map[datapath.id] = {}

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def _shuffle_ports_periodically(self):
        while self.running:
            time.sleep(self.shuffle_interval)
            self.logger.info("Shuffling ports for MTD")
            for dpid, datapath in self.datapaths.items():
                self._shuffle_ports(datapath)

    def _shuffle_ports(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # Example logic: shuffle ports 8000-8010 mapping to random available ports
        original_ports = list(range(8000, 8011))
        shuffled_ports = original_ports[:]
        random.shuffle(shuffled_ports)

        self.port_map[datapath.id] = dict(zip(original_ports, shuffled_ports))

        # Remove old flow entries for these ports
        for port in original_ports:
            match = parser.OFPMatch(in_port=port)
            mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                    match=match)
            datapath.send_msg(mod)

        # Install new flows with shuffled ports mapping
        for original, shuffled in self.port_map[datapath.id].items():
            match = parser.OFPMatch(tcp_dst=original)
            actions = [parser.OFPActionSetField(tcp_dst=shuffled),
                       parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.add_flow(datapath, 10, match, actions)

        self.logger.info(f"Port shuffle mapping for switch {datapath.id}: {self.port_map[datapath.id]}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
