from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from threading import Thread
import random
import sys

class PortShuffleMTD(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PortShuffleMTD, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.original_ports = [8010, 8025, 8050]        # demo candidate ports
        self.last_allowed_port = None
        # Start input-wait thread to shuffle on keypress
        t = Thread(target=self.keypress_trigger)
        t.daemon = True
        t.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial table-miss entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Install initial port shuffle (random)
        self.shuffle_ports(datapath)

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

    def keypress_trigger(self):
        # Wait for Enter, then shuffle ports
        while True:
            key = input("Press Enter to shuffle allowed port...\n")
            self.logger.info("Shuffling ports for MTD...")
            for dpid, datapath in self.datapaths.items():
                self.shuffle_ports(datapath)

    def shuffle_ports(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        allowed_port = random.choice(self.original_ports)
        self.last_allowed_port = allowed_port

        # Clean up previous flows for all candidate ports
        for port in self.original_ports:
            match = parser.OFPMatch(tcp_dst=port)
            mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                    match=match)
            datapath.send_msg(mod)

        # Install new rules
        for port in self.original_ports:
            match = parser.OFPMatch(ip_proto=6, tcp_dst=port)
            if port == allowed_port:
                # Forward to h1 (port 2)
                actions = [parser.OFPActionOutput(2)]
                self.add_flow(datapath, 100, match, actions)
            else:
                # Drop all other candidate ports
                actions = []
                self.add_flow(datapath, 10, match, actions)

        self.logger.info(f"Allowed port is NOW: {allowed_port}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Learning switch fallback - not affecting TCP rules above
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # No packet_in custom logic needed for port shuffle
        # Just basic learning switch below (optional)
        pkt = msg.data
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=pkt)
        datapath.send_msg(out)
