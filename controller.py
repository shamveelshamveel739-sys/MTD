from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from threading import Thread
import random

class PortShuffleMTD(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(PortShuffleMTD, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.ports_to_shuffle = [8010, 8025, 8050]  # candidate ports
        self.h1_port = 2                            # adjust if needed!
        t = Thread(target=self._manual_shuffler)
        t.daemon = True
        t.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # install table-miss flow (lowest priority)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        # Install an initial port shuffle rule
        self._shuffle_ports(datapath)

    def _add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _manual_shuffler(self):
        while True:
            try:
                input("Press Enter to shuffle MTD port...\n")
            except EOFError:
                break
            # Shuffle for all switches currently registered
            for dpid, datapath in self.datapaths.items():
                self._shuffle_ports(datapath)

    def _shuffle_ports(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        allowed_port = random.choice(self.ports_to_shuffle)
        # Remove all old rules for these ports (for simplicity)
        for port in self.ports_to_shuffle:
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=port)
            mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                    match=match)
            datapath.send_msg(mod)
        # Add DROP flows for all candidate ports except allowed
        for port in self.ports_to_shuffle:
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=port)
            if port == allowed_port:
                actions = [parser.OFPActionOutput(self.h1_port)]
                self._add_flow(datapath, 100, match, actions)
                self.logger.info(f"Allowed port: {allowed_port} (FORWARD to h1)")
            else:
                self._add_flow(datapath, 90, match, [])    # No actions = DROP
                self.logger.info(f"Blocked port: {port} (DROP)")
