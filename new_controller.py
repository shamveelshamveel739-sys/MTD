from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from threading import Thread
import random
import socket
import time

class CoordinatedPortShuffleMTD(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CoordinatedPortShuffleMTD, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.ports_to_shuffle = [8010, 8025, 8050]
        self.h1_port = 2
        self.current_allowed_port = None
        self.sender_socket_port = 9999  # Port where sender listens for notifications

        # Start periodic shuffle thread
        t = Thread(target=self._periodic_shuffler)
        t.daemon = True
        t.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # Set table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _periodic_shuffler(self):
        while True:
            for dpid, datapath in self.datapaths.items():
                self._coordinated_shuffle(datapath)
            time.sleep(30)  # Shuffle every 30 seconds

    def _coordinated_shuffle(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        old_port = self.current_allowed_port
        # Choose new allowed port different from current
        available_ports = [p for p in self.ports_to_shuffle if p != old_port]
        new_port = random.choice(available_ports)

        # Notify sender asynchronously about new port via TCP socket
        self._notify_sender(new_port)

        # Install flow for new port with higher priority, soft handover active
        match_new = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=new_port)
        actions_new = [parser.OFPActionOutput(self.h1_port)]
        self._add_flow(datapath, 110, match_new, actions_new, idle_timeout=30)

        # Keep old port flow for a grace period for soft handover
        if old_port is not None:
            match_old = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=old_port)
            actions_old = [parser.OFPActionOutput(self.h1_port)]
            self._add_flow(datapath, 100, match_old, actions_old, idle_timeout=10)

        # Install drop rules for other ports except new and old
        for port in self.ports_to_shuffle:
            if port != new_port and port != old_port:
                match_drop = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=port)
                self._add_flow(datapath, 90, match_drop, [])

        self.current_allowed_port = new_port
        self.logger.info(f"Port updated from {old_port} to {new_port}, soft handover in progress")

    def _notify_sender(self, new_port):
        try:
            # Connect to sender's listening socket and send new port
            with socket.create_connection(('127.0.0.1', self.sender_socket_port), timeout=2) as sock:
                sock.sendall(str(new_port).encode())
                self.logger.info(f"Notified sender of new port: {new_port}")
        except Exception as e:
            self.logger.error(f"Failed to notify sender: {e}")
