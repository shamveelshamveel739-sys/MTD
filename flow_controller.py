from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route, Response
from threading import Thread
import random
import time

class MTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(MTDController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.ports_to_shuffle = [8010, 8025, 8050]
        self.h1_port = 2
        self.current_allowed_port = None
        wsgi = kwargs['wsgi']
        wsgi.register(RestAPI, {'mtd': self})
        t = Thread(target=self._periodic_shuffler)
        t.daemon = True
        t.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def _periodic_shuffler(self):
        while True:
            for dpid, datapath in self.datapaths.items():
                self._coordinated_shuffle(datapath)
            time.sleep(30)

    def _coordinated_shuffle(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        old_port = self.current_allowed_port
        available_ports = [p for p in self.ports_to_shuffle if p != old_port]
        new_port = random.choice(available_ports) if available_ports else self.ports_to_shuffle[0]

        # Install flow for new port (high priority)
        match_new = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=new_port)
        actions_new = [parser.OFPActionOutput(self.h1_port)]
        self._add_flow(datapath, 110, match_new, actions_new, idle_timeout=30)

        # Keep old port flow temporarily (soft handover)
        if old_port is not None:
            match_old = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=old_port)
            actions_old = [parser.OFPActionOutput(self.h1_port)]
            self._add_flow(datapath, 100, match_old, actions_old, idle_timeout=10)

        # Drop all other ports
        for port in self.ports_to_shuffle:
            if port != new_port and port != old_port:
                match_drop = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=port)
                self._add_flow(datapath, 90, match_drop, [])

        self.current_allowed_port = new_port
        self.logger.info(f"Port updated from {old_port} to {new_port}, soft handover active.")

class RestAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RestAPI, self).__init__(req, link, data, **config)
        self.mtd = data['mtd']

    @route('get_port', '/getport', methods=['GET'])
    def get_port(self, req, **kwargs):
        body = str(self.mtd.current_allowed_port)
        return Response(content_type='text/plain', body=body)
