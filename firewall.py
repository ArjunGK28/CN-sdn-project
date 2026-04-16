#!/usr/bin/env python3
"""
firewall.py: Ryu Controller script combining L2 Learning Switch and Firewall logic.
Supports OpenFlow 1.3.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

import logging

# Configure logging for dropped packets.
# Allowed packets pass silently.
logging.basicConfig(filename='firewall_blocks.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# -----------------------------------------------------------------------------
# FIREWALL RULES DEFINITION
# Data structure defining what traffic to DROP. 
# You can extend this with more rules as needed.
# An empty dictionary here blocks nothing.
# -----------------------------------------------------------------------------
FIREWALL_RULES = [
    # 1. Block by MAC address (Drops ANY traffic from h4 completely)
    {"mac_src": "00:00:00:00:00:04"},
    
    # 2. Block by IP address: Drop traffic from h3 (10.0.0.3) to h1 (10.0.0.1)
    {"ipv4_src": "10.0.0.3", "ipv4_dst": "10.0.0.1"},
    
    # 3. Block by TCP destination port (e.g., blocking HTTP on port 80)
    {"tcp_dst": 80},
    
    # 4. Block by UDP destination port (e.g., blocking iperf default UDP port 5001)
    {"udp_dst": 5001}
]

class L2Firewall(app_manager.RyuApp):
    # Specify OpenFlow 1.3 protocol
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Firewall, self).__init__(*args, **kwargs)
        # Dictionary to maintain MAC-to-Port mappings for learning switches
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Called when a switch connects to the controller.
        Installs the table-miss flow entry to send all unmatched packets 
        to the controller so we can process/learn them.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # match entirely wildcarded (matches everything)
        match = parser.OFPMatch()
        # action is to send to controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # Priority 0 is the lowest priority (table-miss)
        self.add_flow(datapath, 0, match, actions, idle_timeout=0, hard_timeout=0)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """
        Helper method to install a flow rule on the switch.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Wrap actions in an ApplyActions instruction
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # Create FlowMod message
        kwargs = dict(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout
        )
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
            
        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    def install_drop_rule(self, datapath, priority, match, idle_timeout=60, hard_timeout=120):
        """
        Helper method to install a hard DROP flow rule on the switch.
        To drop a packet in OpenFlow, we send a FlowMod with an empty action list.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Empty action list = drop packet
        inst = []
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Triggered when a packet arrives at the controller from the switch 
        (e.g., via table-miss or explicitly sent to controller).
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parse the raw packet data
        pkt = packet.Packet(msg.data)
        
        # Get Ethernet header
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP (Link Layer Discovery Protocol) packets safely
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # ---------------------------------------------------------------------
        # 1. PARSE HEADERS
        # ---------------------------------------------------------------------
        # Try to pull out IPv4, TCP, and UDP headers if they exist
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Build a dictionary roughly mimicking the structure of our firewall rules
        # to allow easy comparisons.
        pkt_info = {
            "mac_src": src,
            "mac_dst": dst,
        }
        
        if ipv4_pkt:
            pkt_info["ipv4_src"] = ipv4_pkt.src
            pkt_info["ipv4_dst"] = ipv4_pkt.dst
            
        if tcp_pkt:
            pkt_info["tcp_src"] = tcp_pkt.src_port
            pkt_info["tcp_dst"] = tcp_pkt.dst_port
            
        if udp_pkt:
            pkt_info["udp_src"] = udp_pkt.src_port
            pkt_info["udp_dst"] = udp_pkt.dst_port

        # ---------------------------------------------------------------------
        # 2. FIREWALL FILTERING LOGIC
        # ---------------------------------------------------------------------
        block = False
        matched_rule = None
        
        # Iterate over all defined rules
        for rule in FIREWALL_RULES:
            # Check if this rule matches the current packet
            # A rule matches if ALL key-value pairs in the rule match the packet
            match_flag = True
            for key, value in rule.items():
                if key not in pkt_info or pkt_info[key] != value:
                    match_flag = False
                    break
            
            if match_flag:
                block = True
                matched_rule = rule
                break # We found a match, no need to check other rules

        if block:
            # Drop the packet and log the event.
            log_msg = f"DROPPED: src_mac={src}, dst_mac={dst}"
            if ipv4_pkt:
                log_msg += f", ipv4_src={pkt_info['ipv4_src']}, ipv4_dst={pkt_info['ipv4_dst']}"
            if tcp_pkt:
                log_msg += f", tcp_dst={pkt_info['tcp_dst']}"
            if udp_pkt:
                log_msg += f", udp_dst={pkt_info['udp_dst']}"
            log_msg += f", matched_rule={matched_rule}"
            
            with open('firewall_blocks.log', 'a') as f:
                import datetime
                f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {log_msg}\n")
            self.logger.info(log_msg)
            
            # Construct a Match to push the drop rule to the switch's flow table.
            # This ensures future packets in this flow are dropped directly by the 
            # switch and don't bother the controller.
            match_kwargs = {'in_port': in_port, 'eth_src': src, 'eth_dst': dst}
            if ipv4_pkt:
                match_kwargs['eth_type'] = ether_types.ETH_TYPE_IP
                match_kwargs['ipv4_src'] = ipv4_pkt.src
                match_kwargs['ipv4_dst'] = ipv4_pkt.dst
                if tcp_pkt:
                    match_kwargs['ip_proto'] = 6 # TCP Protocol Number
                    match_kwargs['tcp_src'] = tcp_pkt.src_port
                    match_kwargs['tcp_dst'] = tcp_pkt.dst_port
                elif udp_pkt:
                    match_kwargs['ip_proto'] = 17 # UDP Protocol Number
                    match_kwargs['udp_src'] = udp_pkt.src_port
                    match_kwargs['udp_dst'] = udp_pkt.dst_port

            match = parser.OFPMatch(**match_kwargs)
            # Priority=100 ensures this drop rule overrides our default forward rules (priority=1)
            self.install_drop_rule(datapath, 100, match, idle_timeout=60, hard_timeout=120)
            
            # Stop processing this packet, thereby dropping it contextually in the controller.
            return

        # ---------------------------------------------------------------------
        # 3. MAC LEARNING & FORWARDING (Allowed Traffic)
        # ---------------------------------------------------------------------
        # Remember the port this MAC address came from
        self.mac_to_port[dpid][src] = in_port

        # If we know where the destination MAC is, send it to that port.
        # Otherwise, flood it out all ports.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # If we know the destination port, install a flow entry to avoid PacketIn 
        # messages for future packets in this flow. We MUST include eth_type so 
        # ARP packets don't create whitelist flows that accidentally allow blocked IPv4 packets!
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=eth.ethertype)
            # Send flow modification
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=60, hard_timeout=120)
                # Packet gets forwarded as part of buffer processing inside OpenFlow
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=60, hard_timeout=120)

        # To send this specific packet out, we construct a PacketOut message.
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
