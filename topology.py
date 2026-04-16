#!/usr/bin/env python3
"""
topology.py: Mininet Topology Script
Creates a simple SDN topology for our Ryu Firewall application.
Topology: 1 OVS switch connected to 4 hosts, controlled by a remote Ryu controller.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import sys

def create_topology():
    # Set the log level to 'info' to see mininet output on the terminal
    setLogLevel('info')

    # Create Mininet object
    # RemoteController tells Mininet to look for an external controller (our Ryu app)
    # OVSSwitch tells Mininet to use Open vSwitch for the OpenFlow implementation
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    info('*** Adding controller\n')
    # Default Ryu OpenFlow port is 6653
    # Connects to localhost where Ryu should be running
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Adding switch\n')
    # Force use of OpenFlow 1.3 protocol
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    info('*** Adding hosts\n')
    # Adding 4 hosts, explicitly setting their IPs and MAC addresses for easier testing
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    info('*** Creating links\n')
    # Connect all hosts to the single switch (s1)
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    info('*** Starting network\n')
    net.start()

    info('*** Running CLI\n')
    # Open the Mininet prompt. This blocks execution until the user typing 'exit'
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    create_topology()
