#!/usr/bin/env python3
"""
topology.py: Mininet Topology Script
Creates a simple SDN topology for our Ryu Firewall application.
Topology: 3 OVS switches (1 root, 2 edge) connected to 6 hosts, controlled by a remote Ryu controller.
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

    info('*** Adding switches\n')
    # Force use of OpenFlow 1.3 protocol
    s1 = net.addSwitch('s1', protocols='OpenFlow13') # Main root switch
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')

    info('*** Adding hosts\n')
    # Adding 6 hosts total, explicitly setting their IPs and MAC addresses
    # Hosts 1-3 connect to s2
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    # Hosts 4-6 connect to s3
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')

    info('*** Creating links\n')
    # Connect switches
    net.addLink(s1, s2)
    net.addLink(s1, s3)
    
    # Connect hosts to switches
    net.addLink(h1, s2)
    net.addLink(h2, s2)
    net.addLink(h3, s2)
    
    net.addLink(h4, s3)
    net.addLink(h5, s3)
    net.addLink(h6, s3)

    info('*** Starting network\n')
    net.start()

    info('*** Running CLI\n')
    # Open the Mininet prompt. This blocks execution until the user typing 'exit'
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    create_topology()
