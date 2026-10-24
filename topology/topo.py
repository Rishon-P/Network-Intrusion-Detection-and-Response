#!/usr/bin/env python3
"""
Mininet topology for the SDN Intrusion Detection project.

            +------ h1  10.0.0.1  (TCP server)
            |------ h2  10.0.0.2  (benign client)
   s1 ------|------ h3  10.0.0.3  (benign client)
 (OpenFlow1.3)------ h4  10.0.0.4  (attacker)
     |
   c0 = remote Ryu controller at 127.0.0.1:6653

Manual use (from the project root):
    sudo python3 topology/topo.py
"""
from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


def build_net(controller_ip="127.0.0.1", controller_port=6653):
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True)
    net.addController("c0", controller=RemoteController,
                      ip=controller_ip, port=controller_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    h1 = net.addHost("h1", ip="10.0.0.1/24")   # server
    h2 = net.addHost("h2", ip="10.0.0.2/24")   # benign client
    h3 = net.addHost("h3", ip="10.0.0.3/24")   # benign client
    h4 = net.addHost("h4", ip="10.0.0.4/24")   # attacker
    for h in (h1, h2, h3, h4):
        net.addLink(h, s1)
    return net


def wait_for_switch(net, timeout=10):
    """Wait until the switch has connected to the controller."""
    if hasattr(net, "waitConnected"):
        try:
            net.waitConnected(timeout=timeout)
        except TypeError:
            net.waitConnected()


if __name__ == "__main__":
    setLogLevel("info")
    net = build_net()
    net.start()
    wait_for_switch(net)
    info("*** Topology ready: h1=server, h2/h3=benign, h4=attacker\n")
    CLI(net)
    net.stop()
