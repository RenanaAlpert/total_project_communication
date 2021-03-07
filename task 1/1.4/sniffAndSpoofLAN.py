#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

""" Sniff and spoof to IP in the LAN. """

def icmp_reply(pkt):
    """
    Reply to the packet which the sniffer capture.
    """
    if pkt[ARP].op == 1:
        ip = IP()
        ip.dst = pkt[ARP].psrc
        ip.src = pkt[ARP].pdst

        icmp = ICMP()
        icmp.type = 0

        send(ip / icmp)


if __name__ == '__main__':
    pkt = sniff(iface='br-78ead1488d97', filter='arp', prn=icmp_reply)
