#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

""" Sniff and spoof to IP outside the LAN. """

def reply(pkt):
    """
    Reply to the packet which the sniffer capture.
    """
    if pkt[ICMP].type == 8:
        ip = IP()
        ip.dst = pkt[IP].src
        ip.src = pkt[IP].dst

        icmp = ICMP()
        icmp.id = pkt[ICMP].id
        icmp.seq = pkt[ICMP].seq
        icmp.type = 0

        raw = Raw()
        raw.load = pkt[Raw].load

        send(ip / icmp / raw)


if __name__ == '__main__':
    pkt = sniff(iface='enp0s3', filter='icmp', prn=reply)
