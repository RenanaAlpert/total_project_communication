#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether


def icmp_reply(pkt):
    if pkt[ARP].op == 1:
        ip = IP()
        ip.dst = pkt[ARP].psrc
        ip.src = pkt[ARP].pdst

        icmp = ICMP()
        icmp.type = 0

        send(ip / icmp)


if __name__ == '__main__':
    intface = ['br-78ead1488d97']
    pkt = sniff(iface=intface, filter='arp', prn=icmp_reply)
