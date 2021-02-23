#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP


def print_pkt(pkt):
    # pkt.show
    if (pkt[ICMP].type == 8):
        a = IP(dst=pkt[IP].src)
        a.src = pkt[IP].dst
        b = ICMP()
        send(a / b)

if __name__ == '__main__':
    intface = ['enp0s3']
    pkt = sniff(iface=intface, filter='icmp', prn=print_pkt)
