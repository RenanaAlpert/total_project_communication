#!/usr/bin/env python3
from scapy.all import*
from scapy.layers.inet import IP, ICMP


def print_pkt(pkt):
   #pkt.show
    a = IP(dst=pkt[IP].src)
    a.src = pkt[IP].dst
    a.ttl = 1
    b = ICMP()
    b.type = 0
    send(a / b)

if __name__=='__main__':
    intface = ['enp0s3']
    pkt = sniff(iface= intface, filter= 'icmp', prn= print_pkt)