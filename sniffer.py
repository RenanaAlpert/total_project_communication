#!/usr/bin/env python3
from scapy.all import*

def print_pkt(pkt):
    pkt.show()

if __name__=='__main__':
    pkt = sniff(iface= 'enp0s3', filter= 'icmp', prn= print_pkt)