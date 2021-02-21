#!/usr/bin/env python3
from scapy.all import*

def print_pkt(pkt):
    pkt.show()

if __name__=='__main__':
    intface = ['br-c3830695f822', 'enp0s3']
    pkt = sniff(iface= intface, filter= 'icmp', prn= print_pkt)