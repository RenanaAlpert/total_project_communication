#!/usr/bin/env python3
from scapy.all import*

""" Sniffer for all task 1. """

def print_pkt(pkt):
    """ Show the packet """
    pkt.show()

if __name__=='__main__':
    """
    The filters:
    icmp - icmp,
    tcp with destination port 23 - ip host 10.9.0.5 and tcp dst port 23,
    subnet - net 128.230.0.0/16.
    """
    pkt = sniff(iface = 'enp0s3', filter = 'icmp', prn = print_pkt)