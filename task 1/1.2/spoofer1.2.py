#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP

""" Send ICMP packet from 10.9.0.4 to 10.9.0.1. """

a = IP(dst="10.9.0.1")
a.src='10.9.0.4'
b = ICMP()
send(a/b)

