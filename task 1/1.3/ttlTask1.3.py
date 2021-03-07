#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP

""" Finding the ttl to 8.8.8.8. """

a = IP(dst="8.8.8.8")
a.ttl = 20
b = ICMP()
send(a/b)
