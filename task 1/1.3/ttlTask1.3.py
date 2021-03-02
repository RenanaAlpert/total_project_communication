#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP

a = IP(dst="10.2.0.5")
a.ttl = 20
b = ICMP()
send(a/b)
