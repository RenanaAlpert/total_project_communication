#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP

a = IP(dst="8.8.8.8")
a.ttl = 1
b = ICMP()
ssend(a/b)