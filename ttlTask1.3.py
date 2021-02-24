#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP

a = IP(dst="8.8.8.8")
a.ttl = 4
b = ICMP()
send(a/b)