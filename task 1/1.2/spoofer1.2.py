#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, ICMP

a = IP(dst="10.9.0.1")
a.src='10.9.0.5'
b = ICMP()
send(a/b)

