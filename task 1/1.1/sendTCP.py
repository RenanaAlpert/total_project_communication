#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import TCP, IP

a = IP(dst="128.230.0.5")
b = TCP()
b.dport = 23
send(a/b)
