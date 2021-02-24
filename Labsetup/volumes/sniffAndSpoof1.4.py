#!/usr/bin/env python3
from scapy.all import*
from scapy.layers.inet import IP, ICMP


def print_pkt(pkt):
    if(pkt[ICMP].type == 8):
        eth = Ether()
        eth.dst = pkt[Ether].src
        eth.src = pkt[Ether].dst

        ip = IP()
        ip.dst = pkt[IP].src
        ip.src = pkt[IP].dst
        ip. ihl = pkt[IP].ihl

        icmp = ICMP()
        icmp.id = pkt[ICMP].id
        icmp.seq = pkt[ICMP].seq
        icmp.type = 0

        raw = Raw()
        raw.load = pkt[Raw].load

        send(eth/ip/icmp/raw)

if __name__=='__main__':
    intface = ['enp0s3']
    pkt = sniff(iface= intface, filter= 'icmp', prn= print_pkt)