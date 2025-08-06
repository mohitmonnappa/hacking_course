#!/bin/python3
from scapy import all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    print(arp_request.summary())

scan("192.168.68.0/24")

# Output:
# ARP who has Net("192.168.68.0/24") says 192.168.68.54
