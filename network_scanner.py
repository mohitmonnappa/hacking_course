#!/bin/python3
from scapy import all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request # / is used to append
    print(arp_broadcast.summary()) # show() can be used to show all details

scan("192.168.68.0/24")

# Output:
# Ether / ARP who has Net("192.168.68.0/24") says 192.168.68.54