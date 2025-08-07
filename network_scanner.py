#!/bin/python3
from scapy import all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request # / is used to append
    # srp returns 2 lists by default: answered packets and unanswered packets
    answered = scapy.srp(arp_broadcast, timeout=1)[0] # srp sends packets with our user defined frame
    print(answered.summary())


scan("192.168.68.0/24")

# Output:
# Ether / ARP who has 192.168.68.1 says 192.168.68.60 ==> Ether / ARP is at 3c:64:cf:36:b4:a8 says 192.168.68.1
# Ether / ARP who has 192.168.68.57 says 192.168.68.60 ==> Ether / ARP is at 3c:a3:08:00:b9:19 says 192.168.68.57