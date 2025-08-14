#!/bin/python3
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_function)


def packet_function(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)

sniff("wlan0")