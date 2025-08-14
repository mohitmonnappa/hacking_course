#!/bin/python3
import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_function)


def packet_function(packet):
    print(packet)

sniff("wlan0")