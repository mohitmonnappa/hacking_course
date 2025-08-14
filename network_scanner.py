#!/bin/python3
from scapy import all as scapy
import optparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request # / is used to append
    # srp returns 2 lists by default: answered packets and unanswered packets
    answered_packets = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0 ] # srp sends packets with our user defined frame
    clients_list = [] # list of ip and mac of hosts connected
    for element in answered_packets:
        dict_answered_packets = {}
        ip, mac = str(element[1].psrc), str(element[1].hwsrc) # 2nd element has packet details
        dict_answered_packets["ip"], dict_answered_packets["mac"] = ip, mac
        clients_list.append(dict_answered_packets)
    return clients_list


def print_results(results_list):
    print("IP\t\t\tMAC")
    for client in results_list:
        print(client['ip'],"\t", client['mac'])


def ip_input():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="range", help="IP range to scan for devices")
    (options, arguments) = parser.parse_args()
    if not options.range:
        parser.error("[-] Please specify an IP range. Use --help for more info")
    return options.range


ip = ip_input()
print_results(scan(ip))

# Output:
# IP			            MAC
# 192.168.68.1 	     3c:64:cf:36:b4:a8
# 192.168.68.56 	 a8:51:ab:d5:99:07