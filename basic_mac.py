#!/usr/bin/python3
import subprocess
import optparse
import re


def get_arguments() :
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    (options,arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.new_mac:
        parser.error("[-] Please specify a new mac, use --help for more info.")
    return options


def change_mac(interface, new_mac):
    # sudo is required because ifconfig needs elevated permission
    # just running the program with eleavated permission isn't enough
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["sudo", "ifconfig", interface, "up"])


def get_changed_mac(interface):
    ifconfig_result = str(subprocess.check_output(["ifconfig", interface])) # returns output of the command
    # \w represents alpha-numeric, 6 parts of 2 \w in total seperated by :
    regex_match_mac = re.search(r"((\w){2}:){5}(\w){2}", ifconfig_result)
    return regex_match_mac.group(0) if regex_match_mac else None


options = get_arguments()
current_mac = get_changed_mac(options.interface)
print("Current MAC Address:", current_mac) if current_mac else print("Could not get the MAC")

change_mac(options.interface, options.new_mac)
updated_mac = get_changed_mac(options.interface)


if updated_mac == options.new_mac:
    print("[+] MAC Address successfully changed to:", updated_mac)
else:
    print("[+] Could not change the MAC Address.")