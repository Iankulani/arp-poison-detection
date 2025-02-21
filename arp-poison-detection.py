# -*- coding: utf-8 -*-
"""
Created on Fri Feb  21 03:345:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("ARP POISON DETECTOR")
print(Fore.GREEN+font)

import os
import subprocess
import re
from scapy.all import ARP, Ether, srp

# Function to get the ARP cache using the system command
def get_arp_cache():
    # For Windows, use 'arp -a'. For Linux/macOS, use 'arp -n'
    if os.name == 'nt':  # Windows
        command = "arp -a"
    else:  # Linux/macOS
        command = "arp -n"
    
    try:
        # Get the ARP cache by running the system command
        output = subprocess.check_output(command, shell=True, text=True)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error getting ARP cache: {e}")
        return None

# Function to check ARP cache for possible poisoning
def check_for_arp_poisoning():
    arp_cache = get_arp_cache()
    if arp_cache is None:
        print("Could not retrieve ARP cache.")
        return
    
    # Use regex to find IP and MAC address mappings
    ip_mac_mapping = {}
    lines = arp_cache.splitlines()
    
    for line in lines:
        match = re.match(r"([0-9\.]+)\s+([a-f0-9:]+)\s+", line, re.IGNORECASE)
        if match:
            ip = match.group(1)
            mac = match.group(2)
            if ip not in ip_mac_mapping:
                ip_mac_mapping[ip] = mac
            else:
                # If the same IP has a different MAC address, it's a possible ARP poisoning
                if ip_mac_mapping[ip] != mac:
                    print(f"WARNING: Possible ARP Poisoning detected for IP {ip}!")
                    print(f"  Original MAC: {ip_mac_mapping[ip]}")
                    print(f"  Attacker's MAC: {mac}")
                else:
                    print(f"ARP Entry: IP {ip} -> MAC {mac}")
    
    print("ARP cache check complete.")

# Function to perform ARP request and verify if the IP address responds correctly
def arp_request(ip):
    # Send ARP request to check if the device responds
    print(f"Performing ARP request to {ip}...")
    
    # Create the ARP request packet
    arp_request = ARP(pdst=ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_request

    # Send the request and capture the response
    ans, _ = srp(ether_frame, timeout=2, verbose=False)

    if ans:
        for sent, received in ans:
            print(f"Received response from {received.psrc} -> MAC: {received.hwsrc}")
            return received.hwsrc
    else:
        print(f"No response received from {ip}.")
        return None

# Main function to initiate ARP poisoning detection
def main():
    # Prompt the user to enter the IP address to check
    ip_address = input("Enter the IP address to check for ARP Poisoning:")
    
    # First, check the ARP cache for any suspicious entries
    check_for_arp_poisoning()
    
    # Perform ARP request to verify the MAC address of the given IP address
    mac_address = arp_request(ip_address)
    if mac_address:
        print(f"MAC Address of {ip_address}: {mac_address}")
    else:
        print(f"No MAC address received for IP {ip_address}. It could be a possible network issue.")

if __name__ == "__main__":
    main()
