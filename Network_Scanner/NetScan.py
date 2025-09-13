#!/usr/bin/env python

import scapy.all as scapy
def scan(ip):
    arp_req=scapy.ARP(pdst=ip)
    #print(arp_packet.show())
    brodcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast=brodcast/arp_req
    answered_list= scapy.srp(arp_req_broadcast, timeout=1,verbose=False)[0]
    print("Mac Address \t\t\t Ip Address")
    for element in answered_list:
        print(element[1].psrc +"\t\t"+ element[1].hwsrc)

scan("192.168.64.0/24")