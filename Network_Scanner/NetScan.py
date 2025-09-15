#!/usr/bin/env python

import scapy.all as scapy
def scan(ip):
    arp_req=scapy.ARP(pdst=ip)
    #print(arp_packet.show())
    brodcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast=brodcast/arp_req
    answered_list= scapy.srp(arp_req_broadcast, timeout=1,verbose=False)[0]

    client_list=[]
    for element in answered_list:
        client_dict={"ip":element [1].psrc,"mac":element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
def print_result(result_list):
        print("Mac Address \t\t\t Ip Address")
        for client in result_list:
            print(client["ip"] +"\t\t"+ client["mac"])

scan_res=scan("192.168.64.0/24")
print_result(scan_res)