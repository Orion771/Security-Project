import scapy.all as scapy
import optparse

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="ip_range", help="Specify IP range (e.g. 192.168.1.1/24)")
    parser.add_option("-i", "--interface", dest="interface", help="Specify network interface (e.g. eth0, wlan0)")
    options, _ = parser.parse_args()

    if not options.ip_range:
        parser.error("[-] Please enter an IP range using -r <range>")
    if not options.interface:
        parser.error("[-] Please enter an interface using -i <interface>")

    return options

def scan(ip_range, interface):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]

    clients = []
    for element in answered:
        client = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients.append(client)

    return clients

def print_result(results):
    print("IP\t\t\tMAC Address")
    print("-" * 40)
    for client in results:
        print(f"{client['ip']}\t\t{client['mac']}")

options = get_args()
scan_results = scan(options.ip_range, options.interface)
print_result(scan_results)
