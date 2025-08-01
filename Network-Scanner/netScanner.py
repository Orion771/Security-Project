import scapy.all as scapy
import optparse

# دالة لجلب البراميتر من المستخدم
def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="network_ip", help="Target IP range, e.g. 192.168.1.1/24")
    parser.add_option("-i", "--interface", dest="network_interface", help="Network Interface eth0,wlan0")
    options, _ = parser.parse_args()
    if not options.network_ip:
        parser.error("[-] Please specify a network IP/range using -r or --range")
    if not options.network_interface:
        parser.error("[-] Please specify a network interface using -i or --interface")
    return options

# دالة للمسح باستخدام ARP
def scan(network_ip,network_interface):
    arp_request = scapy.ARP(pdst=network_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=network_interface)[0]

    clients = []
    for element in answered:
        client = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clients.append(client)

    return clients

# عرض الأجهزة
def display_clients(clients):
    print("\nIP Address\t\tMAC Address")
    print("==========================================")
    for client in clients:
        print(f"{client['IP']}\t\t{client['MAC']}")
    print()

# تشغيل البرنامج
options = get_args()
clients_list = scan(options.network_ip,options.network_interface)
display_clients(clients_list)
