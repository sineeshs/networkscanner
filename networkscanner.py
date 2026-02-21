import scapy.all as scapy
import socket 
import ipaddress
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from mac_vendor_lookup import MacLookup

def get_netbios_name(ip):
    """Attempts to get the hostname directly from the device via NetBIOS."""
    try:
        packet = scapy.IP(dst=ip) / scapy.UDP(sport=137, dport=137) / scapy.NBNSQueryRequest(QUESTION_NAME="*")
        response = scapy.sr1(packet, timeout=1, verbose=False)
        
        if response and response.haslayer(scapy.NBNSQueryResponse):
            name = response.getlayer(scapy.NBNSQueryResponse).RR_NAME.decode('utf-8').strip()
            return name.replace('\x00', '')
    except Exception:
        pass
    return None

def scan(ip, result_queue):
    """Scans a single IP, grabs the MAC, and attempts to resolve the hostname."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    answer = scapy.srp(packet, timeout=1, verbose=False)[0]

    clients = []
    for client in answer:
        client_info = {'IP': client[1].psrc, 'MAC': client[1].hwsrc}
        
        # 1. Try standard DNS
        try:
            hostname = socket.gethostbyaddr(client_info['IP'])[0]
        except socket.herror:
            # 2. Try NetBIOS
            nb_name = get_netbios_name(client_info['IP'])
            if nb_name:
                hostname = nb_name
            else:
                # 3. Fallback to MAC Vendor Lookup
                try:
                    vendor = MacLookup().lookup(client_info['MAC'])
                    hostname = f"Unknown ({vendor})"
                except Exception:
                    hostname = "Unknown"
                    
        client_info['Hostname'] = hostname
        clients.append(client_info)
        
    if clients:
        result_queue.put(clients)

def print_result(result):
    """Prints the discovered devices in a formatted table."""
    print('\n' + 'IP'.ljust(18) + 'MAC'.ljust(20) + 'Hostname')
    print('-' * 70)
    for client in result:
        print(client['IP'].ljust(18) + client['MAC'].ljust(20) + client['Hostname'])

def main(cidr):
    results_queue = Queue()
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print("Invalid CIDR format. Please try again (e.g., 192.168.1.0/24).")
        return

    hosts = list(network.hosts())
    print(f"Scanning {len(hosts)} hosts. Please wait...")

    # Using ThreadPoolExecutor prevents the system from being overwhelmed by too many threads
    with ThreadPoolExecutor(max_workers=50) as executor:
        for ip in hosts:
            executor.submit(scan, str(ip), results_queue)
    
    all_clients = []
    while not results_queue.empty():
        all_clients.extend(results_queue.get())
    
    if not all_clients:
        print("No active devices found.")
    else:
        # Sort by IP address before printing
        all_clients.sort(key=lambda x: ipaddress.IPv4Address(x['IP']))
        print_result(all_clients)

if __name__ == '__main__':
    cidr = input("Enter network ip address (e.g., 192.168.1.0/24): ")
    main(cidr)
