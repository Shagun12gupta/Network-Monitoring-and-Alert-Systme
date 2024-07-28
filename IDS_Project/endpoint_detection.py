import sys
import argparse
import csv
import logging
import os
from datetime import datetime
from scapy.all import ARP, Ether, srp, conf

def parse_arguments():
    parser = argparse.ArgumentParser(description="ARP Network Scanner")
    parser.add_argument("-ip", "--ipadd", help="IP Address/Subnet Mask", required=True)
    parser.add_argument("-i", "--interface", help="Network Interface", default=None)
    parser.add_argument("-o", "--output", help="Output file (CSV format)", default="results.csv")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    return parser.parse_args()

def scan_network(ip, interface=None):
    if interface:
        conf.iface = interface
    arp_request = ARP(pdst=ip)
    broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    final_request = broadcast_frame / arp_request
    answered_list = srp(final_request, timeout=2, verbose=False)[0]
    clients = []
    for sent, received in answered_list:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})
    return clients

def display_results(clients):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")

def save_results(clients, filename):
    file_exists = os.path.exists(filename)
    mode = 'a' if file_exists else 'w'
    with open(filename, mode, newline='') as csvfile:
        fieldnames = ['Date', 'IP Address', 'MAC Address']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        for client in clients:
            writer.writerow({'Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'IP Address': client['ip'], 'MAC Address': client['mac']})

def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(filename='arp_scanner.log', level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def main(args=None):
    if args is None:
        args = parse_arguments()
    setup_logging(args.verbose)
    if not args.ipadd:
        logging.error("Invalid Syntax. Use --help or -h for options.")
        print("Invalid Syntax")
        print("Use --help or -h for options.")
        sys.exit(1)
    clients = scan_network(args.ipadd, args.interface)
    if clients:
        display_results(clients)
        save_results(clients, args.output)
        print(f"\nResults appended to {args.output}")
        logging.info(f"Results appended to {args.output}")
    else:
        print("No clients found.")
        logging.info("No clients found.")

if __name__ == "__main__":
    main()
