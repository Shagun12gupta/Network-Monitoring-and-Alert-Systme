import os
import subprocess
import signal
import sys
import csv
import ipaddress
from datetime import datetime, timedelta
from scapy.all import sniff, ARP, Ether, srp, conf, IP
from tabulate import tabulate
from colorama import Fore, init
import threading


# Initialize colorama for colored output
init(autoreset=True)

# Signal handler for graceful exit
def signal_handler(sig, frame):
    print('Exiting...')
    sys.exit(0)

# Function to get the router's IP address (default gateway) on macOS
def get_router_ip():
    try:
        result = subprocess.run(['netstat', '-nr'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'default' in line:
                return line.split()[1]
        raise ValueError("Could not determine router IP address")
    except Exception as e:
        print(f"Error in getting router IP address: {e}")
        sys.exit(1)

# Function to dynamically determine the IP range from the router IP
def get_ip_range(router_ip):
    try:
        ip_network = ipaddress.ip_network(f"{router_ip}/24", strict=False)
        return str(ip_network.network_address) + "/24"
    except Exception as e:
        print(f"Error in determining IP range: {e}")
        sys.exit(1)

# Function to scan the network
def scan_network(ip_range, interface=None):
    try:
        print(f"Scanning IP Range: {ip_range}")
        if interface:
            conf.iface = interface
        arp_request = ARP(pdst=ip_range)
        broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        final_request = broadcast_frame / arp_request
        answered_list = srp(final_request, timeout=2, verbose=False)[0]
        clients = []
        for sent, received in answered_list:
            clients.append({"ip": received.psrc, "mac": received.hwsrc})
        return clients
    except Exception as e:
        print(f"Error in scanning network: {e}")
        sys.exit(1)

# Display the banner with endpoints
def display_banner(endpoints):
    print(Fore.CYAN + "Welcome to RTX CLI")
    print(Fore.GREEN + "Endpoints:")
    
    headers = ["IP Address", "MAC Address"]
    table_data = [[client['ip'], client['mac']] for client in endpoints]
    print(Fore.YELLOW + tabulate(table_data, headers, tablefmt="grid"))
    print()

# Save the endpoints to a file
def save_results(clients, filename):
    try:
        file_exists = os.path.exists(filename)
        mode = 'a' if file_exists else 'w'
        with open(filename, mode, newline='') as csvfile:
            fieldnames = ['Date', 'IP Address', 'MAC Address']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            for client in clients:
                writer.writerow({'Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'IP Address': client['ip'], 'MAC Address': client['mac']})
        print(f"Results stored in {filename}")
    except Exception as e:
        print(f"Error in saving results: {e}")

# Generate a unique filename if the default already exists
def get_unique_filename(filename):
    base, ext = os.path.splitext(filename)
    counter = 1
    new_filename = filename
    while os.path.exists(new_filename):
        new_filename = f"{base}({counter}){ext}"
        counter += 1
    return new_filename

# Function to detect DDoS attacks
def detect_ddos(packet, ddos_detect):
    if not packet.haslayer(IP):
        return

    current_time = datetime.now()
    src_ip = packet[IP].src

    with ddos_detect['lock']:
        # Clean up old records
        for ip in list(ddos_detect['packet_count'].keys()):
            if ddos_detect['packet_count'][ip]['timestamp'] < current_time - timedelta(seconds=ddos_detect['time_window']):
                del ddos_detect['packet_count'][ip]

        # Update packet count for the current source IP
        if src_ip in ddos_detect['packet_count']:
            ddos_detect['packet_count'][src_ip]['count'] += 1
            ddos_detect['packet_count'][src_ip]['timestamp'] = current_time
        else:
            ddos_detect['packet_count'][src_ip] = {'count': 1, 'timestamp': current_time}

        # Check if the packet count exceeds the threshold
        if ddos_detect['packet_count'][src_ip]['count'] > ddos_detect['packet_threshold']:
            if src_ip not in ddos_detect['alerted_ips']:
                ddos_detect['alerted_ips'].add(src_ip)
                print(f"Alert: Potential DDoS attack detected from IP {src_ip}")

# Callback function for packet sniffing
def packet_callback(packet):
    if packet.haslayer(IP):
        packet_number = packet_callback.counter
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        info = packet.summary()

        try:
            with open(packet_callback.logfile, 'a', newline='') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow([packet_number, timestamp, src, dst, proto, length, info])
        except Exception as e:
            print(f"Error in writing packet details: {e}")

        packet_callback.counter += 1

        # Use threading to check for DDoS attacks
        threading.Thread(target=detect_ddos, args=(packet, ddos_detect)).start()

# Initialize DDoS detection attributes with thread lock and alert tracking
ddos_detect = {
    'packet_count': {},
    'packet_threshold': 100,  # Adjust this threshold as needed
    'time_window': 10,        # Time window in seconds
    'alerted_ips': set(),    # Track IPs that have already triggered an alert
    'lock': threading.Lock() # Lock for thread safety
}

# Initialize packet callback function attributes
packet_callback.counter = 1
packet_callback.logfile = ''

# Main function
def main():
    signal.signal(signal.SIGINT, signal_handler)

    # Display banner
    print(Fore.CYAN + """
    _  _     _                  _     __  __          _ _           _                  
   | \\| |___| |___ __ _____ _ _| |__ |  \\/  |___ _ _ (_) |_ ___ _ _(_)_ _  __ _        
   | .` / -_)  _\\ V  V / _ \\ '_| / / | |\\/| / _ \\ ' \\| |  _/ _ \\ '_| | ' \\/ _` |       
   |_|\_\\___|\\__|\\_/\\_/\\___/_| |_\\_\\ |_|  |_\\___/_||_|_|\\__\\___/_| |_|_||_\\__, |       
                                                                           |___/           
              /_\\  _ _  __| |                                                    
             / _ \\| ' \\/ _` |                                                          
            /_/ \\_\\_||_\\__,_|                                                          
  ___     _               _              _   _         _     ___         _             
 |_ _|_ _| |_ _ _ _  _ __(_)___ _ _     /_\\ | |___ _ _| |_  / __|_  _ __| |__ ___ _ __  
  | || ' \\  _| '_| || (_-< / _ \\ ' \\   / _ \\| / -_) '_|  _| \\__ \\ || (_-<  __/ -_) '  \\ 
 |___|_||_\\__|_|  \\_,_/__/_\\___/_||_| /_/ \\_\\_\\___|_|  \\__| |___/\\_, /__/_\\__\\___|_|_|_|
                                                                 |__/                  
    """)
    
    # Get router IP and determine IP range
    router_ip = get_router_ip()
    ip_range = get_ip_range(router_ip)

    # Scan network for endpoints
    endpoints = scan_network(ip_range)
    if not endpoints:
        print("No endpoints found.")
        sys.exit(1)
    
    display_banner(endpoints)

    # Save the endpoints to 'endpoints.csv' without prompting
    save_results(endpoints, "endpoints.csv")

    # Automatically generate a filename for network monitoring
    file_name = get_unique_filename("packet_log.csv")

    print(Fore.GREEN + f"Monitoring network traffic... Logs will be saved in {file_name}\n")

    headers = ["Number", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    # Start network traffic monitoring
    packet_callback.logfile = file_name
    try:
        with open(packet_callback.logfile, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(headers)
    except Exception as e:
        print(f"Error in creating log file: {e}")
        sys.exit(1)

    print(Fore.GREEN + "Starting packet sniffing...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
