import argparse
from scapy.all import sniff, IP
import logging
import signal
import sys
import csv
from datetime import datetime, timedelta
from attack_detection import (
    detect_sql_injection, detect_xss, detect_dos,
    detect_command_injection, detect_buffer_overflow, detect_arp_spoofing,
    detect_dns_spoofing, detect_http_flood, detect_smtp_spam,
    detect_snmp_brute_force, detect_icmp_flood, detect_tftp_abuse,
    detect_sip_brute_force, detect_telnet_brute_force, detect_ftp_brute_force,
    detect_rdp_brute_force, detect_ssh_brute_force, detect_vpn_brute_force,
    detect_smb_attack, detect_malware, detect_crypto_mining, detect_iot_attack,
    detect_dns_tunneling, detect_http_tunneling, detect_smtp_tunneling,
    detect_bt_sdr, detect_worm_propagation, detect_dhcp_exhaustion,
    detect_man_in_the_middle, detect_data_exfiltration, detect_phishing,
    detect_ssl_stripping, detect_webshell, detect_scanning, detect_p2p_traffic,
    detect_wireless_jamming, detect_bluetooth_attacks, detect_spoofing,
    detect_unknown_proto
)

# Setup logging for network monitoring
def setup_logging(logfile):
    logging.basicConfig(filename=logfile, level=logging.INFO, format='%(message)s')

# Callback function for packet sniffing
def packet_callback(packet, dos_detect):
    if not packet.haslayer(IP):
        detect_unknown_proto(packet)
        return

    # Extract packet details
    packet_number = packet_callback.counter
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    src = packet[IP].src
    dst = packet[IP].dst
    proto = packet[IP].proto
    length = len(packet)
    info = packet.summary()

    # Write packet details to CSV file
    try:
        with open(packet_callback.logfile, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([packet_number, timestamp, src, dst, proto, length, info])
    except Exception as e:
        print(f"Error in writing packet details: {e}")

    # Increment packet counter
    packet_callback.counter += 1

    # Call detection functions
    detect_sql_injection(packet)
    detect_xss(packet)
    detect_dos(packet, dos_detect)
    detect_command_injection(packet)
    detect_buffer_overflow(packet)
    detect_arp_spoofing(packet)
    detect_dns_spoofing(packet)
    detect_http_flood(packet)
    detect_smtp_spam(packet)
    detect_snmp_brute_force(packet)
    detect_icmp_flood(packet)
    detect_tftp_abuse(packet)
    detect_sip_brute_force(packet)
    detect_telnet_brute_force(packet)
    detect_ftp_brute_force(packet)
    detect_rdp_brute_force(packet)
    detect_ssh_brute_force(packet)
    detect_vpn_brute_force(packet)
    detect_smb_attack(packet)
    detect_malware(packet)
    detect_crypto_mining(packet)
    detect_iot_attack(packet)
    detect_dns_tunneling(packet)
    detect_http_tunneling(packet)
    detect_smtp_tunneling(packet)
    detect_bt_sdr(packet)
    detect_worm_propagation(packet)
    detect_dhcp_exhaustion(packet)
    detect_man_in_the_middle(packet)
    detect_data_exfiltration(packet)
    detect_phishing(packet)
    detect_ssl_stripping(packet)
    detect_webshell(packet)
    detect_scanning(packet)
    detect_p2p_traffic(packet)
    detect_wireless_jamming(packet)
    detect_bluetooth_attacks(packet)
    detect_spoofing(packet)
    # Add more calls to detection functions here...

# Initialize packet callback function attributes
packet_callback.counter = 1
packet_callback.logfile = ''

# Signal handler for graceful exit
def signal_handler(sig, frame):
    print('Stopping network traffic monitor...')
    sys.exit(0)

def main(logfile=None):
    # Initialize DoS detection attributes
    dos_detect = {
        'packet_count': {},
        'packet_threshold': 100,  # Adjust this threshold as needed
        'time_window': 10,        # Time window in seconds
        'alerted_ips': set()
    }

    # Generate logfile if not provided
    if logfile is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        logfile = f"logfile_{timestamp}.csv"

    packet_callback.logfile = logfile
    # Setup CSV file and write header
    try:
        with open(logfile, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(['Number', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
    except Exception as e:
        print(f"Error in creating CSV file: {e}")
        sys.exit(1)

    print(f'Starting network traffic monitor... Press Ctrl+C to stop. Logging to {logfile}')

    # Start sniffing traffic
    try:
        sniff(prn=lambda pkt: packet_callback(pkt, dos_detect), store=0)
    except Exception as e:
        print(f"Error in starting packet sniffing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Traffic Monitor")
    parser.add_argument("-o", "--output", help="Output file for logging packets")
    args = parser.parse_args()

    # Setup signal handling
    signal.signal(signal.SIGINT, signal_handler)

    # Start main function
    main(args.output)


def main(logfile=None):
    global ddos_detect

    # Generate logfile if not provided
    if logfile is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        logfile = f"logfile_{timestamp}.csv"

    packet_callback.logfile = logfile
    # Setup CSV file and write header
    try:
        with open(logfile, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(['Number', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
    except Exception as e:
        print(f"Error in creating CSV file: {e}")
        sys.exit(1)

    print(f'Starting network traffic monitor... Press Ctrl+C to stop. Logging to {logfile}')

    # Start sniffing traffic
    try:
        sniff(prn=lambda pkt: packet_callback(pkt, ddos_detect), store=0)
    except Exception as e:
        print(f"Error in starting packet sniffing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Traffic Monitor")
    parser.add_argument("-o", "--output", help="Output file for logging packets")
    args = parser.parse_args()

    # Setup signal handling
    signal.signal(signal.SIGINT, signal_handler)

    # Start main function
    main(args.output)
