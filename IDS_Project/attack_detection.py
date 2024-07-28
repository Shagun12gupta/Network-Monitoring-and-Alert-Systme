from scapy.all import IP, TCP, UDP, Raw, ARP, DNS, ICMP
import re
from datetime import datetime, timedelta

# Detection functions for various attacks

def detect_sql_injection(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        sql_patterns = [
            r"(?i)select.*from",
            r"(?i)union.*select",
            r"(?i)drop\s+table",
            r"(?i)insert\s+into",
            r"(?i)delete\s+from"
        ]
        if any(re.search(pattern, payload) for pattern in sql_patterns):
            print("Alert: SQL Injection attempt detected!")

def detect_xss(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*="
        ]
        if any(re.search(pattern, payload) for pattern in xss_patterns):
            print("Alert: XSS attempt detected!")

def detect_dos(packet, dos_detect):
    if not packet.haslayer(IP):
        return

    current_time = datetime.now()
    src_ip = packet[IP].src

    # Clean up old records
    for ip in list(dos_detect['packet_count'].keys()):
        if dos_detect['packet_count'][ip]['timestamp'] < current_time - timedelta(seconds=dos_detect['time_window']):
            del dos_detect['packet_count'][ip]

    # Update packet count for the current source IP
    if src_ip in dos_detect['packet_count']:
        dos_detect['packet_count'][src_ip]['count'] += 1
        dos_detect['packet_count'][src_ip]['timestamp'] = current_time
    else:
        dos_detect['packet_count'][src_ip] = {'count': 1, 'timestamp': current_time}

    # Check if the packet count exceeds the threshold
    if dos_detect['packet_count'][src_ip]['count'] > dos_detect['packet_threshold']:
        print(f"Alert: Potential DDoS attack detected from IP {src_ip}")

def detect_command_injection(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        command_patterns = [
            r"(?i)system\(",
            r"(?i)exec\(",
            r"(?i)eval\(",
            r"(?i)popen\("
        ]
        if any(re.search(pattern, payload) for pattern in command_patterns):
            print("Alert: Command Injection attempt detected!")

def detect_buffer_overflow(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        # Check for unusually large payloads or repeated patterns
        if len(payload) > 1000 or b"\x90" * 100 in payload:  # NOP sled example
            print("Alert: Possible Buffer Overflow attempt detected!")

def detect_arp_spoofing(packet):
    if packet.haslayer(ARP):
        if packet[ARP].op == 2:  # ARP is-at (reply)
            print("Alert: Possible ARP Spoofing detected!")

def detect_dns_spoofing(packet):
    if packet.haslayer(DNS) and packet[DNS].ancount > 0:
        # Compare DNS response IPs with known legitimate IPs
        # (Here we should maintain a database of known IPs)
        print("Alert: Possible DNS Spoofing detected!")

def detect_http_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        # Detect high volume of HTTP requests
        print("Alert: Possible HTTP Flood attack detected!")

def detect_smtp_spam(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 25:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            if "Subject:" in payload and "viagra" in payload.lower():
                print("Alert: Possible SMTP Spam detected!")

def detect_snmp_brute_force(packet):
    if packet.haslayer(UDP) and packet[UDP].dport == 161:
        # Detect multiple SNMP requests possibly indicating brute force
        print("Alert: Possible SNMP Brute Force attack detected!")

def detect_icmp_flood(packet):
    if packet.haslayer(ICMP):
        # Detect high volume of ICMP Echo Request packets
        print("Alert: Possible ICMP Flood attack detected!")

def detect_tftp_abuse(packet):
    if packet.haslayer(UDP) and packet[UDP].dport == 69:
        # Detect unusual TFTP traffic patterns
        print("Alert: Possible TFTP Abuse detected!")

def detect_sip_brute_force(packet):
    if packet.haslayer(UDP) and packet[UDP].dport == 5060:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            if "REGISTER" in payload or "INVITE" in payload:
                print("Alert: Possible SIP Brute Force attack detected!")

def detect_telnet_brute_force(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 23:
        # Detect multiple login attempts possibly indicating brute force
        print("Alert: Possible Telnet Brute Force attack detected!")

def detect_ftp_brute_force(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 21:
        # Detect multiple login attempts possibly indicating brute force
        print("Alert: Possible FTP Brute Force attack detected!")

def detect_rdp_brute_force(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 3389:
        # Detect multiple login attempts possibly indicating brute force
        print("Alert: Possible RDP Brute Force attack detected!")

def detect_ssh_brute_force(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 22:
        # Detect multiple login attempts possibly indicating brute force
        print("Alert: Possible SSH Brute Force attack detected!")

def detect_vpn_brute_force(packet):
    if packet.haslayer(UDP) and packet[UDP].dport == 500:
        # Detect multiple login attempts possibly indicating brute force
        print("Alert: Possible VPN Brute Force attack detected!")

def detect_smb_attack(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 445:
        # Detect SMB-related attack patterns
        print("Alert: Possible SMB attack detected!")

def detect_malware(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect malware signatures
        if "malware_signature" in payload:
            print("Alert: Malware detected!")

def detect_crypto_mining(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect crypto mining traffic
        if "mining" in payload.lower():
            print("Alert: Possible Crypto Mining detected!")

def detect_iot_attack(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect IoT-specific attack patterns
        if "iot" in payload.lower():
            print("Alert: Possible IoT attack detected!")

def detect_dns_tunneling(packet):
    if packet.haslayer(DNS):
        if packet[DNS].qd:
            qname = packet[DNS].qd.qname.decode(errors='ignore')
            # Detect DNS tunneling patterns
            if len(qname) > 50:
                print("Alert: Possible DNS Tunneling detected!")

def detect_http_tunneling(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            # Detect HTTP tunneling patterns
            if "CONNECT" in payload:
                print("Alert: Possible HTTP Tunneling detected!")

def detect_smtp_tunneling(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 25:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            # Detect SMTP tunneling patterns
            if "AUTH LOGIN" in payload:
                print("Alert: Possible SMTP Tunneling detected!")

def detect_bt_sdr(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect Bluetooth SDR-related traffic
        if "bluetooth" in payload.lower():
            print("Alert: Possible Bluetooth SDR attack detected!")

def detect_worm_propagation(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect worm propagation patterns
        if "worm" in payload.lower():
            print("Alert: Possible Worm Propagation detected!")

def detect_dhcp_exhaustion(packet):
    if packet.haslayer(UDP) and packet[UDP].dport == 67:
        # Detect DHCP starvation attacks
        print("Alert: Possible DHCP Exhaustion attack detected!")

def detect_man_in_the_middle(packet):
    if packet.haslayer(TCP):
        # Detect Man-in-the-Middle attack patterns
        print("Alert: Possible Man-in-the-Middle attack detected!")

def detect_data_exfiltration(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect data exfiltration patterns
        if "sensitive_data" in payload:
            print("Alert: Possible Data Exfiltration detected!")

def detect_phishing(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect phishing-related keywords
        phishing_keywords = ["login", "password", "account", "update"]
        if any(keyword in payload.lower() for keyword in phishing_keywords):
            print("Alert: Possible Phishing detected!")

def detect_ssl_stripping(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 443:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            # Detect SSL stripping patterns
            if "http://" in payload.lower():
                print("Alert: Possible SSL Stripping detected!")

def detect_webshell(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect webshell patterns
        if "webshell" in payload.lower():
            print("Alert: Possible Webshell detected!")

def detect_scanning(packet):
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        # Detect port scanning activity
        print("Alert: Possible Scanning detected!")

def detect_p2p_traffic(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect P2P traffic
        if "torrent" in payload.lower():
            print("Alert: Possible P2P traffic detected!")

def detect_wireless_jamming(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect wireless jamming signals
        if "jamming" in payload.lower():
            print("Alert: Possible Wireless Jamming detected!")

def detect_bluetooth_attacks(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Detect Bluetooth attack patterns
        if "bluetooth" in payload.lower():
            print("Alert: Possible Bluetooth Attack detected!")

def detect_spoofing(packet):
    if packet.haslayer(IP):
        # Detect spoofed IP addresses
        if packet[IP].src in ["spoofed_ip_list"]:
            print("Alert: Possible Spoofing detected!")

def detect_unknown_proto(packet):
    if not packet.haslayer(IP):
        print("Alert: Packet with unknown protocol detected!")

# Additional detection functions can be added here
