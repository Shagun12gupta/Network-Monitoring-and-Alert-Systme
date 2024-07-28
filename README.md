# Network Security Project

## Overview
This project consists of various network security scripts designed to detect and analyze different types of network traffic and potential attacks. The main components include a network scanner, a network traffic monitor, and various attack detection modules.

## Features
- **Network Scanning**: Identifies endpoints in a network using ARP requests.
- **Network Monitoring**: Monitors network traffic and logs packet details.
- **Attack Detection**: Detects a variety of network attacks such as DDoS, SQL Injection, XSS, and more.

## Requirements
- Python 3.x
- `scapy` library
- `colorama` library
- `tabulate` library
- `argparse` library

## Installation
1. Clone the repository:

   `git clone <repository-url>`
2. Navigate to the project directory

   `cd <project-directory>`

3. Install the required packages:

   `pip install -r requirements.txt`


**#Usage**

The main script performs network scanning, monitoring, and attack detection.
  Run the main script:
  `python main_script.py`
This script will display a banner, scan the network for endpoints, display them, and start monitoring network traffic for potential attacks.


**##Scripts Overview**
rtx.py.py
-This is the main script that integrates network scanning, monitoring, and attack detection. It initializes the environment, scans the network, displays the results, and starts packet sniffing.

network_monitoring.py
-This script handles the monitoring of network traffic and logs details about each packet. It also integrates with attack detection modules to identify potential threats.

endpoint_detection.py
-This script performs ARP scanning to discover devices in a network and logs their IP and MAC addresses.

attack_detection.py
-This module contains functions for detecting various types of network attacks, including DDoS, SQL Injection, XSS, and more.

**##Contributing**
Feel free to fork the repository, make changes, and submit pull requests. Any improvements or bug fixes are welcome!

This README covers the essential aspects of your project, including setup, usage, and a 
