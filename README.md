# Python Network Scanner

[cite_start]A fast, multi-threaded Python-based network scanner that detects active devices in a given IP range[cite: 5]. [cite_start]This project was originally inspired by an Inlighn Tech assignment [cite: 3] and extended to include advanced device identification techniques.

## Features
* [cite_start]**ARP Scanning:** Uses the Scapy library to send out ARP requests and identify active hosts[cite: 14].
* [cite_start]**MAC Address Retrieval:** Collects the hardware MAC address of active devices[cite: 15].
* [cite_start]**Hostname Resolution:** Attempts standard reverse DNS lookups to fetch hostnames[cite: 16].
* **NetBIOS & Vendor Fallback:** Integrates NetBIOS queries and MAC Vendor lookups to identify devices that hide their standard hostnames.
* [cite_start]**Multi-threading:** Utilizes Python's `ThreadPoolExecutor` to scan multiple devices in parallel for rapid execution[cite: 17].

## Prerequisites
This tool uses raw network sockets, which requires it to be run on a Linux system (like Kali Linux) with root privileges.

## Installation
1. Clone this repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git)
   cd YOUR_REPOSITORY_NAME
