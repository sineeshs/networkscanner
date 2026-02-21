# Python Network Scanner

A fast, multi-threaded Python-based network scanner that detects active devices in a given IP range. This project was originally inspired by an Inlighn Tech assignment and extended to include advanced device identification techniques.

## Features
* **ARP Scanning:** Uses the Scapy library to send out ARP requests and identify active hosts.
* **MAC Address Retrieval:** Collects the hardware MAC address of active devices.
* **Hostname Resolution:** Attempts standard reverse DNS lookups to fetch hostnames.
* **NetBIOS & Vendor Fallback:** Integrates NetBIOS queries and MAC Vendor lookups to identify devices that hide their standard hostnames.
* **Multi-threading:** Utilizes Python's `ThreadPoolExecutor` to scan multiple devices in parallel for rapid execution.

## Prerequisites
This tool uses raw network sockets, which requires it to be run on a Linux system (like Kali Linux) with root privileges.

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/sineeshs/networkscanner.git
