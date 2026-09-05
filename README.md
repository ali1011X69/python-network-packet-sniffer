# 🛡️ Python Network Packet Sniffer

A lightweight **network packet sniffer built with Python and Linux raw sockets**. This project captures network traffic and parses Ethernet, IPv4, ICMP, TCP, and UDP packets to help understand how network communication works at the packet level.

> ⚠️ **Educational & Ethical Use Only:** Use this tool only on networks and systems that you own or have explicit permission to monitor.

---

## 📌 Features

* 🔹 Captures Ethernet frames
* 🔹 Displays source and destination MAC addresses
* 🔹 Parses IPv4 packets
* 🔹 Displays source and destination IP addresses
* 🔹 Identifies network protocols
* 🔹 Supports:

  * ICMP
  * TCP
  * UDP
* 🔹 Displays TCP flags:

  * URG
  * ACK
  * PSH
  * RST
  * SYN
  * FIN
* 🔹 Displays TCP sequence and acknowledgement numbers
* 🔹 Displays UDP source/destination ports and packet length
* 🔹 Displays packet payload in hexadecimal format
* 🔹 Supports selecting a specific network interface
* 🔹 Designed for Linux/Kali Linux

---

## 🛠️ Technologies Used

| Technology | Purpose                |
| ---------- | ---------------------- |
| Python 3   | Programming language   |
| Socket     | Raw packet capture     |
| Struct     | Binary packet parsing  |
| Textwrap   | Formatting packet data |
| Linux      | Raw socket networking  |

---

## 📂 Project Structure

```text
python-network-packet-sniffer/
│
├── packet_sniffer.py
├── README.md
├── requirements.txt
└── LICENSE
```

---

## ⚙️ Requirements

* Linux operating system
* Python 3.x
* Root/sudo privileges
* Network interface such as Wi-Fi or Ethernet

No external Python packages are required.

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/python-network-packet-sniffer.git
```

### 2. Enter the project directory

```bash
cd python-network-packet-sniffer
```

### 3. Check Python

```bash
python3 --version
```

---

## ▶️ Usage

### Start the packet sniffer

```bash
sudo python3 packet_sniffer.py
```

The program will listen for packets on the available network interfaces.

---

### Select a network interface

First, check your available interfaces:

```bash
ip link
```

Example:

```text
lo
eth0
wlan0
```

Then run:

```bash
sudo python3 packet_sniffer.py -i wlan0
```

Replace `wlan0` with your actual interface name.

For example:

```bash
sudo python3 packet_sniffer.py -i eth0
```

---

## 🧪 Testing

After starting the packet sniffer, open another terminal and generate some network traffic.

For example:

```bash
ping google.com
```

You should see ICMP packets being captured.

You can also open a website or perform other normal network activity to observe TCP and UDP traffic.

---

## 📊 Example Output

```text
======================================================================

Ethernet Frame:
    - Destination: XX:XX:XX:XX:XX:XX
    - Source: XX:XX:XX:XX:XX:XX
    - Protocol: 8

    - IPv4 Packet:
        - Version: 4
        - Header Length: 20
        - TTL: 64
        - Protocol: 6
        - Source: 192.168.1.10
        - Target: 142.250.183.14

    - TCP Segment:
        - Source Port: 54321
        - Destination Port: 443
        - Sequence: XXXXX
        - Acknowledgement: XXXXX

        - Flags:
            - URG: 0
            - ACK: 1
            - PSH: 0
            - RST: 0
            - SYN: 1
            - FIN: 0
```

---

## 🧠 How It Works

The packet sniffer follows this basic process:

```text
Network Interface
       ↓
Raw Socket
       ↓
Ethernet Frame
       ↓
IPv4 Packet
       ↓
Protocol Identification
       ↓
 ┌─────┼─────┐
 ↓     ↓     ↓
ICMP  TCP   UDP
 ↓     ↓     ↓
Parse Packet Headers
       ↓
Display Information
```

### Packet Layers

The program analyzes packets from the lower networking layers upward:

```text
Ethernet
   ↓
IPv4
   ↓
TCP / UDP / ICMP
   ↓
Payload
```

---

## 📚 What I Learned

While building this project, I improved my understanding of:

* Python socket programming
* Linux networking
* Raw sockets
* Ethernet frames
* MAC addresses
* IPv4 packet structure
* TCP headers
* UDP headers
* ICMP packets
* TCP flags
* Network protocols
* Binary data parsing using Python `struct`
* Basic packet analysis

---

## 🔮 Future Improvements

Possible improvements for future versions:

* [ ] Add DNS packet parsing
* [ ] Add ARP packet parsing
* [ ] Add HTTP packet detection
* [ ] Add packet filtering
* [ ] Add protocol statistics
* [ ] Add packet counters
* [ ] Add logging to a file
* [ ] Add a graphical interface
* [ ] Add PCAP export
* [ ] Improve packet visualization
* [ ] Add configurable filters for IP addresses and ports

---

## 🔐 Ethical Disclaimer

This project is created for **educational and cybersecurity learning purposes**.

Do not use this tool to intercept, monitor, or analyze network traffic without authorization.

Only use it on:

* Your own computer
* Your own lab environment
* Networks you are authorized to test
* Cybersecurity training environments

---

## 👨‍💻 Author

**MD Ali Abbas**

BSc Cyber Security Student

Interested in:

* Cybersecurity
* Network Security
* Security Analysis
* Python
* Linux
* Ethical Hacking

---

## ⭐ Support

If you found this project useful for learning, consider giving the repository a ⭐ on GitHub.

---

**Built with Python 🐍 | Linux 🐧 | Cybersecurity 🔐**
