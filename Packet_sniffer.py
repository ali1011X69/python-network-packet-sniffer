```python
import socket
import struct
import textwrap
import argparse


TAB_1 = '\t- '
TAB_2 = '\t\t- '
TAB_3 = '\t\t\t- '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '

# Ethernet protocol
ETH_P_ALL = 0x0003


def main(interface=None):
    try:
        # Create raw socket
        conn = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL)
        )

        # Bind to a specific interface if provided
        if interface:
            conn.bind((interface, 0))
            print(f"[*] Listening on interface: {interface}")
        else:
            print("[*] Listening on all interfaces")

        print("[*] Packet sniffer started")
        print("[*] Press Ctrl+C to stop\n")

        while True:
            raw_data, addr = conn.recvfrom(65535)

            # Need at least an Ethernet header
            if len(raw_data) < 14:
                continue

            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            print("\n" + "=" * 70)
            print("Ethernet Frame:")
            print(
                TAB_1 +
                f"Destination: {dest_mac}, "
                f"Source: {src_mac}, "
                f"Protocol: {eth_proto}"
            )

            # IPv4
            if eth_proto == 8:

                if len(data) < 20:
                    continue

                try:
                    (
                        version,
                        header_length,
                        ttl,
                        proto,
                        src,
                        target,
                        data
                    ) = ipv4_packet(data)

                except struct.error:
                    continue

                print(TAB_1 + "IPv4 Packet:")
                print(
                    TAB_2 +
                    f"Version: {version}, "
                    f"Header Length: {header_length}, "
                    f"TTL: {ttl}"
                )

                print(
                    TAB_2 +
                    f"Protocol: {proto}, "
                    f"Source: {src}, "
                    f"Target: {target}"
                )

                # ICMP
                if proto == 1:

                    if len(data) < 4:
                        continue

                    try:
                        icmp_type, code, checksum, data = icmp_packet(data)
                    except struct.error:
                        continue

                    print(TAB_1 + "ICMP Packet:")
                    print(
                        TAB_2 +
                        f"Type: {icmp_type}, "
                        f"Code: {code}, "
                        f"Checksum: {checksum}"
                    )

                    print(TAB_2 + "Data:")
                    print(format_multi_line(DATA_TAB_3, data))

                # TCP
                elif proto == 6:

                    if len(data) < 20:
                        continue

                    try:
                        (
                            src_port,
                            dest_port,
                            sequence,
                            acknowledgement,
                            flag_urg,
                            flag_ack,
                            flag_psh,
                            flag_rst,
                            flag_syn,
                            flag_fin,
                            data
                        ) = tcp_segment(data)

                    except struct.error:
                        continue

                    print(TAB_1 + "TCP Segment:")
                    print(
                        TAB_2 +
                        f"Source Port: {src_port}, "
                        f"Destination Port: {dest_port}"
                    )

                    print(
                        TAB_2 +
                        f"Sequence: {sequence}, "
                        f"Acknowledgement: {acknowledgement}"
                    )

                    print(TAB_2 + "Flags:")
                    print(
                        TAB_3 +
                        f"URG: {flag_urg}, "
                        f"ACK: {flag_ack}, "
                        f"PSH: {flag_psh}, "
                        f"RST: {flag_rst}, "
                        f"SYN: {flag_syn}, "
                        f"FIN: {flag_fin}"
                    )

                    print(TAB_2 + "Data:")
                    print(format_multi_line(DATA_TAB_3, data))

                # UDP
                elif proto == 17:

                    if len(data) < 8:
                        continue

                    try:
                        (
                            src_port,
                            dest_port,
                            length,
                            checksum,
                            data
                        ) = udp_segment(data)

                    except struct.error:
                        continue

                    print(TAB_1 + "UDP Segment:")
                    print(
                        TAB_2 +
                        f"Source Port: {src_port}, "
                        f"Destination Port: {dest_port}, "
                        f"Length: {length}"
                    )

                    print(
                        TAB_2 +
                        f"Checksum: {checksum}"
                    )

                    print(TAB_2 + "Data:")
                    print(format_multi_line(DATA_TAB_3, data))

                # Other IPv4 protocols
                else:
                    print(TAB_1 + f"Other IPv4 Protocol: {proto}")
                    print(TAB_2 + "Data:")
                    print(format_multi_line(DATA_TAB_2, data))

            # Non-IPv4 Ethernet traffic
            else:
                print(TAB_1 + "Non-IPv4 Data:")
                print(format_multi_line(DATA_TAB_1, data))

    except PermissionError:
        print("\n[!] Permission denied.")
        print("[!] Raw sockets require root privileges.")
        print("[!] Run the program with:")
        print("    sudo python3 packet_sniffer.py")

    except KeyboardInterrupt:
        print("\n\n[*] Packet sniffer stopped.")
        print("[*] Goodbye!")

    except OSError as error:
        print(f"\n[!] Socket error: {error}")

    finally:
        try:
            conn.close()
        except:
            pass


# --------------------------------------------------
# Ethernet Frame
# --------------------------------------------------

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack(
        '!6s6sH',
        data[:14]
    )

    return (
        get_mac_addr(dest_mac),
        get_mac_addr(src_mac),
        socket.ntohs(proto),
        data[14:]
    )


# --------------------------------------------------
# MAC Address
# --------------------------------------------------

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# --------------------------------------------------
# IPv4 Packet
# --------------------------------------------------

def ipv4_packet(data):

    version_header_length = data[0]

    version = version_header_length >> 4

    header_length = (version_header_length & 15) * 4

    if len(data) < header_length:
        raise struct.error("Invalid IPv4 header")

    ttl, proto, src, target = struct.unpack(
        '!8xBB2x4s4s',
        data[:20]
    )

    return (
        version,
        header_length,
        ttl,
        proto,
        ipv4(src),
        ipv4(target),
        data[header_length:]
    )


# --------------------------------------------------
# IPv4 Address
# --------------------------------------------------

def ipv4(addr):
    return '.'.join(map(str, addr))


# --------------------------------------------------
# ICMP Packet
# --------------------------------------------------

def icmp_packet(data):

    icmp_type, code, checksum = struct.unpack(
        '!BBH',
        data[:4]
    )

    return (
        icmp_type,
        code,
        checksum,
        data[4:]
    )


# --------------------------------------------------
# TCP Segment
# --------------------------------------------------

def tcp_segment(data):

    (
        src_port,
        dest_port,
        sequence,
        acknowledgement,
        offset_reserved_flags
    ) = struct.unpack(
        '!HHLLH',
        data[:14]
    )

    offset = (offset_reserved_flags >> 12) * 4

    if offset < 20 or len(data) < offset:
        raise struct.error("Invalid TCP header")

    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return (
        src_port,
        dest_port,
        sequence,
        acknowledgement,
        flag_urg,
        flag_ack,
        flag_psh,
        flag_rst,
        flag_syn,
        flag_fin,
        data[offset:]
    )


# --------------------------------------------------
# UDP Segment
# --------------------------------------------------

def udp_segment(data):

    (
        src_port,
        dest_port,
        length,
        checksum
    ) = struct.unpack(
        '!HHHH',
        data[:8]
    )

    return (
        src_port,
        dest_port,
        length,
        checksum,
        data[8:]
    )


# --------------------------------------------------
# Format Data
# --------------------------------------------------

def format_multi_line(prefix, string, size=80):

    if not string:
        return prefix + "(empty)"

    size -= len(prefix)

    if isinstance(string, bytes):

        string = ''.join(
            r'\x{:02x}'.format(byte)
            for byte in string
        )

        if size % 2:
            size -= 1

    if size <= 0:
        size = 1

    lines = textwrap.wrap(
        string,
        width=size,
        replace_whitespace=False
    )

    return '\n'.join(
        prefix + line
        for line in lines
    )


# --------------------------------------------------
# Program Start
# --------------------------------------------------

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='Simple Linux IPv4 Packet Sniffer'
    )

    parser.add_argument(
        '-i',
        '--interface',
        help='Network interface, e.g. eth0 or wlan0',
        default=None
    )

    args = parser.parse_args()

    main(args.interface)
```
