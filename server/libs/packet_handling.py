from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether


def export_packet(packet):
    # type: (Any) -> str
    import zlib
    return base64.b64encode(zlib.compress(pickle.dumps(packet, 2), 9)).decode()


def import_packet(packet):
    # type: (str) -> Any
    import zlib
    return pickle.loads(zlib.decompress(base64.b64decode(packet.strip())))


def handle_packet(packet: Packet):
    import string
    # Handling each packet and extract information from each layer
    packet_data = ""
    # Ether Layer : D L
    if packet.haslayer(Ether):
        packet_data += f"MAC Source: {packet[Ether].src}\n"
        packet_data += f"MAC Destination: {packet[Ether].dst}\n"
        packet_data += f"Ethernet Type: 0x{packet[Ether].type:04x}\n"

    # IP Layer : N
    if packet.haslayer(IP):
        packet_data += "\nIP - Layer\n"
        packet_data += f"IP Version: {packet[IP].version}\n"
        packet_data += f"Source IP: {packet[IP].src}\n"
        packet_data += f"Destination IP: {packet[IP].dst}\n"

        if packet.haslayer(TCP):
            packet_data += "\nTCP - Layer\n"
            packet_data += f"Source Port: {packet[TCP].sport}\n"
            packet_data += f"Destination Port: {packet[TCP].dport}\n"
            packet_data += f"Flags: {packet[TCP].flags}\n"

        if packet.haslayer(UDP):
            packet_data += "\nUDP - Layer\n"
            packet_data += f"Source Port: {packet[UDP].sport}\n"
            packet_data += f"Destination Port: {packet[UDP].dport}\n"
            packet_data += f"Length: {packet[UDP].len}\n"

            # ICMP Analysis
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            packet_data += "\nICMP - Layer\n"
            packet_data += f"Type: {icmp.type}\n"
            packet_data += f"Code: {icmp.code}\n"

    if packet.haslayer(Raw):
        data = ""
        for b in bytes(packet[Raw]):
            if chr(b) in string.printable:
                data += chr(b)
            else:
                data += "."
        packet_data += data
    print("-" * 50)
    print(packet_data)
    print("-" * 50)
