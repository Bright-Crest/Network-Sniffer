from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
import threading 
import queue

import utils


class Sniffer():
    '''Sniffer assuring that the packets are not lost. The output is stream of packets.'''

    def __init__(self, net_card="", filter=""):
        self._net_card = net_card
        self._filter = filter
        self._packets_buffer = queue.Queue()
        self._sniff_thread = None
        self._stop = False

    def _buffer_packet(self, packet: Packet):
        self._packets_buffer.put(packet)
    
    def _sniff(self, stop_event: threading.Event):
        sniffer = AsyncSniffer(iface=self._net_card, filter=self._filter, prn=self._buffer_packet, stop_filter=lambda _: stop_event.is_set())
        sniffer.start()

    def get_packets(self):
        self._sniff_thread = utils.StoppableThread(target=self._sniff, daemon=True)
        self._sniff_thread.start()
        while True:
            try:
                yield self._packets_buffer.get_nowait()
            except queue.Empty:
                pass
            finally:
                if self._stop:
                    break
    
    def stop(self):
        self._stop = True
        self._sniff_thread.stop()


def get_net_cards():
    # return NetworkInterfaceDict()
    return ifaces


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


# if __name__ == "__main__":
#     import sys
#     filter = ""
#     if len(sys.argv) == 2:
#         filter = sys.argv[1]
#     elif len(sys.argv) > 2:
#         print("Usage: python3 sniff.py [filter]")
#         exit(0)
#     try:
#         print(ifaces)
#         iface = ""
#         packets = sniff(iface=iface, prn=handle_packet, filter=filter, count=10)
#     except Scapy_Exception:
#         print("Bad filter. Program terminated")
#     print(packets)