from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
import threading 
import queue

from utils import utils


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


def export_packet(packet):
    # type: (Any) -> str
    import zlib
    return base64.b64encode(zlib.compress(pickle.dumps(packet, 2), 9)).decode()


def import_packet(packet):
    # type: (str) -> Any
    import zlib
    return pickle.loads(zlib.decompress(base64.b64decode(packet.strip())))


def get_net_cards():
    return _ifaces2dict(ifaces)


def _ifaces2dict(interfaces: NetworkInterfaceDict):
    ret = dict()
    for iface_name in sorted(interfaces.data):
        dev = interfaces.data[iface_name]
        if not dev.is_valid():
            continue
        prov = dev.provider
        mac = dev.mac
        if conf.manufdb and mac:
            mac = conf.manufdb._resolve_MAC(mac)

        # headers: ("Index", "Name", "MAC", "IPv4", "IPv6")
        ret[dev.index] = {
            "Index": str(dev.index),
            "Name": dev.description,
            "MAC": mac or "",
            "IPv4": dev.ips[4],
            "IPv6": dev.ips[6],
        }
    return ret


# def handle_packet(packet: Packet):
#     import string
#     # Handling each packet and extract information from each layer
#     packet_data = ""
#     # Ether Layer : D L
#     if packet.haslayer(Ether):
#         packet_data += f"MAC Source: {packet[Ether].src}\n"
#         packet_data += f"MAC Destination: {packet[Ether].dst}\n"
#         packet_data += f"Ethernet Type: 0x{packet[Ether].type:04x}\n"

#     # IP Layer : N
#     if packet.haslayer(IP):
#         packet_data += "\nIP - Layer\n"
#         packet_data += f"IP Version: {packet[IP].version}\n"
#         packet_data += f"Source IP: {packet[IP].src}\n"
#         packet_data += f"Destination IP: {packet[IP].dst}\n"

#         if packet.haslayer(TCP):
#             packet_data += "\nTCP - Layer\n"
#             packet_data += f"Source Port: {packet[TCP].sport}\n"
#             packet_data += f"Destination Port: {packet[TCP].dport}\n"
#             packet_data += f"Flags: {packet[TCP].flags}\n"

#         if packet.haslayer(UDP):
#             packet_data += "\nUDP - Layer\n"
#             packet_data += f"Source Port: {packet[UDP].sport}\n"
#             packet_data += f"Destination Port: {packet[UDP].dport}\n"
#             packet_data += f"Length: {packet[UDP].len}\n"

#             # ICMP Analysis
#         elif packet.haslayer(ICMP):
#             icmp = packet[ICMP]
#             packet_data += "\nICMP - Layer\n"
#             packet_data += f"Type: {icmp.type}\n"
#             packet_data += f"Code: {icmp.code}\n"

#     if packet.haslayer(Raw):
#         data = ""
#         for b in bytes(packet[Raw]):
#             if chr(b) in string.printable:
#                 data += chr(b)
#             else:
#                 data += "."
#         packet_data += data
#     print("-" * 50)
#     print(packet_data)
#     print("-" * 50)
