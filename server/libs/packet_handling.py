from scapy.all import (
    Packet,
    Raw,
    raw,
    Padding,
    Any,
    Callable,
    Optional,
)
from scapy.layers.l2 import Ether, ARP, STP
from scapy.layers.inet import IP, ICMP, TCP, UDP, in4_chksum
from scapy.layers.tftp import TFTP
from scapy.layers.http import HTTP
from scapy.contrib import http2 as h2
from scapy.layers import (
    hsrp,
    sctp,
)
import base64
import pickle
import time
import json
from enum import Enum
import re

from libs.utils import bytes2hex, decode_all_bytes


def export_packet(packet: Any):
    # type: (Any) -> str
    import zlib
    return base64.b64encode(zlib.compress(pickle.dumps(packet, 2), 9)).decode()


def import_packet(packet: str):
    # type: (str) -> Any
    import zlib
    return pickle.loads(zlib.decompress(base64.b64decode(packet.strip())))


def dict_summary(packet: Packet):
    # type: (Packet) -> dict
    '''
    Return a dictionary with the following keys:
    - time
    - source
    - destination
    - protocol
    - length
    - info
    '''
    max_info_length = 80
    not_protocols = [Raw, Padding]

    summary_ = { 
        "time": time.strftime("%X", time.localtime(packet.time)),
        "length": len(packet),
    }

    if Ether in packet:
        summary_["source"] = packet[Ether].src
        summary_["destination"] = packet[Ether].dst
        if IP in packet:
            summary_["source"] = packet[IP].src
            summary_["destination"] = packet[IP].dst
    
    for layer_class in packet.layers()[::-1]:
        if layer_class not in not_protocols:
            # TODO: like http/1.1 and http/2
            summary_["protocol"] = layer_class().name
            break

    info = packet.summary()
    summary_["info"] = info if len(info) <= max_info_length else info[:max_info_length - 2] + "..."
    return summary_


def packet_css_class(packet: Packet):
    # type: (Packet) -> str
    '''Return the CSS class of the packet for user-client side displaying filtering
    
    Currently support src, dst, sport, dport, layers
    '''
    css_class = ""
    if Ether in packet:
        css_class += "src-" + packet[Ether].src.replace(':', '-') + " "
        css_class += "dst-" + packet[Ether].dst.replace(':', '-') + " "
        if IP in packet:
            # css_class += "src-" + "".join([format(i, ">03") for i in packet[IP].src.split('.')]) + " "
            # css_class += "dst-" + "".join([format(i, ">03") for i in packet[IP].dst.split('.')]) + " "
            css_class += "src-" + packet[IP].src.replace('.', '-') + " "
            css_class += "dst-" + packet[IP].dst.replace('.', '-') + " "
            if TCP in packet or UDP in packet:
                css_class += "sport-" + str(packet[IP].sport) + " "
                css_class += "dport-" + str(packet[IP].dport) + " "

    for layer_class in packet.layers():
        css_class += "layer-" + re.sub(r"[^a-z0-9-_]+", "", layer_class().name.lower()) + " "
    return css_class


def split_layers(packet: Packet):
    # type: (Packet) -> list[Packet]
    p = packet.copy()
    layers = []
    for layer_class in p.layers()[::-1]:
        p[layer_class].remove_payload()
        layers.append(p[layer_class])
    return layers[::-1]


def packet2list(packet: Packet, summary: bool = True):
    # type: (Packet, bool) -> list[dict]
    packet_list = []
    for layer in split_layers(packet):
        packet_dict = packet2dict(layer)
        packet_dict["name"] = layer.name
        if "payload" in packet_dict:
            del packet_dict["payload"]
        if summary:
            packet_dict["summary"] = layer.summary()
        packet_list.append(packet_dict)
    return packet_list


def packet2dict(packet: Packet):
    # type: (Packet) -> dict
    binary_layers = {Raw: ["load"], Padding: ["load"]}

    packet_dict = {k: v for (k, v) in packet._command(json=True)}
    if type(packet) in binary_layers.keys():
        for key in binary_layers[type(packet)]:
            packet_dict[key] = bytes2hex(packet_dict[key])
    else:
        packet_dict = decode_all_bytes(packet_dict)
    pc = packet2dict(packet.payload) if packet.payload else None
    if pc:
        packet_dict["payload"] = pc
    return packet_dict


def packet2json(packet: Packet):
    # type: (Packet) -> str
    """Rewrite `scapy.Packet.json` method to handle json `bytes` key error.

    Erro info: "keys must be str, int, float, bool or None, not bytes".
    This is a workaround for the `bytes` key error. 

    Returns a JSON representing the packet.

    Please note that this cannot be used for bijective usage: data loss WILL occur,
    so it will not make sense to try to rebuild the packet from the output.
    This must only be used for a grepping/displaying purpose.
    """
    dump = json.dumps(decode_all_bytes({k: v for (k, v) in packet._command(json=True)}))
    pc = packet2json(packet.payload) if packet.payload else None
    if pc:
        dump = dump[:-1] + ", \"payload\": %s}" % pc
    return dump


########## Color Related ##########

class Color(Enum):
    Blue = "blue"
    Grey = "grey"
    Green = "green"
    Red = "red"
    Yellow = "yellow"
    BrilliantBlue = "brilliant_blue"
    Light = "light"
    Dark = "dark"
    NONE = "none"
    
# COLOR_CSS_CLASSES = { Color.Blue: "text-bg-primary", Color.Grey: "text-bg-secondary", Color.Green: "text-bg-success", 
#                      Color.Red: "text-bg-danger", Color.Yellow: "text-bg-warning", Color.BrilliantBlue: "text-bg-info", 
#                      Color.Light: "text-bg-light", Color.Dark: "text-bg-dark", Color.NONE: "" }
COLOR_CSS_CLASSES = { Color.Blue: "text-primary", Color.Grey: "text-secondary", Color.Green: "text-success", 
                     Color.Red: "text-danger", Color.Yellow: "text-warning", Color.BrilliantBlue: "text-info", 
                     Color.Light: "text-light", Color.Dark: "text-dark", Color.NONE: "" }


def color2css_class(color: Color):
    # type: (Color) -> str
    return COLOR_CSS_CLASSES.get(color, "")
    

########## Color Rule Callbacks ##########

# def bad_tcp(packet: Packet):
#     # type: (Packet) -> bool
#     return TCP in packet and packet[TCP].flags and ...

def hsrp_state_change(packet: Packet):
    # type: (Packet) -> bool
    return hsrp.HSRP in packet and packet[hsrp.HSRP].state != 8 and packet[hsrp.HSRP].state != 16 

def stp_change(packet: Packet):
    # type: (Packet) -> bool
    return STP in packet and packet[STP].bpdutype == 0x80

def icmp_errors(packet: Packet):
    # type: (Packet) -> bool
    return ICMP in packet and (packet[ICMP].type in [3, 4, 5, 11])

def arp(packet: Packet):
    # type: (Packet) -> bool
    return ARP in packet

def icmp(packet: Packet):
    # type: (Packet) -> bool
    return ICMP in packet

def tcp_rst(packet: Packet):
    # type: (Packet) -> bool
    return TCP in packet and packet[TCP].flags.R 

def sctp_abort(packet: Packet):
    # type: (Packet) -> bool
    return sctp.SCTPChunkAbort in packet

# def ipv4_ttl_low_or_unexpected(packet: Packet):
#     # type: (Packet) -> bool
#     return IP in packet and (packet[IP].dst != "224.0.0.0" and packet[IP].ttl < 5 and not(...))

def checksum_errors(packet: Packet):
    # type: (Packet) -> bool
    '''only implemented for IPv4 and its upper layer like TCP, UDP and so on'''
    return (IP in packet and in4_chksum(packet[IP].proto, packet[IP], raw(packet[IP].payload)) != 0)

def http(packet: Packet):
    # type: (Packet) -> bool
    return HTTP in packet or (TCP in packet and packet[TCP].dport == 80) or h2.H2Frame in packet

def tcp_syn_fin(packet: Packet):
    # type: (Packet) -> bool
    return TCP in packet and (packet[TCP].flags.S or packet[TCP].flags.F)

def tcp(packet: Packet):
    # type: (Packet) -> bool
    return TCP in packet

def udp(packet: Packet):
    # type: (Packet) -> bool
    return UDP in packet

def broadcast(packet: Packet):
    # type: (Packet) -> bool
    return Ether in packet and packet[Ether].dst == "ff:ff:ff:ff:ff:ff"


########## Color Rule Registering ##########

class ColorRule:
    def __init__(self, condition, color: Color, name=None):
        # type: (Callable[[Packet], bool], Color, Optional[str]) -> None
        self._condition = condition
        self._color = color
        self._name = name if name else "Color Rule: " + condition.__name__ + "::" + color.name.lower()
    
    def __str__(self):
        return self._name
    
    def __call__(self, packet: Packet):
        # type: (Packet, bool) -> Color
        color = self._color if self._condition(packet) else Color.NONE
        return color
    
    def help_info(self, is_css_class: bool = True):
        return (self._name, color2css_class(self._color) if is_css_class else self._color)

'''has priority. The first rule that matches the packet will be applied. 
`Color.NONE` will be ignored.'''
COLOR_RULES = [
    ColorRule(hsrp_state_change, Color.Dark),
    ColorRule(stp_change, Color.Dark),
    ColorRule(icmp_errors, Color.Dark),
    ColorRule(arp, Color.Grey),
    ColorRule(icmp, Color.Light),
    ColorRule(tcp_rst, Color.Yellow),
    ColorRule(sctp_abort, Color.Yellow),
    ColorRule(checksum_errors, Color.Red),
    ColorRule(http, Color.Green),
    ColorRule(tcp_syn_fin, Color.Grey),
    ColorRule(tcp, Color.BrilliantBlue),
    ColorRule(udp, Color.Blue),
    ColorRule(broadcast, Color.Grey)
]


def packet_color(packet: Packet, is_css_class: bool = True):
    # type: (Packet, Optional[bool]) -> str
    '''Return the color of the packet'''
    color = Color.NONE
    for rule in COLOR_RULES:
        color = rule(packet)
        if color != Color.NONE:
            # only print for debug
            # print(f"Packet {packet.summary()} matched rule {rule}")
            break
    return color2css_class(color) if is_css_class else color


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
