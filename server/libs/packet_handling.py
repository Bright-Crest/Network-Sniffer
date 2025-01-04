from scapy.all import (
    Packet,
    Raw,
    Padding,
    Any,
)
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.tftp import TFTP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.tls.tools import TLSPlaintext
import base64
import pickle
import time
import json


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

    # summary_ = { "time": packet.time }
    # if Raw in packet:
    #     summary_["length"] = len(packet[Raw].load)
    #     if Ether in packet:
    #         summary_["source"] = packet[Ether].src
    #         summary_["destination"] = packet[Ether].dst
    #         summary_["protocol"] = Ether.name
    #         if IP in packet:
    #             summary_["source"] = packet[IP].src
    #             summary_["destination"] = packet[IP].dst
    #             summary_["protocol"] = IP.name
    #             if ICMP in packet:
    #                 summary_["protocol"] = ICMP.name
    #             if TCP in packet:
    #                 summary_["protocol"] = TCP.name
    #                 if HTTP in packet:
    #                     summary_["protocol"] = "HTTP/1.1"
    #                     if HTTPRequest in packet:
    #                         summary_["protocol"] = packet[HTTPRequest].
    #             if UDP in packet:
    #                 summary_["protocol"] = UDP.name
    #                 if TFTP in packet:
    #                     summary_["protocol"] = "TFTP"
    # summary_["info"] = str(packet.summary())
    # return summary_

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
        packet_dict = _packet2dict(layer)
        packet_dict["name"] = layer.name
        if "payload" in packet_dict:
            del packet_dict["payload"]
        if summary:
            packet_dict["summary"] = layer.summary()
        packet_list.append(packet_dict)
    return packet_list


def _packet2dict(packet: Packet):
    # type: (Packet) -> dict
    # only for debug:
    # return json.loads(packet.json())
    # return json.loads(_packet2json(packet))

    binary_layers = {Raw: ["load"], Padding: ["load"]}

    packet_dict = {k: v for (k, v) in packet._command(json=True)}
    if type(packet) in binary_layers.keys():
        for key in binary_layers[type(packet)]:
            packet_dict[key] = _bytes2hex(packet_dict[key])
    else:
        packet_dict = _decode_all_bytes(packet_dict)
    pc = _packet2dict(packet.payload) if packet.payload else None
    if pc:
        packet_dict["payload"] = pc
    return packet_dict


def _packet2json(packet: Packet):
    # type: (Packet) -> str
    """Rewrite `scapy.Packet.json` method to handle json `bytes` key error.

    Erro info: "keys must be str, int, float, bool or None, not bytes".
    This is a workaround for the `bytes` key error. 

    Returns a JSON representing the packet.

    Please note that this cannot be used for bijective usage: data loss WILL occur,
    so it will not make sense to try to rebuild the packet from the output.
    This must only be used for a grepping/displaying purpose.
    """
    dump = json.dumps(_decode_all_bytes({k: v for (k, v) in packet._command(json=True)}))
    pc = _packet2json(packet.payload) if packet.payload else None
    if pc:
        dump = dump[:-1] + ", \"payload\": %s}" % pc
    return dump


def _decode_all_bytes(dict_: dict, is_decode_keys: bool = True, is_decode_values: bool = True, encoding: str = "utf-8"):
    # type: (dict, bool, bool, str) -> dict
    new_dict = dict()
    for k, v in dict_.items():
        k = k.decode() if isinstance(k, bytes) and is_decode_keys else k
        v = v.decode() if isinstance(v, bytes) and is_decode_values else v
        if isinstance(v, dict):
            v = _decode_all_bytes(v, is_decode_keys, is_decode_values, encoding)
        new_dict[k] = v
    return new_dict


def _bytes2hex(b, is_for_display: bool = True, is_for_web_display: bool = True, is_break_at_first: bool = True):
    # type: (bytes|str, bool, bool, bool) -> str
    if isinstance(b, str):
        b = bytes(b, "utf-8")
    if is_for_display:
        hex_str = "" if not is_break_at_first else ("<br>" if is_for_web_display else "\n")
        for i, byte in enumerate(b):
            hex_str += f"{byte:02x}"
            if i % 16 == 15:
                hex_str += "<br>" if is_for_web_display else "\n"
            elif i % 8 == 7:
                hex_str += "&ensp;&ensp;" if is_for_web_display else "  "
            else:
                hex_str += "&ensp;" if is_for_web_display else " "
        return hex_str.strip()
    else:
        return b.hex()


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
