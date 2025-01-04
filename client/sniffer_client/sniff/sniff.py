from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
import threading 
import queue

from utils import utils


class SniffException(Exception):
    pass


class SniffNetCardException(SniffException):
    pass


class SniffFilterException(SniffException):
    pass


class Sniffer():
    '''Sniffer assuring that the packets are not lost. The output is stream of packets.'''

    def __init__(self, net_card="", filter=""):
        self._net_card = net_card
        self._filter = filter
        self._packets_buffer = queue.Queue()
        self._sniff_thread = None
        self._stop = False
        self._config_check()

    def _config_check(self):
        # type: () -> None
        '''Check if the configuration is correct.
        
        Raises:
            SniffNetCardException: If the network card is invalid.
            SniffFilterException: If the filter is invalid.
        '''
        try:
            sniff(iface=self._net_card, filter=self._filter, count=1, store=False)
        except Scapy_Exception as e:
            if "filter" in str(e):
                raise SniffFilterException(f"Invalid filter: {self._filter}")
            else:
                raise Scapy_Exception from e
        except ValueError as e:
            if "interface" in str(e).lower():
                raise SniffNetCardException(f"Invalid network card: {self._net_card}")
            else:
                raise ValueError from e

    def _buffer_packet(self, packet: Packet):
        self._packets_buffer.put(packet)
    
    def _sniff(self, stop_event: threading.Event):
        sniffer = AsyncSniffer(iface=self._net_card, filter=self._filter, prn=self._buffer_packet, stop_filter=lambda _: stop_event.is_set(), store=False)
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
