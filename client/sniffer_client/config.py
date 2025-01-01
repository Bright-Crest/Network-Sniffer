import logging

from msg import msg

SERVER_IP = "127.0.0.1"
SERVER_PORT = 8000
SERVER_URL = f"http://{SERVER_IP}:{SERVER_PORT}/" if SERVER_PORT else f"http://{SERVER_IP}/"

SSE_SUFFIX = "sniffer/events/"
SSE_CHANNELS = ["switch"]

URLS = {
    msg.MsgType.NET_CARDS: SERVER_URL + "sniffer/net_cards/",
    msg.MsgType.SNIFF_CONFIG: SERVER_URL + "sniffer/sniff_config/",
    msg.MsgType.PACKET: SERVER_URL + "sniffer/packet/",
}

IS_POST_DICT = {
    msg.MsgType.NET_CARDS: False,
    msg.MsgType.SNIFF_CONFIG: False,
    msg.MsgType.PACKET: False,
}

LOG_LEVEL = logging.DEBUG
logging.basicConfig(level=LOG_LEVEL, format = '%(asctime)s %(name)s: [%(levelname)s] %(message)s')
