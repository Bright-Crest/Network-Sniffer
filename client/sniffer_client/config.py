import logging

from msg import msg

# server info

SERVER_IP = "127.0.0.1"
SERVER_PORT = 8000
SERVER_URL = f"http://{SERVER_IP}:{SERVER_PORT}/" if SERVER_PORT else f"http://{SERVER_IP}/"

SSE_SUFFIX = "sniffer/events/"
SSE_CHANNELS = ["switch"]

URLS = {
    msg.MsgType.NET_CARDS: SERVER_URL + "sniffer/net_cards/",
    msg.MsgType.SNIFF_CONFIG: SERVER_URL + "sniffer/sniff_config/",
    msg.MsgType.PACKET: SERVER_URL + "sniffer/packet/",
    msg.MsgType.SESSION_ERROR: SERVER_URL + "sniffer/session_error/",
    msg.MsgType.SNIFF_CONFIG_FEEDBACK: SERVER_URL + "sniffer/sniff_config_feedback/",
}

IS_POST_DICT = {
    msg.MsgType.NET_CARDS: False,
    msg.MsgType.SNIFF_CONFIG: False,
    msg.MsgType.PACKET: False,
    msg.MsgType.SESSION_ERROR: False,
    msg.MsgType.SNIFF_CONFIG_FEEDBACK: False,
}


# client info

SSE_RECONNECT_INTERVAL = 3
SEND_NET_CARDS_TIMEOUT = 10
ASK_FOR_SNIFF_CONFIG_TIMEOUT = 60


LOG_LEVEL = logging.DEBUG
logging.basicConfig(level=LOG_LEVEL, format = '%(asctime)s %(name)s: [%(levelname)s] %(message)s')
