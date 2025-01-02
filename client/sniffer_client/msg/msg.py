import requests
from enum import Enum
import logging

Logger = logging.getLogger(__name__)


class MsgType(Enum):
    # client to server
    NET_CARDS = "net_cards"
    SNIFF_CONFIG = "sniff_config"
    PACKET = "packet"
    SESSION_ERROR = "session_error" # e.g. sniffing session not found or session cannot be restarted


def send_msg(msg_type: MsgType, msg, url, is_post, timeout=None):
    data = {'type': msg_type.value, 'data': msg}
    response = None
    if is_post:
        response = requests.post(url, data=data, timeout=timeout)
        Logger.debug(f"request data: {data}")
    else:
        response = requests.get(url, params=data, timeout=timeout)
    Logger.debug(f"response: {response}")
    return response


def handle_response(response: requests.Response):
    if response.status_code == 200:
        ...
