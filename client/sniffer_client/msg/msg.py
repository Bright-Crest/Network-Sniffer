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


def send_msg(msg_type: MsgType, msg, url, is_post, timeout=None, session: requests.Session=None):
    '''Send message to server.

    use session to imporve performance.
    
    Args:
        msg_type (MsgType): message type
        msg (dict): message data
        url (str): server url
        is_post (bool): whether to use post method
        timeout (int, optional): request timeout. Defaults to None.
        session (requests.Session, optional): requests session
    Returns:
        requests.Response: server response
    '''
    if session is None:
        session = requests.Session()

    data = {'type': msg_type.value, 'data': msg}
    response = None
    if is_post:
        response = session.post(url, data=data, timeout=timeout)
        Logger.debug(f"request data: {data}")
    else:
        response = session.get(url, params=data, timeout=timeout)
    Logger.debug(f"response: {response}")
    return response
