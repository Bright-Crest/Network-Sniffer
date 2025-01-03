import threading
import queue
import time
import json
import requests
import logging

import config
from sniff import sniff
from msg import msg, sse
from utils import utils

Logger = logging.getLogger(__name__)


class SessionError(Exception):
    def __init__(self, session_id, *args):
        super().__init__(*args)
        self.session_id = session_id


class MultiSniffingSendingSessions():
    '''Multi sniffing sending sessions.'''

    def __init__(self):
        self._daemon = True

        def _ask_for_sniff_config(session_id, sniff_config_queue: queue.Queue, stop_event: threading.Event):
            sniff_config = ask_for_sniff_config(session_id, stop_event, daemon=self._daemon)
            # one for _start_sniffing_sending_session, one for self._sniff_configs
            sniff_config_queue.put(sniff_config)
            sniff_config_queue.put(sniff_config)
            Logger.debug(f"Got sniff config {sniff_config} for session {session_id}")
        
        def _start_sniffing_sending_session(session_id, sniff_config_queue: queue.Queue, stop_event: threading.Event):
            sniff_config = sniff_config_queue.get()
            Logger.debug(f"Start sniffing sending session {session_id} with sniff config {sniff_config}")
            start_sniffing_sending_session(session_id, sniff_config, stop_event, daemon=self._daemon)

        self._ask_for_sniff_config_threads = utils.MultiStoppableThreads(_ask_for_sniff_config, daemon=self._daemon)
        self._sniffing_sending_sessions = utils.MultiStoppableThreads(_start_sniffing_sending_session, daemon=self._daemon)
        self._sniff_config_queues = dict()
        self._sniff_configs = dict()
    
    def start(self, id):
        if id in self._sniff_config_queues:
            self.stop(id)
        self._sniff_config_queues[id] = queue.Queue()
        # simply take id as session_id
        self._ask_for_sniff_config_threads.start(id, args=(id, self._sniff_config_queues[id],))
        self._sniffing_sending_sessions.start(id, args=(id, self._sniff_config_queues[id],))
    
    def stop(self, id):
        self._ask_for_sniff_config_threads.stop(id)
        self._sniffing_sending_sessions.stop(id)
    
    def restart(self, id):
        '''restart with the same sniffing config'''
        if id not in self._sniff_config_queues:
            raise SessionError(id, f"Session {id} cannot be restarted because it has never been started")

        self.stop(id)
        if id not in self._sniff_configs:
            self._sniff_configs[id] = self._sniff_config_queues[id].get_nowait()
        self._sniff_config_queues[id].put(self._sniff_configs[id])
        self._sniffing_sending_sessions.start(id, args=(id, self._sniff_config_queues[id],))


def send_net_cards(daemon=False):
    '''Send net cards to server.'''
    net_cards_timeout = None if daemon else config.SEND_NET_CARDS_TIMEOUT
    net_cards = sniff.get_net_cards()
    net_cards_response = msg.send_msg(msg.MsgType.NET_CARDS, json.dumps(net_cards), config.URLS[msg.MsgType.NET_CARDS], 
                                      config.IS_POST_DICT[msg.MsgType.NET_CARDS], timeout=net_cards_timeout)
    if net_cards_response.status_code != 200:
        raise Exception(f"Failed to send net cards: {net_cards_response.text}")
    else:
        Logger.info(f"Sent net cards: {net_cards}")


def ask_for_sniff_config(session_id, stop_event: threading.Event, daemon=False):
    sniff_config_timeout = None if daemon else config.ASK_FOR_SNIFF_CONFIG_TIMEOUT
    # async: ask for sniff config
    request_session = requests.Session()
    while True:
        if not stop_event.is_set():
            sniff_config_response = msg.send_msg(msg.MsgType.SNIFF_CONFIG, json.dumps({"session_id": session_id}), config.URLS[msg.MsgType.SNIFF_CONFIG], 
                                                 config.IS_POST_DICT[msg.MsgType.SNIFF_CONFIG], sniff_config_timeout, request_session)
            if sniff_config_response.status_code == 200:
                if sniff_config_response.text != "":
                    sniff_config = sniff_config_response.json()
                    Logger.debug(f"Sniff config: {sniff_config}")
                    return sniff_config
        else:
            return dict()


def sniffing(session_id, msg_buffer: queue.Queue, sniff_config: dict, stop_event: threading.Event):
    '''continuously sniff packets and put them into the msg_buffer until stop_event is set.'''
    # sniff packets and put them into the msg_buffer
    sniffer = sniff.Sniffer(sniff_config["net_card"], sniff_config["filter"])
    for packet in sniffer.get_packets():
        packet_msg = json.dumps({
            "session_id": session_id,
            "packet": sniff.export_packet(packet),
        })
        msg_buffer.put(packet_msg)
        Logger.debug(f"packet summay: {packet.summary()}")
        if stop_event.is_set():
            sniffer.stop()
            return


def buffered_msg_sending(msg_buffer: queue.Queue, stop_event: threading.Event):
    '''Get packet from msg_buffer and send it to server.'''
    request_session = requests.Session()
    while not stop_event.is_set():
        packet_msg = msg_buffer.get()
        msg.send_msg(msg.MsgType.PACKET, packet_msg, config.URLS[msg.MsgType.PACKET], 
                     config.IS_POST_DICT[msg.MsgType.PACKET], session=request_session)


def start_sniffing_sending_session(session_id, sniff_config: dict, stop_event: threading.Event, daemon=False):
    '''Start a sniffing and sending session.'''
    if sniff_config == dict():
        return
    
    msg_buffer = queue.Queue()
    sniffing_thread = utils.StoppableThread(target=sniffing, daemon=daemon, args=(session_id, msg_buffer, sniff_config,))
    buffered_msg_sending_thread = utils.StoppableThread(target=buffered_msg_sending, daemon=daemon, args=(msg_buffer,))
    buffered_msg_sending_thread.start()
    sniffing_thread.start()

    while True:
        if stop_event.is_set():
            sniffing_thread.stop()
            buffered_msg_sending_thread.stop()
            return


# TODO server multi channels
def sse_client(callbacks: dict, daemon=False):
    '''Setup a sse client.'''
    sse_url = sse.sse_url(config.SERVER_URL, config.SSE_SUFFIX)
    while True:
        try:
            Logger.debug("SSE connecting")
            client = sse.connect(sse_url)
            Logger.debug("SSE connected; next: send net cards info and wait for events")

            send_net_cards(daemon)

            # handle received events 
            for event in client.events():
                Logger.debug(f"Received event: {event.data}")
                session_id, sse_type = sse.parse_event(event, config.SSE_CHANNELS[0])
                if sse_type in callbacks:
                    try:
                        callbacks[sse_type](session_id)
                    except SessionError as e:
                        Logger.error(f"{e}")
                        msg.send_msg(msg.MsgType.SESSION_ERROR, json.dumps({"session_id": session_id}), config.URLS[msg.MsgType.SESSION_ERROR],
                                     config.IS_POST_DICT[msg.MsgType.SESSION_ERROR], timeout=10)
                else:
                    raise TypeError(f"Unknown SSE type: {sse_type}")
        except TypeError as e:
            Logger.error(f"{e}")
        except Exception as e:
            Logger.error(f"{e}")
        finally:
            time.sleep(config.SSE_RECONNECT_INTERVAL)


def main():
    sessions = MultiSniffingSendingSessions()
    callbacks = {
        sse.SSEType.START: sessions.start,
        sse.SSEType.STOP: sessions.stop,
        sse.SSEType.RESTART: sessions.restart,
    }
    sse_client(callbacks)
    

if __name__ == "__main__":
    main()
