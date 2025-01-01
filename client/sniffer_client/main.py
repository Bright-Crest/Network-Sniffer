import threading
import queue
import time
import json
import logging

import config
from sniff import sniff
from msg import msg, sse
import utils

Logger = logging.getLogger(__name__)


def sniffing(msg_buffer: queue.Queue, stop_event: threading.Event, daemon=False):
    '''First send net_cards and then ask for sniff config and continuously
    sniff packets and put them into the msg_buffer until stop_event is set.'''

    net_cards_timeout = None if daemon else 60
    sniff_config_timeout = None if daemon else 60

    # send net cards
    net_cards = str(sniff.get_net_cards())
    net_cards_response = msg.send_msg(msg.MsgType.NET_CARDS, net_cards, config.URLS[msg.MsgType.NET_CARDS], 
                                      config.IS_POST_DICT[msg.MsgType.NET_CARDS], timeout=net_cards_timeout)
    if net_cards_response.status_code != 200:
        Logger.error(f"Failed to send net cards: {net_cards_response.text}")
        return
    
    # async: ask for sniff config
    sniff_config = dict()
    while True:
        if not stop_event.is_set():
            sniff_config_response = msg.send_msg(msg.MsgType.SNIFF_CONFIG, "", config.URLS[msg.MsgType.SNIFF_CONFIG], 
                                                    config.IS_POST_DICT[msg.MsgType.SNIFF_CONFIG], timeout=sniff_config_timeout)
            if sniff_config_response.status_code == 200:
                if sniff_config_response.text != "":
                    sniff_config = json.loads(sniff_config_response.text)
                    Logger.debug(f"Sniff config: {sniff_config}")
                    break
        else:
            return
    
    # sniff packets and put them into the msg_buffer
    sniffer = sniff.Sniffer(sniff_config["net_card"], sniff_config["filter"])
    for packet in sniffer.get_packets():
        # TODO packet jsonify
        msg_buffer.put(str(packet))
        Logger.debug(f"packet summary: {packet.summary()}")
        if stop_event.is_set():
            sniffer.stop()
            return


def buffered_msg_sending(msg_buffer: queue.Queue, stop_event: threading.Event):
    '''Get packet from msg_buffer and send it to server.'''
    while not stop_event.is_set():
        packet = msg_buffer.get()
        msg.send_msg(msg.MsgType.PACKET, packet, config.URLS[msg.MsgType.PACKET], 
                        config.IS_POST_DICT[msg.MsgType.PACKET])


# TODO packet group id?
def start_sniffing_sending_session(stop_event: threading.Event):
    '''Start a sniffing and sending session.'''
    sniffing_daemon = True

    msg_buffer = queue.Queue()
    sniffing_thread = utils.StoppableThread(target=sniffing, daemon=sniffing_daemon, args=(msg_buffer,), kwargs={"daemon": sniffing_daemon})
    buffered_msg_sending_thread = utils.StoppableThread(target=buffered_msg_sending, args=(msg_buffer,))
    buffered_msg_sending_thread.start()
    sniffing_thread.start()

    while True:
        if stop_event.is_set():
            sniffing_thread.stop()
            buffered_msg_sending_thread.stop()
            return


# TODO server multi channels
def sse_client(callbacks: dict):
    '''Setup a sse client.'''
    cnt = 0
    sse_url = sse.sse_url(config.SERVER_URL, config.SSE_SUFFIX)
    while True:
        try:
            Logger.debug("SSE connecting")
            client = sse.connect(sse_url)
            Logger.debug("SSE connected; next: wait for events")
            # handle received events 
            prev_event_type = None
            for event in client.events():
                sse_type = sse.parse_event(event, config.SSE_CHANNELS[0])
                if prev_event_type and sse_type == prev_event_type:
                    if sse_type == sse.SSEType.START:
                        callbacks[sse.SSEType.STOP](cnt)
                        cnt += 1
                        callbacks[sse.SSEType.START](cnt)
                elif sse_type == sse.SSEType.START or sse_type == sse.SSEType.STOP:
                    callbacks[sse_type](cnt)
                    cnt += 1
                else:
                    raise TypeError(f"Unknown SSE type: {sse_type}")
                prev_event_type = sse_type
        except TypeError as e:
            Logger.error(f"{e}")
        except Exception as e:
            Logger.error(f"{e}")


def main():
    multi_sessions = utils.MultiStoppableThreads(start_sniffing_sending_session, daemon=True)
    callbacks = {
        sse.SSEType.START: multi_sessions.start,
        sse.SSEType.STOP: multi_sessions.stop,
    }
    sse_client(callbacks)
    

if __name__ == "__main__":
    main()
