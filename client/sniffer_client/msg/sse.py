'''
SSE: Server-Sent Events

Handle server-sent events, namely EventSource in Web with
`Content-Type: text/event-stream`.
'''

from sseclient import SSEClient, Event
from enum import Enum
import json
import pprint
import logging

Logger = logging.getLogger(__name__)


class SSEClientWrapper(SSEClient):
    """Wrapper of `sseclient.SSEClient`
    
    Fix a bug of `sseclient.SSEClient`: when no new event is received, client
    crashes. This wrapper only yields non-empty events. If no new event is received,
    it blocks until new event arrives.
    """
    def __init__(self, event_source, char_enc='utf-8'):
        super().__init__(event_source, char_enc)
        # self._events_buffer = [] # FIFO
    
    @staticmethod
    def _is_event_empty(event: Event):
        return not event.id and not event.data

    def events(self):
        for event in super().events():
            if not SSEClientWrapper._is_event_empty(event): 
                yield event
                

class SSEType(Enum):
    ERROR = 'error'
    START = 'start'
    STOP = 'stop'


def sse_url(server_url, sse_suffix):
    return f"{server_url}{sse_suffix}"


def connect(url):
    headers = {'Accept': 'text/event-stream'}
    response = with_requests(url, headers)
    client = SSEClientWrapper(response)
    return client


def parse_event(event: Event, channel):
    if event.event == 'message' and event.id.rsplit(':', 1)[0] == channel:
        sse_type = event.data.strip("'").strip('"')
        if sse_type == SSEType.START.value:
            return SSEType.START
        elif sse_type == SSEType.STOP.value:
            return SSEType.STOP
        else:
            return SSEType.ERROR
    else:
        return SSEType.ERROR


def with_requests(url, headers):
    """Get a streaming response for the given event feed using requests."""
    import requests
    return requests.get(url, stream=True, headers=headers)


def _test_print(client: SSEClientWrapper):
    for event in client.events():
        pprint.pprint(json.loads(event.data))
