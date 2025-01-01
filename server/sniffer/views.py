from django.shortcuts import render, HttpResponse, redirect
from django.urls import reverse
from django_eventstream import send_event, get_current_event_id
import threading
import asyncio
import json
import logging

from sniffer import config
from libs import packet_handling

Logger = logging.getLogger(__name__)

g_net_cards = []
g_net_cards_lock = threading.Lock()

g_sniff_config = dict()
g_sniff_config_lock = threading.Lock()

g_packets = []
g_packets_lock = threading.Lock()


def home(request):
    return render(request, 'home.html')


def index(request):
    global g_net_cards
    global g_sniff_config
    global g_packets
    if request.method == "GET":
        return render(request, "sniffer/index.html")
    if request.method == "POST":
        request_post = request.POST
        if "sseData" in request_post:
            # request_data: <QueryDict: {'csrfmiddlewaretoken': ['...'], 'sseData': ['start']}>
            sseData = request_post["sseData"]
            if sseData == "start":
                g_net_cards_lock.acquire()
                g_net_cards = []
                g_net_cards_lock.release()
                g_sniff_config_lock.acquire()
                g_sniff_config = dict()
                g_sniff_config_lock.release()
                g_packets_lock.acquire()
                g_packets = []
                g_packets_lock.release()

            send_event("switch", "message", sseData)
            Logger.debug(f"send event: {sseData}")
        return HttpResponse()


async def show_net_cards(request):
    global g_net_cards
    global g_sniff_config
    if request.method == "GET":
        context = dict()
        net_cards = []
        while True:
            g_net_cards_lock.acquire()
            length = len(g_net_cards)
            net_cards = g_net_cards
            g_net_cards_lock.release()
            if length > 0:
                break
            await asyncio.sleep(0.5)

        context["net_cards_header"] = net_cards[0]
        context["net_cards"] = net_cards[1:]
        return render(request, "sniffer/show_net_cards.html", context)
    if request.method == "POST":
        request_post = request.POST
        g_sniff_config_lock.acquire()
        g_sniff_config["net_card"] = request_post["net_card"]
        g_sniff_config["filter"] = request_post["filter"]
        Logger.debug(f"sniff config: {g_sniff_config}")
        g_sniff_config_lock.release()
        return redirect(reverse("sniffer:show_packets"))


def show_packets(request):
    global g_packets
    context = dict()
    g_packets_lock.acquire()
    context["packets"] = g_packets
    g_packets_lock.release()
    return render(request, "sniffer/show_packets.html", context)


def net_cards(request):
    global g_net_cards
    if request.method == "GET":
        request_get = request.GET
        if "type" in request_get and request_get["type"] == "net_cards":
            net_cards = request_get["data"]
            net_cards = net_cards.replace(" ", "&ensp;").split("\n")

            g_net_cards_lock.acquire()
            g_net_cards = net_cards
            g_net_cards_lock.release()
        return HttpResponse()


async def sniff_config(request):
    global g_sniff_config
    if request.method == "GET":
        res_text = ""
        request_get = request.GET
        if "type" in request_get and request_get["type"] == "sniff_config":
            while True:
                g_sniff_config_lock.acquire()
                is_config = len(g_sniff_config)
                if is_config > 0:
                    res_text = json.dumps(g_sniff_config)
                    g_sniff_config.clear()
                    break
                g_sniff_config_lock.release()

                await asyncio.sleep(1)

        return HttpResponse(res_text)
    

def packet(request):
    global g_packets
    if request.method == "GET":
        request_get = request.GET
        if "type" in request_get and request_get["type"] == "packet":
            packet = request_get["data"]
            g_packets_lock.acquire()
            g_packets.append(packet)
            g_packets_lock.release()
        return HttpResponse()


# async def sniff_config(request):
#     if request.method == "GET":
#         res_text = ""
#         request_get = request.GET
#         if "type" in request_get and request_get["type"] == "sniff_config":
#             res_text = json.dumps({
#                 "net_card": "",
#                 "filter": ""
#             })
#         return HttpResponse(res_text)


# def packet(request):
#     if request.method == "GET":
#         request_get = request.GET
#         if "type" in request_get and request_get["type"] == "packet":
#             packet = request_get["data"]
#             Logger.debug(f"packet: {packet}")
#         return HttpResponse()


def test_sse(request):
    if request.method == "GET":
        return render(request, "sniffer/test_sse.html")
    if request.method == "POST":
        request_post = request.POST
        if "sseData" in request_post:
            # request_data: <QueryDict: {'csrfmiddlewaretoken': ['...'], 'sseData': ['start']}>
            sseData = request_post["sseData"]
            send_event("switch", "message", sseData)
            Logger.debug(f"send event: {sseData}")
        return HttpResponse()


def render_sse(request):
    if request.method == "GET":
        context = dict()
        context["sse_url"] = "/sniffer/" + config.SSE_URL
        context["last_id"] = get_current_event_id(config.SSE_CHANNELS)
        return render(request, "sniffer/render_sse.html", context)
    if request.method == "POST":
        request_post = request.POST
        if "sseData" in request_post:
            # request_data: <QueryDict: {'csrfmiddlewaretoken': ['...'], 'sseData': ['start']}>
            sseData = request_post["sseData"]
            send_event("switch", "message", sseData)
            Logger.debug(f"send event: {sseData}")
        return HttpResponse()
