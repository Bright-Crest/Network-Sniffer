from django.shortcuts import render, HttpResponse, redirect
from django.urls import reverse
from django_eventstream import send_event, get_current_event_id
from asgiref.sync import sync_to_async
import json
import asyncio
import logging

from sniffer import models, config
from libs import packet_handling

Logger = logging.getLogger(__name__)


async def home(request):
    return render(request, 'home.html')


async def index(request):
    if request.method == "GET":
        if "is_no_sse_client" in request.GET and request.GET["is_no_sse_client"] == "true":
            # XMLHttpRequest to update page without refresh
            if await models.SSEClient.objects.all().aexists():
                return redirect(reverse("sniffer:index"))
            else:
                return HttpResponse()
        else:
            # normal get request
            context = dict()
            context["sniff_historys"] = [s async for s in models.SniffHistory.objects.all().order_by("-id")]
            sse_clients = models.SSEClient.objects.all()
            context["sse_clients"] = [c async for c in sse_clients] if await sse_clients.aexists() else None
            return render(request, "sniffer/index.html", context)

    elif request.method == "POST":
        request_post = request.POST
        if "sseData" in request_post:
            # request_data: <QueryDict: {'csrfmiddlewaretoken': ['...'], 'sseData': ['start']}>
            if request_post["sseData"] == "start":
                new_sniff_session = await models.SniffHistory.objects.acreate()
                def _update_session():
                    request.session["sniffer_current_session_id"] = new_sniff_session.id
                await sync_to_async(_update_session)()
                Logger.debug(f"Start new session with id {request.session['sniffer_current_session_id']}")
                sseData = {
                    # simply use id as session_id
                    "session_id": new_sniff_session.id,
                    "sse_type": "start"
                }
                await sync_to_async(send_event)(config.SSE_CHANNELS[0], "message", sseData)
                Logger.debug(f"send event: {sseData}")
                return redirect(reverse("sniffer:show_net_cards", kwargs={"session_id": int(new_sniff_session.id)}))


async def show_net_cards(request, session_id):
    sniff_session_objs = models.SniffHistory.objects.filter(id=session_id)
    # handle error session id 
    if not await sniff_session_objs.aexists():
        return render(request, "sniffer/error.html", {"error": f"Sniff session with id {session_id} does not exist"})
    sniff_session = await sniff_session_objs.afirst()
    if sniff_session.is_history:
        return render(request, "sniffer/error.html", {"error": f"Sniff session with id {session_id} is a history record which cannot be restarted"})
    if sniff_session.is_configured:
        return redirect(reverse("sniffer:show_packets", kwargs={"session_id": session_id}))

    if request.method == "GET":
        context = {"net_cards": []}
        while not await models.NetCards.objects.all().aexists():
            await asyncio.sleep(1)
        net_cards = await models.NetCards.objects.order_by("-id").afirst()
        for _, net_card in net_cards.net_cards.items():
            ipv4 = ""
            for i in net_card["IPv4"]:
                ipv4 += i + "<br>"
            net_card["IPv4"] = ipv4
            ipv6 = ""
            for i in net_card["IPv6"]:
                ipv6 += i + "<br>"
            net_card["IPv6"] = ipv6
            context["net_cards"].append(net_card)
        return render(request, "sniffer/show_net_cards.html", context)

    elif request.method == "POST":
        request_post = request.POST
        await sniff_session_objs.aupdate(
            net_card=request_post["net_card"],
            filter=request_post["filter"],
            is_configured=True
        )
        return redirect(reverse("sniffer:show_packets", kwargs={"session_id": session_id}))


async def show_packets(request, session_id):
    if request.method == "GET":
        if "last_row" not in request.GET:
            # normal get request
            sniff_session_objs = models.SniffHistory.objects.filter(id=session_id)
            if not (await sniff_session_objs.afirst()).is_configured:
                await sniff_session_objs.aupdate(is_configured=True)
                await asyncio.sleep(0.5)

            sniff_session = await sniff_session_objs.afirst()
            context = {
                "is_history": sniff_session.is_history,
                "is_stopped": sniff_session.is_stopped,
            }

            packets = []
            i = 0
            async for p in models.Packets.objects.filter(sniff_history_id=session_id).order_by("id"):
                row = i + 1
                packet = packet_handling.import_object(p.packet)
                packets.append((row, p.id, str(packet)))
                i += 1
            context["packets"] = packets
            return render(request, "sniffer/show_packets.html", context)
        else:
            # XMLHttpRequest to update page without refresh
            last_row = int(request.GET["last_row"])
            packets_to_append = []
            i = 0
            async for p in models.Packets.objects.filter(sniff_history_id=session_id).order_by("id"):
                if i < last_row:
                    i += 1
                    continue
                row = i + 1
                packet = packet_handling.import_object(p.packet)
                packets_to_append.append((row, p.id, str(packet)))
                i += 1
            return render(request, "sniffer/show_packets_table_rows.html", {"packets": packets_to_append})

    elif request.method == "POST":
        request_post = request.POST
        if "sseData" in request_post:
            sseData = {
                "session_id": session_id,
                "sse_type": request_post["sseData"]
            }

            if request_post["sseData"] == "restart":
                await sync_to_async(send_event)(config.SSE_CHANNELS[0], "message", sseData)
                sniff_history_objs = models.SniffHistory.objects.filter(id=session_id)
                if (await sniff_history_objs.afirst()).is_history:
                    return render(request, "sniffer/error.html", {"error": "Cannot restart history session"})
                await sniff_history_objs.aupdate(is_stopped=False)
                await models.Packets.objects.filter(sniff_history_id=session_id).adelete()
                Logger.debug(f"deleted packets with session id {session_id}")
                # force refresh
                return redirect(reverse("sniffer:show_packets", kwargs={"session_id": session_id}))
            elif request_post["sseData"] == "stop":
                # XMLHttpRequest to send event without refresh
                sniff_history_objs = models.SniffHistory.objects.filter(id=session_id)
                await sniff_history_objs.aupdate(is_stopped=True, is_configured=True)
                await sync_to_async(send_event)(config.SSE_CHANNELS[0], "message", sseData)
                return HttpResponse()
            else:
                return HttpResponse()


async def delete_session(request, session_id):
    sniff_session_objs = models.SniffHistory.objects.filter(id=session_id)
    if not await sniff_session_objs.aexists():
        return render(request, "sniffer/error.html", {"error": f"Sniff session with id {session_id} does not exist"})
    sniff_session = await sniff_session_objs.afirst()
    if not sniff_session.is_configured or not sniff_session.is_stopped:
        await sync_to_async(send_event)(config.SSE_CHANNELS[0], "message", {"session_id": session_id, "sse_type": "stop"})

    await sniff_session_objs.adelete()
    # auto cascadedly delete packets belonging to this session
    return render(request, "sniffer/success.html", {"operation": f"删除{sniff_session.timestamp}的嗅探记录", "info": f"网卡: {sniff_session.net_card}，过滤条件: {sniff_session.filter}"})


async def net_cards(request):
    if request.method == "GET":
        request_get = request.GET
        if "type" in request_get and request_get["type"] == "net_cards":
            client_ip = request.META["REMOTE_ADDR"]
            client_port = request.META["REMOTE_PORT"]

            sse_client_objs = models.SSEClient.objects.filter(channel=config.SSE_CHANNELS[0])
            if await sse_client_objs.aexists():
                # assume that same sse channel has only one client
                # but its port may change
                await sse_client_objs.adelete()

            sse_client = await models.SSEClient.objects.acreate(ip=client_ip, port=client_port, channel=config.SSE_CHANNELS[0])
            net_cards = json.loads(request_get["data"])
            await models.NetCards.objects.acreate(net_cards=net_cards, sse_client=sse_client)
            return HttpResponse()


async def sniff_config(request):
    if request.method == "GET":
        request_get = request.GET
        if "type" in request_get and request_get["type"] == "sniff_config":
            session_id = json.loads(request_get["data"])["session_id"]
            sniff_session_objs = models.SniffHistory.objects.filter(id=session_id)
            while not (await sniff_session_objs.afirst()).is_configured:
                Logger.debug(f"wait for sniff session {session_id} to be configured")
                await asyncio.sleep(1)
            sniff_session = await sniff_session_objs.afirst()
            res_text = json.dumps({
                "net_card": sniff_session.net_card,
                "filter": sniff_session.filter
            })
            return HttpResponse(res_text)
    

async def packet(request):
    if request.method == "GET":
        request_get = request.GET
        if "type" in request_get and request_get["type"] == "packet":
            data = json.loads(request_get["data"])

            if not await models.SniffHistory.objects.filter(id=data["session_id"]).aexists():
                return HttpResponse()

            await models.Packets.objects.acreate(
                sniff_history_id=data["session_id"],
                packet=data["packet"]
            )
            return HttpResponse()


async def session_error(request):
    if request.method == "GET":
        request_get = request.GET
        if "type" in request_get and request_get["type"] == "session_error":
            session_id = json.loads(request_get["data"])["session_id"]
            await models.SniffHistory.objects.filter(id=session_id).aupdate(is_configured=True, is_history=True, is_stopped=True)
            return HttpResponse()


# def test_sse(request):
#     if request.method == "GET":
#         return render(request, "sniffer/test_sse.html")
#     if request.method == "POST":
#         request_post = request.POST
#         if "sseData" in request_post:
#             # request_data: <QueryDict: {'csrfmiddlewaretoken': ['...'], 'sseData': ['start']}>
#             sseData = request_post["sseData"]
#             send_event("switch", "message", sseData)
#             Logger.debug(f"send event: {sseData}")
#         return HttpResponse()


# def render_sse(request):
#     if request.method == "GET":
#         context = dict()
#         context["sse_url"] = "/sniffer/" + config.SSE_URL
#         context["last_id"] = get_current_event_id(config.SSE_CHANNELS)
#         return render(request, "sniffer/render_sse.html", context)
#     if request.method == "POST":
#         request_post = request.POST
#         if "sseData" in request_post:
#             # request_data: <QueryDict: {'csrfmiddlewaretoken': ['...'], 'sseData': ['start']}>
#             sseData = request_post["sseData"]
#             send_event("switch", "message", sseData)
#             Logger.debug(f"send event: {sseData}")
#         return HttpResponse()
