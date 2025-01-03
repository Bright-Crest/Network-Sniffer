from django.urls import include, path
import django_eventstream

from sniffer import views
from sniffer import config

app_name = "sniffer"
urlpatterns = [
    path("", views.index, name="index"),
    path(config.SSE_URL, include(django_eventstream.urls), {"channels": config.SSE_CHANNELS}),
    # user-client
    path("<int:session_id>/show_net_cards/", views.show_net_cards, name="show_net_cards"),
    path("<int:session_id>/show_packets/", views.show_packets, name="show_packets"),
    path("<int:session_id>/delete_session/", views.delete_session, name="delete_session"),
    # monitered client
    path("net_cards/", views.net_cards, name="net_cards"),
    path("sniff_config/", views.sniff_config, name="sniff_config"),
    path("packet/", views.packet, name="packet"),
    path("session_error/", views.session_error, name="session_error"),

    # only for debug
    # path("test_sse/", views.test_sse, name="test_sse"),
    # path("render_sse/", views.render_sse, name="render_sse"),
]
