from django.contrib import admin

from sniffer import models


class SSEClientAdmin(admin.ModelAdmin):
    list_display = ("id", "ip", "port", "channel")
    search_fields = ("ip", "port", "channel")
    list_filter = ("ip", "channel")


class NetCardsAdmin(admin.ModelAdmin):
    list_display = ("id", "sse_client", "net_cards_display")
    search_fields = ("sse_client", "net_cards_display")
    list_filter = ("sse_client",)

class SniffHistoryAdmin(admin.ModelAdmin):
    list_display = ("id", "timestamp", "net_card", "filter", "is_history", "is_stopped", "is_configured", "is_config_submitted")
    search_fields = ("timestamp", "net_card", "filter")
    list_filter = ("net_card", "filter", "is_history", "is_stopped", "is_configured", "is_config_submitted")

    
class PacketsAdmin(admin.ModelAdmin):
    list_display = ("id", "sniff_history", "packet_display")
    search_fields = ("sniff_history", "packet_display")
    list_filter = ("sniff_history",)


admin.site.register(models.SSEClient, SSEClientAdmin)
admin.site.register(models.NetCards, NetCardsAdmin)
admin.site.register(models.SniffHistory, SniffHistoryAdmin)
admin.site.register(models.Packets, PacketsAdmin)
