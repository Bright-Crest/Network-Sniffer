from django.contrib import admin

from sniffer import models


class SSEClientAdmin(admin.ModelAdmin):
    pass


class NetCardsAdmin(admin.ModelAdmin):
    list_display = ("id", "net_cards")
    search_fields = ("net_cards",)
    list_filter = ("net_cards",)


class SniffHistoryAdmin(admin.ModelAdmin):
    pass
    
    
class PacketsAdmin(admin.ModelAdmin):
    list_display = ("id", "sniff_history", "packet_display")
    search_fields = ("sniff_history", "packet_display")
    list_filter = ("sniff_history",)


admin.site.register(models.SSEClient, SSEClientAdmin)
admin.site.register(models.NetCards, NetCardsAdmin)
admin.site.register(models.SniffHistory, SniffHistoryAdmin)
admin.site.register(models.Packets, PacketsAdmin)
