from django.db import models
from django.db.models import Q
from django.contrib import admin
import json

from libs import packet_handling


class SSEClient(models.Model):
    """
    SSE connected client model
    """
    # auto id

    ip = models.GenericIPAddressField(verbose_name="IP地址")
    # only for reference, may not be accurate
    port = models.IntegerField(verbose_name="端口")
    # sse channel this client is listening to
    channel = models.CharField(verbose_name="SSE信道", max_length=128, default="")

    class Meta:
        verbose_name = "被嗅探的客户端"
        verbose_name_plural = verbose_name
        constraints = [
            models.UniqueConstraint(fields=["channel"], name="unique_sse_channel"),
        ]

    def __str__(self):
        return "{" + f"sse channel: {self.channel}, ip: {self.ip}, port: {self.port}" + "}"


class NetCards(models.Model):
    """
    Network card model
    """
    # auto id

    net_cards = models.JSONField(verbose_name="网卡列表")
    sse_client = models.ForeignKey(SSEClient, on_delete=models.CASCADE, verbose_name="被嗅探的客户端")

    class Meta:
        verbose_name = "网卡"
        verbose_name_plural = verbose_name

    def __str__(self):
        return f"sse_client: {self.sse_client}"
    
    @admin.display(description="网卡")
    def net_cards_display(self):
        return json.dumps(self.net_cards, indent=4)


class SniffHistory(models.Model):
    """
    Sniff history model
    """
    # auto id, namely session_id

    timestamp = models.DateTimeField(verbose_name="时间", auto_now_add=True)
    net_card = models.CharField(verbose_name="网卡", max_length=200, blank=True, default="")
    filter = models.TextField(verbose_name="过滤器", blank=True, default="")
    # whether user submit sniff config
    is_config_submitted = models.BooleanField(verbose_name="是否已提交抓包配置", default=False)
    # whether this sniff session is successfully configured with net card and filter
    is_configured = models.BooleanField(verbose_name="是否已经成功配置网卡和过滤条件", default=False)
    # config error info if any
    config_error = models.JSONField(verbose_name="配置错误信息", default=dict)
    # whether this sniff session is completely finished, namely a history record. If True, then this session
    # is disconnected with the monitored client which means that this session cannot be restarted.
    is_history = models.BooleanField(verbose_name="是否是历史记录", default=False)
    # whether server has actively stopped this sniff session
    is_stopped = models.BooleanField(verbose_name="是否已停止", default=False)

    # sse_client = models.ForeignKey(SSEClient, on_delete=models.CASCADE, verbose_name="被嗅探的客户端")
    
    class Meta:
        verbose_name = "抓包历史记录"
        verbose_name_plural = verbose_name
        constraints = [
            models.CheckConstraint(check=(Q(is_configured=True) & Q(is_config_submitted=True)) | Q(is_configured=False), name="check_configured_sessions_must_be_submitted"),
            models.CheckConstraint(check=(Q(is_stopped=True) & Q(is_configured=True)) | Q(is_stopped=False), name="check_stopped_sessions_must_be_configured"),
            models.CheckConstraint(check=(Q(is_history=True) & Q(is_stopped=True)) | Q(is_history=False), name="check_history_sessions_must_be_stopped"),
        ]

    def __str__(self):
        # return str(self.sniff_config)
        return "{" + f"net_card: {self.net_card}, filter: {self.filter}" + "}"


class Packets(models.Model):
    """Packets model

    Read only
    """
    # auto id

    sniff_history = models.ForeignKey(SniffHistory, on_delete=models.CASCADE, verbose_name="抓包历史记录")
    # base64 encoded packet
    packet = models.TextField(verbose_name="数据包")

    class Meta:
        verbose_name = "数据包"
        verbose_name_plural = verbose_name

    def __str__(self):
        return str(packet_handling.import_packet(self.packet))


    @admin.display(description="数据包")
    def packet_display(self):
        return str(packet_handling.import_packet(self.packet))
