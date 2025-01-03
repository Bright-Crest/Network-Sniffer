from django.apps import AppConfig


class SnifferConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "sniffer"

    def ready(self):
        # from sniffer import models
        # models.NetCards.objects.all().delete()
        # models.SniffHistory.objects.all().update(is_configured=True, is_history=True, is_stopped=True)
        pass
