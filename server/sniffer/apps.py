from django.apps import AppConfig


class SnifferConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "sniffer"

    def ready(self):
        pass
