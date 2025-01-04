from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = '''Initialize the database for the sniffer app. Recommended to run this command
            before starting the server to avoid unwanted behaviors of database and avoid
            user data loss.'''

    def handle(self, *args, **options):
        from sniffer import models
        models.SSEClient.objects.all().delete()
        models.NetCards.objects.all().delete()
        models.SniffHistory.objects.all().update(is_config_submitted=True, is_configured=True, config_error=dict(), is_history=True, is_stopped=True)
        return "Sniffer database initialized."
