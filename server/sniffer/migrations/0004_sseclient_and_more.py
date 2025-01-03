# Generated by Django 5.1.4 on 2025-01-03 10:29

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("sniffer", "0003_sniffhistory_is_stopped"),
    ]

    operations = [
        migrations.CreateModel(
            name="SSEClient",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("ip", models.GenericIPAddressField(verbose_name="IP地址")),
                ("port", models.IntegerField(verbose_name="端口")),
                (
                    "channel",
                    models.CharField(default="", max_length=128, verbose_name="SSE信道"),
                ),
            ],
            options={
                "verbose_name": "被嗅探的客户端",
                "verbose_name_plural": "被嗅探的客户端",
            },
        ),
        migrations.AddConstraint(
            model_name="sniffhistory",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("is_stopped", True), ("is_configured", True)),
                    ("is_stopped", False),
                    _connector="OR",
                ),
                name="check_stopped_sessions_must_be_configured",
            ),
        ),
        migrations.AddConstraint(
            model_name="sniffhistory",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("is_history", True), ("is_stopped", True)),
                    ("is_history", False),
                    _connector="OR",
                ),
                name="check_history_sessions_must_be_stopped",
            ),
        ),
        migrations.AddField(
            model_name="netcards",
            name="sse_client",
            field=models.ForeignKey(
                default=1,
                on_delete=django.db.models.deletion.CASCADE,
                to="sniffer.sseclient",
                verbose_name="被嗅探的客户端",
            ),
            preserve_default=False,
        ),
    ]