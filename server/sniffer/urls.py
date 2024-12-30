from django.urls import path

from sniffer import views

app_name = "sniffer"
urlpatterns = [
    path("index/", views.index, name="index"),
]
