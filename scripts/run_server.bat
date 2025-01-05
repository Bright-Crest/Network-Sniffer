@echo off

cd /d %~dp0

cd ..\server\

python manage.py sniffer_init_db

python manage.py runserver 0.0.0.0:8000
