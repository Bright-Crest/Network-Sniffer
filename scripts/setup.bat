@echo off

echo Setting up the server...

cd /d %~dp0

cd ..\server\

python manage.py makemigrations --noinput

python manage.py migrate --noinput

python manage.py sniffer_init_db

python manage.py collectstatic --noinput

cd /d %~dp0
