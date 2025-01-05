#!/bin/bash

printf "Setting up the server...\n"

rootDir=$(cd $(dirname $0); pwd)

cd ${rootDir}

cd ../server

python manage.py makemigrations --noinput

python manage.py migrate --noinput

python manage.py sniffer_init_db

python manage.py collectstatic --noinput

cd ${rootDir}
