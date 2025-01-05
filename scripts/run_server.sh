#!/bin/bash

rootDir=$(cd $(dirname $0); pwd)

cd ${rootDir}

cd ../server/

python manage.py sniffer_init_db

python manage.py runserver 0.0.0.0:8000
