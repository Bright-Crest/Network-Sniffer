#!/bin/bash

rootDir=$(cd $(dirname $0); pwd)

cd ${rootDir}

cd ../client/sniffer_client/

python3 main.py
