#!/bin/bash

rootDir=$(cd $(dirname $0); pwd)

cd ${rootDir}

printf "Starting Sniffer Server and Client...\n"

parallel ::: ./run_server.sh ./run_client.sh