@echo off

cd /d %~dp0

echo Starting Sniffer Server...
start "Sniffer Server" .\run_server.bat

echo Starting Sniffer Client...
start "Sniffer Client" .\run_client.bat
