#!/bin/bash
mkdir -p /etc/socketshell/logs
cp controller.py /etc/socketshell/
touch /etc/socketshell/agent_whitelist.json
echo "Installed to /etc/socketshell"
