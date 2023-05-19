#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:run.py
#Function:
#Version:1.0
#Created:2023-05-17
#--------------------------------------------------
import json

# Load localhost mapping
with open('localhost_mapping.json', 'r') as f:
    localhost_mapping = json.load(f)

# Load successful ssh info
with open('successful_ssh.json', 'r') as f:
    successful_ssh = json.load(f)

results = {}

for ssh_info in successful_ssh:
    user = ssh_info['item'][0]
    index = ssh_info['item'][1]
    os_info = ssh_info['stdout'].split('\n')[0].split('=')[1].replace('\"', '').lower()
    if "linux" in os_info:
        os_info = os_info.split(' ')[0]
    os_version = ssh_info['stdout'].split('\n')[1].split('=')[1].replace('\"', '').split(' ')[0].split('.')[0]

    localhost_name = localhost_mapping[str(index)]

    # Extract port from ssh command
    cmd_split = ssh_info['cmd'].split(' ')
    port = cmd_split[cmd_split.index('-p') + 1]

    results[localhost_name] = f'{localhost_name} localhost port={port} {os_info}{os_version} {user}'

# Write in specified order to a new file
with open('output.txt', 'w') as f:
    if 'localhost1' in results:
        f.write(results['localhost1'] + '\n')
    if 'localhost3' in results:
        f.write(results['localhost3'] + '\n')
    if 'localhost2' in results:
        f.write(results['localhost2'] + '\n')