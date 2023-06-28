#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:time_clock_cron_check.py
#Function:
#Version:1.0
#Created:2023-06-25
#--------------------------------------------------
import os
import psutil
import socket
from datetime import datetime
import subprocess
os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

# Function to validate IP
def is_valid_ipv4_address(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Set filter parameter, default is '#'
filter_parameter = os.getenv('FILTER_PARAMETER', '#')

# Script and file paths
scripts_path = "/root/scripts/"
ip_file_path = scripts_path + "AutoDeploy360/based_on_role_yaml/main_exe/time_clock_cron_check_main/ip_all.txt"
host_template_path = scripts_path + "AutoDeploy360/based_on_role_yaml/main_exe/time_clock_cron_check_main/host_all_template.yaml"
new_dir = scripts_path + "AutoDeploy360/time_clock_cron_check_host_yaml/"
os.makedirs(new_dir, exist_ok=True)
host_base_path = new_dir + "host_all_"
roles_file_path = scripts_path + "AutoDeploy360/based_on_role_yaml/roles_to_include.yaml"
playbook_path = scripts_path + "AutoDeploy360/based_on_role_yaml/playbook_name.yaml"

# Get current date
now = datetime.now()
year = now.strftime("%Y")
month = now.strftime("%m")
day = now.strftime("%d")
output_dir = scripts_path + f"AutoDeploy360/time_clock_cron_check_log/{year}/{month}/{day}/"
output_file_path = output_dir + "output.txt"
output_mail_file_path = output_dir + "output_mail.txt"

# Load all IPs
with open(ip_file_path, 'r') as f:
    all_ips = [line for line in f.read().splitlines() if not line.startswith(filter_parameter)]

# Validate all IPs
invalid_ips = [ip for ip in all_ips if not is_valid_ipv4_address(ip)]
if invalid_ips:
    print(f"Invalid IP addresses: {invalid_ips}")
    exit(1)

# Check if there is at least one valid IP
if len(all_ips) == 0:
    print("Please input at least one valid IP address.")
    exit(1)

# Split IPs into chunks of 10
chunks = [all_ips[i:i + 10] for i in range(0, len(all_ips), 10)]

# Load host template, and split at group title to inject IPs later
with open(host_template_path, 'r') as f:
    host_template_parts = f.read().split('[all_all]')

for index, chunk in enumerate(chunks, start=1):
    # Generate hosts file path for this chunk
    hosts_file_path = host_base_path + f"{index:02d}.yaml"

    # Write chunk to hosts file
    with open(hosts_file_path, 'w') as f:
        f.write(host_template_parts[0])
        f.write('[all_all]\n')
        for ip in chunk:
            f.write(ip + "\n")
        f.write(host_template_parts[1])

    # Get current sshpass processes
    before_sshpass_processes = {proc.pid: proc for proc in psutil.process_iter(['pid', 'name']) if proc.info['name'] == 'sshpass'}

    # Run Ansible playbook
    subprocess.run(['ansible-playbook', '-i', hosts_file_path, playbook_path, '--extra-vars', f"@{roles_file_path}", '--extra-vars', "roles=['sshpass_ssh_conn','time_clock_cron_check']"], check=True)

    # Get sshpass processes started by the playbook
    after_sshpass_processes = {proc.pid: proc for proc in psutil.process_iter(['pid', 'name']) if proc.info['name'] == 'sshpass'}
    new_sshpass_pids = set(after_sshpass_processes) - set(before_sshpass_processes)

    # Kill sshpass processes started by the playbook
    for pid in new_sshpass_pids:
        after_sshpass_processes[pid].kill()
# ...

# Check output file against all IPs
with open(output_file_path, 'r') as f:
    output_lines = f.readlines()

# Collect and deduplicate IPs
ip_lines = set()
deduped_lines = []
for line in output_lines:
    parts = line.split('----------')
    ip = parts[0]  # assuming IP is the first element
    if ip not in ip_lines:
        ip_lines.add(ip)
        deduped_lines.append(line)

# Write deduped lines to a temp file
with open(output_file_path + '_deduped', 'w') as f:
    for line in deduped_lines:
        f.write(line)

# Now use the deduped file instead of the original
output_file_path += '_deduped'

missing_ips = list(set(all_ips) - set(ip_lines))

# If there are missing IPs, print them
if missing_ips:
    print(f"Missing IPs: {missing_ips}")

# Read the output file into lines
with open(output_file_path, 'r') as f:
    lines = [line.split('----------') for line in f.readlines()]

# Convert the lines to tuples so they can be added to a set
tuple_lines = [tuple(line) for line in lines]

# Remove duplicates
unique_tuple_lines = list(set(tuple_lines))

# Convert the tuples back to lists
lines = [list(t) for t in unique_tuple_lines]

# Sort by the 4th column
lines.sort(key=lambda x: -int(x[3].replace('s', '')))

# Only keep the first 10 lines
lines = lines[:10]

# Write the sorted and unique lines back to output_mail_file_path
with open(output_mail_file_path, 'w') as f:
    for line in lines:
        f.write('----------'.join(line))
        f.write('\n')

# Send mail
subprocess.run(['ansible-playbook', '-i', 'localhost', playbook_path, '--extra-vars', f"@{roles_file_path}", '--extra-vars', f"roles=['send_to_mail'] mail_subject='Your subject' file_to_send_list=['{output_mail_file_path}']"], check=True)
