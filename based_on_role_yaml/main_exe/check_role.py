#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:check_role.py
#Function:
#Version:1.0
#Created:2023-06-25
#--------------------------------------------------
import os
import subprocess
from datetime import datetime

os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

# Script and file paths
scripts_path = "/root/scripts/"
roles_file_path = scripts_path + "AutoDeploy360/based_on_role_yaml/roles_to_include.yaml"
playbook_path = scripts_path + "AutoDeploy360/based_on_role_yaml/playbook_name.yaml"

# Get current date
now = datetime.now()
year = now.strftime("%Y")
month = now.strftime("%m")
day = now.strftime("%d")
output_dir = scripts_path + f"AutoDeploy360/machine_information/{year}/{month}/{day}/"
output_mail_file_path = output_dir + "output_mail.txt"

# Running ansible-playbook
os.chdir(scripts_path + "AutoDeploy360/based_on_role_yaml/")
subprocess.run(['ansible-playbook', '-i', 'localhost', 'generate_hosts.yaml'], check=True)
subprocess.run(['ansible-playbook', '-i', 'get_real_can_loginhost_for_create_hosts_yaml/files/hosts.yaml', 'get_facts.yaml'], check=True)

# Gather all the file paths in the output directory
file_paths = []
for root, dirs, files in os.walk(output_dir):
    for file in files:
        file_paths.append(os.path.join(root, file))

# Convert the list into a string that can be passed to ansible-playbook
file_paths_str = ','.join([f"'{path}'" for path in file_paths])

# Send mail
subprocess.run(['ansible-playbook', '-i', 'localhost', playbook_path, '--extra-vars', f"@{roles_file_path}", '--extra-vars', f"roles=['send_to_mail'] mail_subject='Your subject' file_to_send_list=[{file_paths_str}]"], check=True)
