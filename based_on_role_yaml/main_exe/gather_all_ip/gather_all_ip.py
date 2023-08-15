#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:gather_all_ip.py
#Function:
#Version:1.0
#Created:2023-06-06
#--------------------------------------------------
import subprocess
import shutil
import os

def find_ansible_playbook():
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    ansible_path = shutil.which("ansible-playbook")
    print(f"Looking for ansible-playbook... Found at {ansible_path if ansible_path else 'not found'}")
    return ansible_path

def run_ansible_playbook(scripts_path, playbook_name, roles_to_include_file, roles):
    ansible_path = find_ansible_playbook()
    if ansible_path is None:
        print("ansible-playbook not found!")
        return

    command = [
        "cd",
        f"{scripts_path}/AutoDeploy360/based_on_role_yaml",
        "&&",
        ansible_path, # 使用动态找到的路径
        "-i",
        "ip_all_collection/files/ip_all_collection_hosts.yaml",
        f"{playbook_name}.yaml",
        "--extra-vars",
        f"@{roles_to_include_file}.yaml",
        "--extra-vars",
        f"roles={roles}"
    ]
    command_str = " ".join(command)
    result = subprocess.run(command_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        print("An error occurred while running the playbook.")
        print(result.stderr.decode())
    else:
        print("Playbook run was successful.")
        print(result.stdout.decode())

scripts_path = "/root/scripts"
playbook_name = "playbook_name"
roles_to_include_file = "roles_to_include"
roles = "['ip_all_collection']"

run_ansible_playbook(scripts_path, playbook_name, roles_to_include_file, roles)
