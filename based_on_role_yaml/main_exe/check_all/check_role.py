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
import hashlib
import argparse

os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
scripts_path = "/root/scripts/"
roles_file_path = scripts_path + "AutoDeploy360/based_on_role_yaml/roles_to_include.yaml"
playbook_path = scripts_path + "AutoDeploy360/based_on_role_yaml/playbook_name.yaml"
now = datetime.now()
year = now.strftime("%Y")
month = now.strftime("%m")
day = now.strftime("%d")
output_dir = scripts_path + f"AutoDeploy360/machine_information/{year}/{month}/{day}/"
output_mail_file_path = output_dir + "output_mail.txt"

def parse_args():
    parser = argparse.ArgumentParser(description="执行脚本以生成主机清单，获取事实和发送邮件。")
    parser.add_argument("-c", "--custom-hosts", help="自定义主机清单文件的路径。", type=str)
    return parser.parse_args()

def compute_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def generate_hosts(custom_hosts=None):
    if custom_hosts:
        print(f"Using custom hosts file: {custom_hosts}")
    else:
        os.chdir(scripts_path + "AutoDeploy360/based_on_role_yaml/")
        subprocess.run(['ansible-playbook', '-i', 'localhost', 'generate_hosts.yaml'], check=True)

def get_facts(custom_hosts=None):
    inventory_file = 'get_real_can_loginhost_for_create_hosts_yaml/files/hosts.yaml' if not custom_hosts else custom_hosts
    subprocess.run(['ansible-playbook', '-i', inventory_file, '/root/scripts/AutoDeploy360/based_on_role_yaml/get_facts.yaml'], check=True)

def send_mail():
    file_paths = []
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            file_paths.append(os.path.join(root, file))
    file_paths_str = ','.join([f"'{path}'" for path in file_paths])
    for file_path in file_paths:
        if file_path.endswith(".sent"):
            continue
        current_md5 = compute_md5(file_path)
        flag_file_path = file_path + ".sent"
        if os.path.exists(flag_file_path):
            with open(flag_file_path, "r") as f:
                previous_md5 = f.read().strip()
            if previous_md5 == current_md5:
                continue
        mail_subject = os.path.splitext(os.path.basename(file_path))[0]
        subprocess.run(['ansible-playbook', '-i', 'localhost', playbook_path, '--extra-vars', f"@{roles_file_path}", '--extra-vars', f"roles=['send_to_mail'] mail_subject='{mail_subject}' file_to_send_list=['{file_path}']"], check=True)
        with open(flag_file_path, "w") as f:
            f.write(current_md5)

if __name__ == "__main__":
    args = parse_args()
    generate_hosts(custom_hosts=args.custom_hosts)
    get_facts(custom_hosts=args.custom_hosts)
    send_mail()

