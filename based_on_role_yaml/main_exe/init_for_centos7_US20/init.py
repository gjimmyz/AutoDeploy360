#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:init.py
#Function:
#Version:1.0
#Created:2023-06-27
#--------------------------------------------------
import os
import sys

current_script_path = os.path.abspath(__file__)
current_directory = os.path.dirname(current_script_path)
common_utils_dir = os.path.join(current_directory, '..')
sys.path.append(common_utils_dir)

from common_utils import execute_ansible

def main():
    scripts_path = "/root/scripts"
    ansible_role_path = os.path.join(scripts_path, "AutoDeploy360/based_on_role_yaml")
    commands = [
        f"cd {ansible_role_path} && `which ansible-playbook` -i localhost generate_hosts.yaml",
        f"cd {ansible_role_path} && `which ansible-playbook` -i get_real_can_loginhost_for_create_hosts_yaml/files/hosts.yaml playbook_name.yaml --extra-vars \"@roles_to_include.yaml\" --extra-vars \"roles=['system_info','set_nic_parameters_for_all','reboot_for_ubuntu20','reboot_for_centos7']\""
    ]
    execute_ansible(commands)

if __name__ == "__main__":
    main()
