#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:install_pkg_for_cube.py
#Function:
#Version:1.0
#Created:2023-08-30
#--------------------------------------------------
import os
import sys

current_script_path = os.path.abspath(__file__)
current_directory = os.path.dirname(current_script_path)
common_utils_dir = os.path.join(current_directory, '..')
sys.path.append(common_utils_dir)

import subprocess
from common_utils import execute_ansible

def read_current_version(version_file_path):
    with open(version_file_path, 'r') as f:
        version = f.read().strip()
    return version

def write_key_file(lines, file_name, key_file_dir):
    file_path = os.path.join(key_file_dir, file_name)
    with open(file_path, 'w') as f:
        f.write(lines)
        f.write('\n')

def check_written_keys(file_name, key_file_dir):
    file_path = os.path.join(key_file_dir, file_name)
    with open(file_path, 'r') as f:
        lines = f.readlines()
    line_count = len(lines)
    return line_count

def main():
    root_scripts_path = "/root/scripts"
    ansible_role_path = "/root/scripts/AutoDeploy360/based_on_role_yaml"
    key_file_dir = os.path.join(ansible_role_path, "install_pkg_for_ubuntu20/files")
    input_text = input("Press enter or type anything to continue, type 'exit' to quit, or type 'key' to install cube: ")
    version_file_path = os.path.join(key_file_dir, "current.version")
    current_version = read_current_version(version_file_path)
    if input_text.lower() == 'key':
        print("Please enter the key content. Type 'EOF' and then press Enter to finish:")
        lines = []
        while True:
            line = input()
            if line == 'EOF':
                break
            lines.append(line)
        key_content = '\n'.join(lines)
        file_name = ""
        if len(lines) == 1:
            file_name = "cube_node_key"
            print(f"You are installing the customer's cube. Current version: {current_version}")
        elif len(lines) == 2:
            file_name = "cube_node_order_key"
            print(f"You are installing the company's cube. Current version: {current_version}")
            print("Ensure the first line is the node's key and the second line is the order's key.")
        if file_name:
            write_key_file(key_content, file_name, key_file_dir)
            if check_written_keys(file_name, key_file_dir) == len(lines):
                print(f"{file_name} has been successfully written with {len(lines)} lines.")
            else:
                print(f"Error: {file_name} was not written correctly.")
        execute_ansible([
            f"cd {ansible_role_path} && `which ansible-playbook` -i localhost generate_hosts.yaml",
            f"cd {ansible_role_path} && `which ansible-playbook` -i get_real_can_loginhost_for_create_hosts_yaml/files/hosts.yaml playbook_name.yaml --extra-vars \"@roles_to_include.yaml\" --extra-vars \"roles=['system_info','install_nic_driver_for_ubuntu20_nuc','set_nic_parameters_for_all','install_samba_for_ubuntu20','install_pkg_for_ubuntu20','reboot_for_ubuntu20']\""
        ])
        
    elif input_text.lower() == 'exit':
        print("Program has exited.")
        return

    else:
        execute_ansible([
            f"cd {ansible_role_path} && `which ansible-playbook` -i localhost generate_hosts.yaml",
            f"cd {ansible_role_path} && `which ansible-playbook` -i get_real_can_loginhost_for_create_hosts_yaml/files/hosts.yaml playbook_name.yaml --extra-vars \"@roles_to_include.yaml\" --extra-vars \"roles=['system_info','install_nic_driver_for_ubuntu20_nuc','set_nic_parameters_for_all','install_samba_for_ubuntu20','reboot_for_ubuntu20']\""
        ])

if __name__ == "__main__":
    main()
