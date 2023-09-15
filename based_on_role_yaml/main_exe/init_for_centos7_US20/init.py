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
import argparse

current_script_path = os.path.abspath(__file__)
current_directory = os.path.dirname(current_script_path)
common_utils_dir = os.path.join(current_directory, '..')
sys.path.append(common_utils_dir)

from common_utils import execute_ansible

def get_user_input():
    args = argparse.Namespace()
    input_text = input("Do you want to debug or specify roles? (Enter for default, 'debug' for debug mode, 'roles' to specify roles, 'both' for both): ")
    if input_text.lower() == 'debug':
        args.debug = True
        args.roles = None
    elif input_text.lower() == 'roles':
        args.debug = False
        roles_input = input("Please enter the roles, separated by spaces (e.g. 'system_info reboot_for_ubuntu20'): ")
        args.roles = roles_input.split()
    elif input_text.lower() == 'both':
        args.debug = True
        roles_input = input("Please enter the roles, separated by spaces (e.g. 'system_info reboot_for_ubuntu20'): ")
        args.roles = roles_input.split()
    else:
        args.debug = False
        args.roles = None
    return args

def main(args):
    scripts_path = "/root/scripts"
    ansible_role_path = os.path.join(scripts_path, "AutoDeploy360/based_on_role_yaml")
    debug_flag = "-vvvv" if args.debug else ""
    roles_to_run = args.roles if args.roles else ['system_info','set_nic_parameters_for_all','reboot_for_ubuntu20','reboot_for_centos7']

    commands = [
        f"cd {ansible_role_path} && `which ansible-playbook` {debug_flag} -i localhost generate_hosts.yaml",
        f"cd {ansible_role_path} && `which ansible-playbook` {debug_flag} -i get_real_can_loginhost_for_create_hosts_yaml/files/hosts.yaml playbook_name.yaml --extra-vars \"@roles_to_include.yaml\" --extra-vars \"roles={roles_to_run}\""
    ]
    log_file = "/tmp/debug_output.txt" if args.debug else None
    execute_ansible(commands, log_file)

if __name__ == "__main__":
    args = get_user_input()
    main(args)
