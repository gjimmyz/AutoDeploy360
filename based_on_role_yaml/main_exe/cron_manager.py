#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:cron_manager.py
#Function:
#Version:1.0
#Created:2023-06-27
#--------------------------------------------------
import subprocess
import sys

def load_config(file_path):
    config = {}
    with open(file_path, 'r') as file:
        for line in file:
            key, value = line.strip().split('=')
            config[key] = value
    return config

def start_task(config):
    task_path = config['task_path']
    python_exe_path = config['python_exe_path']
    cron_schedule = config['cron_schedule']
    cmd_check = f'crontab -l | grep -q "{task_path}"'
    if subprocess.run(cmd_check, shell=True).returncode == 0:
        print("The task is already scheduled. Please stop the task before starting it again.")
    else:
        cmd = f'(crontab -l ; echo "{cron_schedule} cd {python_exe_path} && python3 {task_path}") | crontab -'
        subprocess.run(cmd, shell=True, check=True)
        print("Task has been scheduled successfully.")
        show_task(config)

def show_task(config):
    task_path = config['task_path']
    cmd = f'crontab -l | grep "{task_path}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(result.stdout)
    else:
        print("The task has not been scheduled yet.")

def stop_task(config):
    task_path = config['task_path']
    cmd_check = f'crontab -l | grep -q "{task_path}"'
    if subprocess.run(cmd_check, shell=True).returncode == 0:
        cmd = f'crontab -l | grep -v "{task_path}" | crontab -'
        subprocess.run(cmd, shell=True, check=True)
        print("Task has been stopped successfully.")
    else:
        print("The task has not been scheduled yet.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("please input config")
        sys.exit(1)
        
    config_path = sys.argv[1]
    config = load_config(config_path)
    
    while True:
        print("please input (start|show|stop|exit):")
        action = input()
        if action == "start":
            start_task(config)
        elif action == "show":
            show_task(config)
        elif action == "stop":
            stop_task(config)
        elif action == "exit":
            break
        else:
            print("Invalid action. Valid actions are: start, show, stop, exit")
