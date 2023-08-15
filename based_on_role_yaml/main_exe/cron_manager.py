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
    config = {'cron_schedules': []}
    with open(file_path, 'r') as file:
        for line in file:
            key, value = line.strip().split('=')
            if key.startswith('cron_schedule'):
                config['cron_schedules'].append(value)
            else:
                config[key] = value
    return config

def start_task(config):
    task_path = config['task_path']
    python_exe_path = config['python_exe_path']
    cmd = f'crontab -l'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        for cron_schedule in config['cron_schedules']:
            full_command = f'{cron_schedule} cd {config["python_exe_path"]} && python3 {task_path}'
            if full_command in result.stdout:
                print(f"The task for {cron_schedule} is already scheduled. Please stop the task before starting it again.")
            else:
                cmd = f'(crontab -l ; echo "{full_command}") | crontab -'
                subprocess.run(cmd, shell=True, check=True)
                print(f"Task for {cron_schedule} has been scheduled successfully.")
        show_task(config)
    else:
        print("Failed to fetch crontab.")

def show_task(config):
    cmd = f'crontab -l'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        for cron_schedule in config['cron_schedules']:
            schedule_pattern = f'{cron_schedule} cd {config["python_exe_path"]} && python3 {config["task_path"]}'
            if schedule_pattern in result.stdout:
                print(f"Task for {cron_schedule} is scheduled:")
                print(schedule_pattern)
            else:
                print(f"Task for {cron_schedule} has not been scheduled yet.")
    else:
        print("Failed to fetch crontab.")

def stop_task(config):
    task_path = config['task_path']
    python_exe_path = config['python_exe_path']
    cmd = f'crontab -l'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        new_crontab = result.stdout
        for cron_schedule in config['cron_schedules']:
            schedule_pattern = f'{cron_schedule} cd {python_exe_path} && python3 {task_path}'
            if schedule_pattern in result.stdout:
                new_crontab = new_crontab.replace(schedule_pattern, "").strip()
                print(f"Task for {cron_schedule} has been stopped successfully.")
            else:
                print(f"Task for {cron_schedule} has not been scheduled yet.")

        with open('/tmp/temporary_crontab.txt', 'w') as temp_file:
            temp_file.write(new_crontab)
            temp_file.write('\n') # Add a newline character at the end
        
        subprocess.run('crontab /tmp/temporary_crontab.txt', shell=True, check=True)
    else:
        print("Failed to fetch crontab.")

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
