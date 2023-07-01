#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:time_clock_cron_check_manager.py
#Function:
#Version:1.0
#Created:2023-06-27
#--------------------------------------------------
import subprocess

# Script and task paths
scripts_path = "/root/scripts/"
python_exe_path = scripts_path + "AutoDeploy360/based_on_role_yaml/main_exe/time_clock_cron_check_main/"
task_path = python_exe_path + "time_clock_cron_check.py"

def start_task():
    cmd_check = f'crontab -l | grep -q "{task_path}"'
    if subprocess.run(cmd_check, shell=True).returncode == 0:
        print("The task is already scheduled. Please stop the task before starting it again.")
    else:
        cmd = f'(crontab -l ; echo "01 22 * * * cd {python_exe_path} && python3 {task_path}") | crontab -'
        subprocess.run(cmd, shell=True, check=True)
        print("Task has been scheduled successfully.")
        show_task()

def show_task():
    cmd = f'crontab -l | grep "{task_path}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(result.stdout)
    else:
        print("The task has not been scheduled yet.")

def stop_task():
    cmd_check = f'crontab -l | grep -q "{task_path}"'
    if subprocess.run(cmd_check, shell=True).returncode == 0:
        cmd = f'crontab -l | grep -v "{task_path}" | crontab -'
        subprocess.run(cmd, shell=True, check=True)
        print("Task has been stopped successfully.")
    else:
        print("The task has not been scheduled yet.")

if __name__ == "__main__":
    while True:
        print("请输入操作 (start|show|stop|exit):")
        action = input()
        if action == "start":
            start_task()
        elif action == "show":
            show_task()
        elif action == "stop":
            stop_task()
        elif action == "exit":
            break
        else:
            print("Invalid action. Valid actions are: start, show, stop, exit")
