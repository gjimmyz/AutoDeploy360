#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:check_ubuntu20.py
#Function:
#Version:1.0
#Created:2023-06-06
#--------------------------------------------------
import re
import yaml
import subprocess
import os
import socket
import ipaddress

# 检查firewalld服务状态
def check_firewalld():
    result = subprocess.run(['systemctl', 'is-active', 'firewalld'], stdout=subprocess.PIPE)
    if 'inactive' not in result.stdout.decode():
        print('1、Firewalld service is not inactive')
    else:
        print('Firewalld service is inactive')

# 检查iptables策略
def check_iptables():
    result = subprocess.run(['iptables', '-L', '-n'], stdout=subprocess.PIPE)
    if 'policy ACCEPT' not in result.stdout.decode():
        print('Iptables policies are not empty')
    else:
        print('2、Iptables policies are empty')

# 检查swappiness
def check_swappiness():
    with open('/proc/sys/vm/swappiness', 'r') as file:
        swappiness = file.read().strip()
    print('7、Swappiness:', swappiness)

# 检查系统时区
def check_timezone():
    result = subprocess.run(['timedatectl', 'status'], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    # 解析输出，找到时区行
    for line in output.split('\n'):
        if 'Time zone:' in line:
            timezone = line.split(':')[1].strip().split(' ')[0]
            break
    if timezone != 'Asia/Shanghai':
        print('System timezone is not Asia/Shanghai')
    else:
        print('3、System timezone is Asia/Shanghai')


# 运行检查
check_swappiness()
