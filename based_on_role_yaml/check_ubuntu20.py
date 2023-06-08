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

# 检查swappiness
def check_swappiness():
    with open('/proc/sys/vm/swappiness', 'r') as file:
        swappiness = file.read().strip()
    print('7、Swappiness:', swappiness)

# 运行检查
check_swappiness()
