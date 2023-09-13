#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:generate_ips.py
#Function:
#Version:1.0
#Created:2023-09-12
#--------------------------------------------------
import sys
import ipaddress

def ip_range(start_ip, end_ip):
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    while start <= end:
        yield start
        start += 1

if __name__ == '__main__':
    start_ip = sys.argv[1]
    end_ip = sys.argv[2]
    for ip in ip_range(start_ip, end_ip):
        print(ip)
