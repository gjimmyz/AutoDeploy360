#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:.nmap_scan.py
#Function:
#Version:1.0
#Created:2023-08-08
#--------------------------------------------------
import logging
import datetime
from multiprocessing import Pool

log_file_path = "/tmp/temp_log_file.log"
with open(log_file_path, 'w'):
    pass

try:
    import nmap3
except ImportError:
    print("nmap3 module not found. Please install it before running the script.")
    exit(1)

# 将日志格式设置为仅记录消息
logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(message)s')
logging.info("Script started at: " + str(datetime.datetime.now()))

def scan_ip(ip):
    nmap = nmap3.Nmap()
    os_results = nmap.nmap_os_detection(ip)
    os_name = os_results[ip]['osmatch'][0]['name'] if os_results[ip]['osmatch'] else "Unknown"
    print(f"{ip}\t{os_name}")
    logging.info(f"IP: {ip} OS: {os_name}")

def scan_ips(ip_file_path):
    logging.info("Starting the IP scan for file: " + ip_file_path)
    with open(ip_file_path, 'r') as file:
        ips = [line.strip() for line in file if line.strip()]
        with Pool(5) as pool:
            pool.map(scan_ip, ips)

ip_file_path = f"/tmp/all_ip"
scan_ips(ip_file_path)
logging.info("Script ended at: " + str(datetime.datetime.now()))
