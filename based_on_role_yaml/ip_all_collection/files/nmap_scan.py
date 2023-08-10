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
import os

today_date = datetime.datetime.now().date()
flag_path = f"/tmp/{today_date.year:04}/{today_date.month:02}/{today_date.day:02}/1"

if os.path.exists(flag_path):
    print("nmap has run today, will not run again.")
    exit(0)

log_file_path = "/tmp/temp_log_file.log"

try:
    import nmap3
except ImportError:
    print("nmap3 module not found. Please install it before running the script.")
    exit(1)

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

with open(log_file_path, 'r') as file:
    lines = file.readlines()

if lines[0].startswith("Script started at:") and lines[-1].startswith("Script ended at:"):
    today_str = str(today_date)
    if today_str in lines[0] and today_str in lines[-1]:
        ip_output_file = f"/tmp/{today_date.year:04}/{today_date.month:02}/{today_date.day:02}/filtered_ips.txt"
        os.makedirs(os.path.dirname(ip_output_file), exist_ok=True)
        with open(ip_output_file, 'w') as ip_file:
            for line in lines:
                if "Linux" in line and line.startswith("IP:"):
                    ip = line.split(" ")[1]
                    ip_file.write(ip + '\n')
        os.makedirs(os.path.dirname(flag_path), exist_ok=True)
        with open(flag_path, 'w'):
            pass
