#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:check_all.py
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
import platform
import distro
from collections import defaultdict

# 检查SELinux状态
def check_selinux():
    result = subprocess.run(['getenforce'], stdout=subprocess.PIPE)
    if 'Disabled' not in result.stdout.decode():
        print('SELinux is not disabled')
    else:
        print('1、SELinux is disabled')

# 检查firewalld服务状态
def check_firewalld():
    result = subprocess.run(['systemctl', 'is-active', 'firewalld'], stdout=subprocess.PIPE)
    status = result.stdout.decode().strip()
    if status == 'unknown' or status == 'inactive':
        print('2、Firewalld service is inactive')
    else:
        print('Firewalld service active')

# 检查iptables策略
def check_iptables():
    result = subprocess.run(['iptables', '-L', '-n'], stdout=subprocess.PIPE)
    if 'policy ACCEPT' not in result.stdout.decode():
        print('Iptables policies are not empty')
    else:
        print('3、Iptables policies are empty')

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
        print('4、System timezone is Asia/Shanghai')

# 检查sudo权限
def check_sudo():
    users_with_sudo = []
    with open('/etc/sudoers', 'r') as file:
        sudoers_file = file.read()
    sudoers_lines = sudoers_file.split('\n')
    for line in sudoers_lines:
        if 'NOPASSWD' in line and not line.strip().startswith('#'):
            user = re.search(r'^(.*?)\s', line).group(1)
            users_with_sudo.append(user)
    if users_with_sudo:
        print('5、Sudo permissions are correctly set for ' + ', '.join(users_with_sudo))
    else:
        print('没有用户具有 Sudo NOPASSWD 权限')

# 检查UseDNS
def check_UseDNS():
    result = subprocess.run(['grep', '-n', 'UseDNS', '/etc/ssh/sshd_config'], stdout=subprocess.PIPE)
    lines = result.stdout.decode().splitlines()
    last_line = None
    for line in lines:
        last_line = line
    if last_line:
        print('6、UseDNS found at line:', last_line)

# 检查swappiness
def check_swappiness():
    with open('/proc/sys/vm/swappiness', 'r') as file:
        swappiness = file.read().strip()
    print('7、Swappiness:', swappiness)

# 检查仓库
def is_internal(ip):
    private_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in ipaddress.ip_network(n) for n in private_networks)

def check_repo():
    try:
        with open('/etc/yum.repos.d/baseepel.repo', 'r') as file:
            repo_file = file.read().strip()
        if '[base_new]' in repo_file:
            baseurl = repo_file.split('baseurl=')[1].split('\n')[0]
            url = baseurl.split('//')[1].split('/')[0]
            ip = socket.gethostbyname(url)
            if is_internal(ip):
                print(f'8、Repo file contains correct entries for intranet {url}')
            else:
                print(f'8、Repo file contains correct entries for internet {url}')
        else:
            print('Repo file does not contain correct entries for [base_new]')
    except FileNotFoundError:
        print('Repo file not found')
    result = subprocess.run(['yum', 'makecache'], stdout=subprocess.PIPE)
    last_line = result.stdout.decode().strip().split('\n')[-1]
    if 'Metadata Cache Created' in last_line:
        print('8、There are four warehouses: base_new、epel_new、extras_new、updates_new')
    else:
        print('Yum makecache was not successful')

# 检查ubuntu20仓库
def check_ubuntu20_repo():
    try:
        with open('/etc/apt/sources.list', 'r') as file:
            sources = file.readlines()
        repo_urls = set()
        for source in sources:
            if source.startswith('deb'):
                url = source.split()[1]
                repo_urls.add(url)
        for url in repo_urls:
            domain = url.split('//')[1].split('/')[0]
            try:
                ip = socket.gethostbyname(domain)
                print(f'8、Repo file contains correct entries for internet {url}')
                break
            except socket.gaierror:
                print(f'Could not resolve {domain}')
        result = subprocess.run(['apt-get', 'update'], stdout=subprocess.PIPE)
        update_output = result.stdout.decode()
        hit_lines = [line for line in update_output.split('\n') if line.startswith('Hit:')]
        repo_names = [line.split()[2].split('/')[-1] for line in hit_lines] # Note: The index is changed here to 2 to get the name of the warehouse
        print(f'8、There are {len(hit_lines)} warehouses: {"、".join(repo_names)}')
    except FileNotFoundError:
        print('sources.list file not found')

# 检查软件安装
def check_software():
    with open('/tmp/system_info_var.yaml', 'r') as file:
        system_info = yaml.safe_load(file)
    software_list = system_info['software_list']
    installed_packages = subprocess.run(['rpm', '-qa'], stdout=subprocess.PIPE).stdout.decode().strip().split('\n')
    installed_softwares = []
    not_installed_softwares = []
    for software in software_list:
        if any(software in package for package in installed_packages):
            installed_softwares.append(software)
        else:
            not_installed_softwares.append(software)
    if installed_softwares:
        num_lines = len(installed_softwares) // 6 + (len(installed_softwares) % 6 > 0)
        for i in range(num_lines):
            print('13、' + '、'.join(installed_softwares[i*6:(i+1)*6]) + ': Installed')
    if not_installed_softwares:
        print('13、' + '、'.join(not_installed_softwares) + ': Not installed')

# 检查文件描述符
def check_file_descriptor():
    needed_lines = [
        '*                soft    nofile           819200',
        '*                hard    nofile           819200',
        '*                soft    core             2048000',
        '*                hard    core             2048000',
        '*                soft    nproc            65535',
        '*                hard    nproc            65535'
    ]
    with open('/etc/security/limits.conf', 'r') as file:
        lines = file.readlines()
    all_needed_lines_present = all(any(needed_line in line for line in lines) for needed_line in needed_lines)
    result = subprocess.run(['bash', '-c', 'ulimit -n'], stdout=subprocess.PIPE)
    if all_needed_lines_present:
        print('9、ulimit -n:', result.stdout.decode().strip())
    else:
        print('Not all required lines present in /etc/security/limits.conf')

# 检查tune优化
def check_tuned():
    result = subprocess.run(['tuned-adm', 'active'], stdout=subprocess.PIPE)
    print('10、Tuned current active profile:', result.stdout.decode().strip().split(': ', 1)[-1])

# 检查外网NTP配置
def check_ntp_external():
    result = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE)
    cron_jobs = result.stdout.decode().strip().split('\n')
    cron_jobs = [job for job in cron_jobs if not job.strip().startswith("#")]
    if any('/usr/sbin/ntpdate stdtime.gov.hk' in job for job in cron_jobs):
        print("11、External NTP configuration detected. crontab is as follows:")
        for job in cron_jobs:
            print(job)
        return True
    else:
        return False

# 检查内网NTP配置
def check_ntp_internal():
    with open('/etc/ntp.conf', 'r') as file:
        lines = file.readlines()
    for line in lines:
        if 'iburst' in line:
            print(line.strip())
    result = subprocess.run(['ntpq', '-pn'], stdout=subprocess.PIPE)
    print('ntpq -pn:', result.stdout.decode().strip())

def get_interface_by_pid(pid):
    result = subprocess.run(['ps', '-p', pid, '-o', 'args'], stdout=subprocess.PIPE, universal_newlines=True)
    args = result.stdout.strip()
    match = re.search(r'(\w+)$', args)  # match the last word in the args line, which should be the interface name
    if match:
        return match.group(0)
    return None

def check_dhcpd_process():
    dhcp_processes = ['dhcpd', 'dhclient']
    for process in dhcp_processes:
        result = subprocess.run(['pgrep', '-x', process], stdout=subprocess.PIPE, universal_newlines=True)
        if result.stdout:
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                interface = get_interface_by_pid(pid)
                if interface:
                    ip_result = subprocess.run(['ip', 'addr', 'show', interface], stdout=subprocess.PIPE, universal_newlines=True)
                    if not re.search(r'inet 169\.\d+\.\d+\.\d+', ip_result.stdout):  # check if the interface has an IP starting with 169
                        print(f"12、The {process} process is running.")
                        return True
    print("12、The dhcpd or dhclient process is not running.")
    return False

# 检查并打印网络配置
def check_network_config():
    # 检查所有网络接口配置文件
    config_dir = "/etc/sysconfig/network-scripts"
    for config_file in os.listdir(config_dir):
        if config_file.startswith("ifcfg-"):
            with open(os.path.join(config_dir, config_file), 'r') as file:
                config_lines = file.readlines()
            for line in config_lines:
                if line.startswith("BOOTPROTO="):
                    if "dhcp" in line:
                        print(f"{config_file} is configured with DHCP.")
                    elif "static" in line or "none" in line:
                        print(f"{config_file} is configured with a static IP. Configuration details:")
                        for line in config_lines:
                            # 只打印关键配置信息
                            if any(key in line for key in ["IPADDR", "NETMASK", "GATEWAY", "DNS"]):
                                print(line.strip())

# 检查并打印网络配置
def check_ubuntu20_network_config():
    # 检查所有网络接口配置文件
    config_dir = "/etc/netplan"
    for config_file in os.listdir(config_dir):
        if config_file.endswith(".yaml"):
            with open(os.path.join(config_dir, config_file), 'r') as file:
                config_dict = yaml.safe_load(file)
            for interface, settings in config_dict['network']['ethernets'].items():
                if settings.get('dhcp4') is True:
                    print(f"{interface} is configured with DHCP({config_file}).")
                else:
                    print(f"{interface} is configured with a static IP({config_file}). Configuration details:")
                    for key, value in settings.items():
                        if key in ['addresses', 'gateway4', 'nameservers']:
                            print(f"{key.upper()}: {value}")

# 检查pip包
def check_pip_packages():
    result = subprocess.run(['pip3', 'list'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = result.stdout.decode().strip().split('\n')
    installed_packages = []
    pattern = re.compile(r"^(\S+)\s+(\S+)")
    for line in lines[2:]:  # Skip the first two lines (they contain information messages)
        match = pattern.match(line)
        if match:
            package_name_version = match.group(1) + " (" + match.group(2) + ")"
            installed_packages.append(package_name_version)
    num_lines = len(installed_packages) // 5 + (len(installed_packages) % 5 > 0)
    for i in range(num_lines):
        print('14、' + '、'.join(installed_packages[i*5:(i+1)*5]))

# 使用
def check_ubuntu20_network():
    if not check_dhcpd_process():
        check_ubuntu20_network_config()

# 使用
def check_static_ip():
    if not check_dhcpd_process():
        check_network_config()

def get_major_version(version_str):
    return version_str.split('.')[0]

if platform.system() == 'Linux':
    distro_name, version_str, _ = distro.linux_distribution(full_distribution_name=False)
    distro_name = distro_name.lower()
    major_version = get_major_version(version_str)
    
    if distro_name == 'centos' and major_version == '7':
        check_selinux()
        check_firewalld()
        check_iptables()
        check_timezone()
        check_sudo()
        check_UseDNS()
        check_swappiness()
        check_repo()
        check_file_descriptor()
        check_tuned()
        # 根据外网NTP配置的存在与否，决定是否检查内网NTP配置
        if not check_ntp_external():
            check_ntp_internal()
        check_static_ip()
        check_software()
        check_pip_packages()
        
    elif distro_name == 'ubuntu' and major_version == '20':
        check_firewalld()
        check_iptables()
        check_timezone()
        check_sudo()
        check_UseDNS()
        check_swappiness()
        check_ubuntu20_repo()
        check_file_descriptor()
        check_tuned()
        if not check_ntp_external():
            check_ntp_internal()
        check_ubuntu20_network()
        check_pip_packages()
        
    else:
        print('Unsupported Linux distribution')
        
else:
    print('Unsupported operating system')
