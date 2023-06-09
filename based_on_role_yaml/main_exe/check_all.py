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
import time

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

# 检查网络
def is_internal(ip):
    private_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in ipaddress.ip_network(n) for n in private_networks)

# 检查仓库
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
    if os.path.exists('/tmp/system_info_var.yaml'):
        file_path = '/tmp/system_info_var.yaml'
    elif os.path.exists('/tmp/var_for_US2004.yaml'):
        file_path = '/tmp/var_for_US2004.yaml'
    else:
        print("Neither system_info_var.yaml nor var_for_US2004.yaml exists in /tmp directory.")
        return
    with open(file_path, 'r') as file:
        system_info = yaml.safe_load(file)
    software_list = system_info['software_list']
    if os.path.exists('/etc/redhat-release'):
        installed_packages = subprocess.run(['rpm', '-qa'], stdout=subprocess.PIPE).stdout.decode().strip().split('\n')
    elif os.path.exists('/etc/debian_version'):
        installed_packages = subprocess.run(['dpkg-query', '-f', '${binary:Package}\n', '-W'], stdout=subprocess.PIPE).stdout.decode().strip().split('\n')
    else:
        print("Unsupported system type.")
        return
    installed_softwares = []
    not_installed_softwares = []
    for software in software_list:
        if any(software in package for package in installed_packages):
            installed_softwares.append(software)
        else:
            not_installed_softwares.append(software)
    print("13、The following are the software packages installed on the system:")
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
    match = re.search(r'(\w+)$', args)
    if match:
        return match.group(0)
    return None

# 检查dhcp进程
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
    print("12、The dhcpd or dhclient process is not running:")
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
    print("14、The following are the pip packages installed on the system:")
    for i in range(num_lines):
        print('14、' + '、'.join(installed_packages[i*5:(i+1)*5]))

# 检查网卡信息
def check_nic_info():
    cmd = 'sudo lshw -c network'
    output = subprocess.check_output(cmd, shell=True).decode()
    network_list = output.split('*-network')[1:]
    network_dict = defaultdict(int)
    network_info = {}
    for network in network_list:
        if 'Ethernet interface' in network:
            product_search = re.search('product: (.*)', network)
            vendor_search = re.search('vendor: (.*)', network)
            driver_search = re.search('driver=(\S+)', network)
            driverversion_search = re.search('driverversion=(\S+)', network)
            product = product_search.group(1) if product_search else 'null'
            vendor = vendor_search.group(1) if vendor_search else 'null'
            driver = driver_search.group(1) if driver_search else 'null'
            driverversion = driverversion_search.group(1) if driverversion_search else 'null'
            network_dict[product] += 1
            network_info[product] = {
                'vendor': vendor,
                'driver': driver,
                'driver_ver': driverversion
            }
    print('15、The following are nic info')
    for product, count in network_dict.items():
        info = network_info[product]
        if product == 'null' and info['vendor'] == 'null':
            print('model:', product, '、vendor:', info['vendor'], '、driver:', info['driver'], '、driver_ver:', info['driver_ver'], '、nic_num:', count)
        else:
            print('model:', product, '\nvendor:', info['vendor'], '\ndriver:', info['driver'], '、driver_ver:', info['driver_ver'], '、nic_num:', count)

# 检查带宽
def get_iperf_test(server_hostname, port=5201, duration=1, max_attempts=3, delay_between_attempts=5):
    command = ["iperf3", "-c", server_hostname, "-p", str(port), "-t", str(duration)]
    for attempt in range(1, max_attempts + 1):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        if "the server is busy running a test" in output:
            # Error running iperf, retry after a delay
            time.sleep(delay_between_attempts)
            continue
        elif result.returncode != 0:
            # Non-retryable error, abort
            print("Non-retryable error encountered. Aborting.")
            return None
        else:
            # Test was successful, parse and return the bandwidth
            match = re.search(r"(\d+) Mbits/sec", output)
            if match:
                return int(match.group(1))
            else:
                print("Failed to extract bandwidth information from iperf output")
                return None
    print("Failed to get successful iperf run after max attempts. Aborting.")
    return None

def check_bandwidth(server_hostname):
    bandwidth = get_iperf_test(server_hostname)
    if bandwidth:
        if bandwidth >= 700:
            print("16、Bandwidth 700+ Mbits/sec Ok")
        else:
            print(f"16、Bandwidth {bandwidth} Mbits/sec Warn")
    else:
        print("Failed to get bandwidth information.")

# 检查cpu
def check_cpu_info():
    with open("/proc/cpuinfo") as f:
        for line in f:
            if line.strip():
                if line.rstrip('\n').startswith('model name'):
                    model_name = re.sub( ".*model name.*:", "", line,1)
                if line.rstrip('\n').startswith('processor'):
                    processor = re.sub( ".*processor.*:", "", line,1)
    print(f"17、cpu {int(processor.strip()) + 1} cores {model_name.strip()}")

# 检查内存
def get_total_memory():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemTotal"):
                mem_total_kb = int(line.split()[1])
    mem_total_gb = mem_total_kb / 1024 / 1024
    return round(mem_total_gb, 2)

def get_memory_module_info():
    output = subprocess.check_output("dmidecode --type 17", shell=True).decode()
    max_capacity_output = subprocess.check_output("dmidecode | grep 'Maximum Capacity'", shell=True).decode()
    num_slots_output = subprocess.check_output("dmidecode --type 16 | grep 'Number Of Devices'", shell=True).decode()
    module_info = re.findall("Size: ((?:[0-9]+ GB)|(?:[0-9]+ MB)|(?:No Module Installed))", output)
    # 转换所有模块大小为MB，并过滤掉未安装模块
    installed_modules = []
    for info in module_info:
        if "No Module Installed" not in info:
            size, unit = re.match(r"([0-9]+) (MB|GB)", info).groups()
            size_in_mb = int(size) * 1024 if unit == "GB" else int(size)
            installed_modules.append(size_in_mb)
    if not installed_modules:
        raise ValueError("No installed memory module was found.")
    speeds = list(set(re.findall("Speed: ([0-9]+) MT/s", output)))
    configs = list(set(re.findall("Configured Memory Speed: ([0-9]+) MT/s", output)))
    types = list(set(re.findall("Type: ([A-Za-z0-9 ]+)", output)))
    max_capacity = re.search("Maximum Capacity: (.*)", max_capacity_output).group(1)
    num_slots = re.search("Number Of Devices: (.*)", num_slots_output).group(1)
    return len(installed_modules), installed_modules[0], speeds, configs, types, max_capacity, num_slots

def check_memory_info():
    total_memory = get_total_memory()
    module_count, module_size, speeds, configs, types, max_capacity, num_slots = get_memory_module_info()
    print(f"18、Total_Memory {total_memory}G，Max_Capacity {max_capacity}，Num_Slots {num_slots}，used_slots {module_count}，Module_Size {module_size} MB，Memory_Type {'/'.join(types)}，rate {'/'.join(speeds)}，current_config_memory_speed {'/'.join(configs)}")

def get_disk_info(info):
    # 使用正则表达式匹配相关信息
    logical_name = re.search(r'logical name: (/dev/\w+)', info)
    product = re.search(r'product: (.*)', info)
    description = re.search(r'description: (.*)', info)
    size = re.search(r'size: (.*)', info)
    # 如果相关信息存在则获取，否则设为 None
    logical_name = logical_name.group(1) if logical_name else "None"
    product = product.group(1) if product else "None"
    description = description.group(1) if description else "None"
    size = size.group(1) if size else "None"
    return logical_name, product, description, size

def check_disk_info():
    # 使用 subprocess 执行 lshw 命令并获取输出
    output = subprocess.check_output("lshw -class disk", shell=True).decode()
    # 按 "*-" 分割输出以获取各硬盘信息
    disks_info = output.split('*-')[1:]
    for i, disk_info in enumerate(disks_info, 19):  # 从19开始计数
        logical_name, product, description, size = get_disk_info(disk_info)
        print(f'{i}、{logical_name}, Product: {product}，{description}，{size}')

def get_raid_info(output):
    raid_level_match = re.search("RAID Level\s+:\s+(.*)", output)
    size_match = re.search("Size\s+:\s+(.*)", output)
    states_match = re.findall("State\s+:\s+(.*)", output)
    if raid_level_match is None or size_match is None or not states_match:
        return None
    state_counts = {}
    for state in states_match:
        state = state.strip()
        state_counts[state] = state_counts.get(state, 0) + 1
    state_info = []
    for state, count in state_counts.items():
        state_info.append(f"{count} {state}")
    raid_level = raid_level_match.group(1)
    size = size_match.group(1)
    state_info = ', '.join(state_info)
    return f"RAID Level {raid_level}，Size {size}，State {state_info}"

def check_raid_info():
    commands = [
        'cd /opt/MegaRAID/MegaCli/ && ./MegaCli64 -ShowSummary -aALL',
        'hpssacli ctrl all show config'
    ]
    for i, command in enumerate(commands, 20): # 从20开始计数
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        except subprocess.CalledProcessError as e:
            output = e.output
        info = get_raid_info(output)
        if info is not None:
            print(f"{i}、{info}")

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
        check_nic_info()
        check_bandwidth('192.168.109.149')
        check_cpu_info()
        check_memory_info()
        check_disk_info()
        check_raid_info()
        
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
        check_software()
        check_pip_packages()
        check_nic_info()
        check_bandwidth('192.168.109.149')
        check_cpu_info()
        check_memory_info()
        check_disk_info()
        check_raid_info()
        
    else:
        print('Unsupported Linux distribution')
        
else:
    print('Unsupported operating system')
