#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:report_check_time.py
#Function:
#Version:1.0
#Created:2023-06-20
#--------------------------------------------------
import sys
import time
import datetime
from dateutil.parser import parse
import re

# Function to extract timestamp from date strings
def clean_and_extract_timestamp(date_str):
    # Remove possible " -X.XXXXXX seconds" suffix
    date_str = re.sub(" -[0-9.]* seconds", "", date_str)
    # Convert date_str to timestamp
    try:
        return int(time.mktime(parse(date_str).timetuple()))
    except Exception:
        return None
# Get the path of the record and output file from command line arguments
record_file_path = sys.argv[1]
output_file_path = sys.argv[2]
# Open the record file and read lines
with open(record_file_path, 'r') as f:
    lines = f.readlines()
records = {}
for line in lines:
    # Skip comment lines
    if line.startswith("#"):
        continue
    # Split line into ip, remote file time, local file time, remote hwclock time, remote date time
    ip, remote_file_time, local_file_time, remote_hwclock_time, remote_date_time = line.strip().split(',')
    # Calculate the deviation in seconds for file time
    deviation_file = abs(float(local_file_time) - float(remote_file_time))
    deviation_file = int(deviation_file)  # Convert to int to remove decimals
    # Determine the flag if deviation_file greater than 5 minutes
    flag_file = 1 if deviation_file > 5 * 60 else 0
    # Calculate the deviation in seconds for hwclock time
    remote_hwclock_timestamp = clean_and_extract_timestamp(remote_hwclock_time)
    remote_date_timestamp = clean_and_extract_timestamp(remote_date_time)
    if remote_hwclock_timestamp is not None and remote_date_timestamp is not None:
        deviation_time = abs(remote_hwclock_timestamp - remote_date_timestamp)
        # Determine the flag if deviation_time greater than 5 minutes
        flag_time = 1 if deviation_time > 5 * 60 else 0
        # Add deviations in seconds or days
        if deviation_file >= 86400:
            deviation_file_str = "{}d".format(deviation_file // 86400)
        else:
            deviation_file_str = "{}s".format(deviation_file)
        if deviation_time >= 86400:
            deviation_time_str = "{}d".format(deviation_time // 86400)
        else:
            deviation_time_str = "{}s".format(deviation_time)
        # Add the record to the dictionary, using IP as the key
        # This will ensure that each IP will only have one record
        records[ip] = (ip, deviation_file_str, flag_file, deviation_time_str, flag_time)
# Sort records by deviation_file time in descending order
sorted_records = sorted(records.values(), key=lambda x: x[1], reverse=True)
# Write the top 10 records to output.txt
with open(output_file_path, 'w') as f:
    for record in sorted_records[:10]:
        formatted = [str(item).ljust(0) for item in record]
        f.write('----------'.join(formatted))
        f.write('\n')
