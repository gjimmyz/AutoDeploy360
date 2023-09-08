#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#--------------------------------------------------
#Author:gong_zheng
#Email:gong_zheng@mingmatechs.com
#FileName:sort_file.py
#Function:
#Version:1.0
#Created:2023-06-06
#--------------------------------------------------
import sys

def sort_output(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    sorted_lines = sorted(lines, key=lambda line: int(line.split('、')[0]))
    with open(file_path, 'w') as file:
        file.writelines(sorted_lines)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 sort_file.py <path_to_file>")
        sys.exit(1)
    file_path = sys.argv[1]
    sort_output(file_path)
