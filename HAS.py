#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import subprocess

ASCII_ART = '''
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
░▒▓████████▓▒░▒▓████████▓▒░░▒▓██████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░
                                         
                                         
Name: Host-Alive-Scanner
Author: EvilSnorT
'''

print(ASCII_ART)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Ping IP addresses from a file.")
    parser.add_argument('-i', '--input', required=True, help="Input file containing IP addresses")
    return parser.parse_args()

def ping_ip(ip):
    try:
        output = subprocess.run(["ping", "-c", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if output.returncode == 0:
            return True
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
    return False

def main():
    args = parse_arguments()
    input_file = args.input

    if not os.path.isfile(input_file):
        print(f"The file {input_file} does not exist.")
        sys.exit(1)

    alive_ips = []

    with open(input_file, 'r') as file:
        ips = file.readlines()
        for ip in ips:
            ip = ip.strip()
            if ip:
                print(f"Pinging {ip}...")
                if ping_ip(ip):
                    print(f"{ip} is alive.")
                    alive_ips.append(ip)
                else:
                    print(f"{ip} is not reachable.")

    print("\nAlive IP addresses:")
    for ip in alive_ips:
        print(ip)

if __name__ == "__main__":
    main()

