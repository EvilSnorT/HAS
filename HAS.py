#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import subprocess
import socket
import re
import struct
from datetime import datetime
import platform

# 检测操作系统类型
IS_WINDOWS = platform.system().lower() == 'windows'
IS_LINUX = platform.system().lower() == 'linux'

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
    parser = argparse.ArgumentParser(description="Host Alive Scanner with multiple modes")
    parser.add_argument('-i', '--input', required=True, help="Input file containing IP addresses, URLs, or IP:port")
    parser.add_argument('-m', '--mode', choices=['ping', 'syn', 'tcp'], default='ping',
                        help="Scan mode: ping (ICMP), syn (SYN scan), or tcp (TCP connect). Default: ping")
    parser.add_argument('-p', '--ports', default='80,443,22,8080',
                        help="Ports to scan (comma-separated). Default: 80,443,22,8080")
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                        help="Timeout in seconds for connections. Default: 1.0")
    return parser.parse_args()

def parse_ports(ports_str):
    """Parse comma-separated ports string into a list of integers."""
    ports = []
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return list(set(ports))  # Remove duplicates

def extract_host_port(target):
    """Extract host and port from target string (supports IP, URL, IP:port, URL:port)."""
    target = target.strip()
    port = None
    
    # Check if target has port specification
    if ':' in target:
        parts = target.rsplit(':', 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            host = target  # Invalid port, treat as whole host
    else:
        host = target
    
    return host, port

def resolve_host(host):
    """Resolve host to IP address(es)."""
    try:
        # Check if it's an IP address
        socket.inet_aton(host)
        return [host]
    except socket.error:
        try:
            # Resolve hostname to IP
            return [info[4][0] for info in socket.getaddrinfo(host, None)]
        except (socket.gaierror, socket.herror):
            return []

def ping_ip(ip, timeout=1.0):
    """Ping an IP address with cross-platform support."""
    if IS_WINDOWS:
        command = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
    else:
        command = ['ping', '-c', '1', '-W', str(timeout), ip]
    
    try:
        with open(os.devnull, 'w') as devnull:
            return subprocess.call(command, stdout=devnull, stderr=devnull) == 0
    except Exception:
        return False

def tcp_scan(ip, port, timeout=1.0):
    """TCP connect scan."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
        return False

def syn_scan(ip, port, timeout=1.0):
    """SYN scan using raw sockets (requires root privileges on Linux)."""
    if not IS_LINUX:
        print("SYN scan is only supported on Linux. Falling back to TCP scan.")
        return tcp_scan(ip, port, timeout)
    
    try:
        # Create raw socket (requires root)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(timeout)
        
        # Set IP header manually
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Craft SYN packet
        packet = b''
        
        # IP header
        ip_ver_ihl = 0x45  # IPv4, 5 word header
        ip_tos = 0
        ip_tot_len = 0  # Will fill later
        ip_id = 54321
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton('0.0.0.0')
        ip_daddr = socket.inet_aton(ip)
        
        ip_ihl_ver = (ip_ver_ihl << 4) | 5
        ip_header = struct.pack('!BBHHHBBH4s4s', 
                               ip_ihl_ver, ip_tos, ip_tot_len, 
                               ip_id, ip_frag_off, ip_ttl, 
                               ip_proto, ip_check, ip_saddr, ip_daddr)
        
        # TCP header
        tcp_source = 54321  # Random source port
        tcp_dest = port
        tcp_seq = 0
        tcp_ack_seq = 0
        tcp_doff = 5  # Data offset: 5 words (20 bytes)
        tcp_flags = 0x02  # SYN flag
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) | 0
        tcp_header = struct.pack('!HHLLBBHHH', 
                                tcp_source, tcp_dest, 
                                tcp_seq, tcp_ack_seq, 
                                tcp_offset_res, tcp_flags, 
                                tcp_window, tcp_check, tcp_urg_ptr)
        
        # Pseudo header for checksum
        source_address = socket.inet_aton('0.0.0.0')
        dest_address = socket.inet_aton(ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        psh = struct.pack('!4s4sBBH', 
                          source_address, dest_address, 
                          placeholder, protocol, tcp_length)
        psh = psh + tcp_header
        
        # Calculate TCP checksum
        tcp_check = calculate_checksum(psh)
        tcp_header = struct.pack('!HHLLBBH', 
                                 tcp_source, tcp_dest, 
                                 tcp_seq, tcp_ack_seq, 
                                 tcp_offset_res, tcp_flags, tcp_window) + \
                     struct.pack('H', tcp_check) + \
                     struct.pack('!H', tcp_urg_ptr)
        
        # Combine IP and TCP headers
        packet = ip_header + tcp_header
        
        # Send packet
        s.sendto(packet, (ip, 0))
        
        # Listen for response
        while True:
            try:
                response = s.recv(1024)
            except socket.timeout:
                return False
                
            # Parse IP header
            ip_header = response[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            # Get protocol and source IP
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            
            if protocol != socket.IPPROTO_TCP:
                continue
                
            # Parse TCP header
            tcp_header = response[20:40]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            src_port = tcph[0]
            dest_port = tcph[1]
            flags = tcph[5]
            
            # Check if it's a SYN-ACK response to our port
            if (dest_port == tcp_source and src_ip == ip and src_port == port and 
                (flags & 0x12) == 0x12):  # SYN-ACK
                return True
            elif (flags & 0x04) != 0:  # RST flag
                return False
    except (socket.error, PermissionError):
        print("SYN scan requires root privileges on Linux. Falling back to TCP scan.")
        return tcp_scan(ip, port, timeout)
    finally:
        try:
            s.close()
        except:
            pass

def calculate_checksum(data):
    """Calculate checksum for packet."""
    if len(data) % 2 != 0:
        data += b'\0'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)
    
    return ~checksum & 0xffff

def main():
    args = parse_arguments()
    input_file = args.input
    scan_mode = args.mode
    timeout = args.timeout
    default_ports = parse_ports(args.ports)

    if not os.path.isfile(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        sys.exit(1)

    alive_targets = []  # List of tuples: (host, ip, port, scan_type)
    total_targets = 0

    with open(input_file, 'r') as file:
        targets = [line.strip() for line in file.readlines() if line.strip()]

    print(f"Starting scan with {scan_mode} mode at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Targets: {len(targets)}, Ports: {len(default_ports)} default ports")
    print("-" * 60)

    for target in targets:
        host, specified_port = extract_host_port(target)
        ips = resolve_host(host)
        
        if not ips:
            print(f"[!] Could not resolve: {host}")
            continue
        
        ports_to_scan = [specified_port] if specified_port is not None else default_ports
        
        for ip in ips:
            total_targets += 1
            if specified_port is not None:
                # Only scan the specified port
                scan_result = False
                if scan_mode == 'ping':
                    scan_result = ping_ip(ip, timeout)
                elif scan_mode == 'syn':
                    scan_result = syn_scan(ip, specified_port, timeout)
                else:  # tcp
                    scan_result = tcp_scan(ip, specified_port, timeout)
                
                if scan_result:
                    status = "OPEN" if scan_mode != 'ping' else "ALIVE"
                    print(f"[+] {host} ({ip}:{specified_port}) - {status}")
                    alive_targets.append((host, ip, specified_port, scan_mode))
            else:
                # Scan all ports in the list
                for port in ports_to_scan:
                    scan_result = False
                    if scan_mode == 'ping':
                        scan_result = ping_ip(ip, timeout)
                        # For ping mode, only need to succeed once per IP
                        if scan_result:
                            print(f"[+] {host} ({ip}) - ALIVE")
                            alive_targets.append((host, ip, None, 'ping'))
                            break
                    else:
                        if scan_mode == 'syn':
                            scan_result = syn_scan(ip, port, timeout)
                        else:  # tcp
                            scan_result = tcp_scan(ip, port, timeout)
                        
                        if scan_result:
                            print(f"[+] {host} ({ip}:{port}) - OPEN")
                            alive_targets.append((host, ip, port, scan_mode))

    print("\n" + "=" * 60)
    print(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total targets scanned: {total_targets}")
    print(f"Alive hosts: {len(alive_targets)}")
    
    if alive_targets:
        print("\nAlive Hosts Report:")
        print("-" * 60)
        for host, ip, port, scan_type in alive_targets:
            if port is not None:
                print(f"Host: {host} ({ip}) | Port: {port} | Mode: {scan_type.upper()}")
            else:
                print(f"Host: {host} ({ip}) | Mode: {scan_type.upper()}")
    else:
        print("No alive hosts found.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
