# utils.py

import psutil
from collections import defaultdict

# Globals
_seen_ips = set()
_port_scan_tracker = defaultdict(int)
PORT_THRESHOLD = 10

def detect_new_ips():
    global _seen_ips
    new_ips = []

    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == 'AF_INET':
                ip = addr.address
                if ip not in _seen_ips:
                    new_ips.append(ip)
                    _seen_ips.add(ip)
    return new_ips

def detect_port_scan():
    global _port_scan_tracker
    suspicious_ips = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            ip = conn.raddr.ip
            _port_scan_tracker[ip] += 1

    for ip, count in list(_port_scan_tracker.items()):
        if count > PORT_THRESHOLD:
            suspicious_ips.append(f"{ip} (Ports hit: {count})")
            del _port_scan_tracker[ip]

    return suspicious_ips
