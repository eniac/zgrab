#!/usr/bin/python

import os
import sys
import fileinput
import ipaddress

networks = list()
last_updated = 0
blacklist_file = "/etc/zmap/blacklist.conf"

blacklist_time = 0
valid_ip_time = 0

def blacklisted(ip):
    global last_updated
    try:
        statbuf = os.stat(blacklist_file)
        if last_updated != statbuf.st_mtime:
            last_updated = statbuf.st_mtime
            del networks[:]
            with open(blacklist_file) as f:
                for line in f:
                    sp = line.split() # remove comments
                    if len(sp) < 1:
                        continue
                    cidr = sp[0]
                    try:
                        n = ipaddress.ip_network(unicode(cidr, 'utf-8'), strict=False)
                        networks.append((int(n.netmask), int(n.network_address)))
                    except ValueError as e:
                        pass
    except OSError as e:
        sys.stderr.write(str(e) + '\n')
    ret = False
    a = int(ipaddress.ip_address(unicode(ip, 'utf-8')))
    for n in networks:
        if (a & n[0]) == n[1]:
            ret = True
            break
    return ret

def is_valid_ip(ip):
    ret = False
    try:
        ipaddress.ip_address(unicode(ip, 'utf-8'))
        ret = True
    except ValueError as e:
        pass
    return ret

if __name__ == "__main__":

    for line in fileinput.input():
        ip = line.strip()
        if is_valid_ip(ip) and not blacklisted(ip):
            print ip 
