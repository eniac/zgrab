#!/usr/bin/python

import zmq
import argparse
import os
import traceback
import re
import json
import ipaddress
from netaddr import all_matching_cidrs

cidr_list = list()
last_updated = 0
blacklist_file = "/etc/zmap/blacklist.conf"
IP_CIDR_RE = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))")

def blacklisted(ip):
    statbuf = os.stat(blacklist_file)
    if last_updated != statbuf.st_mtime:
        last_update = statbuf.st_mtime
        del cidr_list[:]
        with open(blacklist_file) as f:
            for line in f:
                sp = line.split()
                if len(sp) < 1:
                    continue
                cidr = sp[0]
                if IP_CIDR_RE.match(cidr):
                    cidr_list.append(cidr)
    if len(all_matching_cidrs(ip, cidr_list)) > 0:
        return True
    else:
        return False

def is_valid_port(port):
    return port in ["25", "110", "143", "443", "465", "587", "993", "995"]

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(bytearray(str(ip)))
        return True
    except ValueError as e:
        return False

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Aggregate pull requests and publish to zgrab processes") 
    parser.add_argument('--receive', '-r', help="url to receive from")
    parser.add_argument('--send', '-s', help="url to publish to")
    parser.add_argument('--error', '-e', help="url to publish errors to")

    args = parser.parse_args()
    
    context = zmq.Context.instance()

    # Socket to receive client requests
    receiver = context.socket(zmq.PULL)
    receiver.bind(args.receive)

    # Socket to publish results to zgrab workders
    publisher = context.socket(zmq.PUB)
    publisher.bind(args.send)

    # Socket to send results to result_aggregator
    errors = context.socket(zmq.PUSH)
    errors.connect(args.error)

    while True:
        try:
            message = receiver.recv_string()
            ip, port = message.split(" ")
            if is_valid_ip(ip) and not blacklisted(ip) and is_valid_port(port):
                publisher.send_string("%s %s" % (port, ip))
            else:
                errors.send_string(json.dumps({'ip': ip, 'port': port, 'blacklisted': True}))
        except Exception:
            print(traceback.format_exc())
            #receiver.close()
            #publisher.close()
            #errors.close()
            #raise
