#!/usr/bin/python

import zmq
import ipaddress
import sys
import argparse

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(bytearray(str(ip)))
        return True
    except ValueError as e:
        return False

def do_drowntest(args):

    context = zmq.Context()
    # Socket to talk to server
    print("Connecting to drowntest server {}:{}...".format(args.server_ip, args.server_port))
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://{}:{}".format(args.server_ip, args.server_port))

    # Send request
    print("Sending request {} {}".format(args.query_ip, args.query_port))
    socket.send_string("{} {}".format(args.query_ip, args.query_port))

    # Get reply
    result = socket.recv_string()

    return result
    

if __name__=="__main__":

    parser = argparse.ArgumentParser(description="Standalone client interface to send queries to drown-server.py") 
    parser.add_argument('--server_ip', '-sp', default="158.130.6.191", help="IP for drown-server.py")
    parser.add_argument('--server_port', '-si', default=54323, type=int, help="port for drown-server.py")
    parser.add_argument('--query_ip', '-qi', help="query IP")
    parser.add_argument('--query_port', '-qp', type=int, help="query port")
    args = parser.parse_args()

    print(do_drowntest(args))
    exit(0)
