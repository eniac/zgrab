#!/usr/bin/python
import zmq
import sys

context = zmq.Context()
socket = context.socket(zmq.SUB)

url = "tcp://158.130.6.191:52322"
if len(sys.argv) > 1:
    url = sys.argv[1]


socket.connect(url)
socket.setsockopt_string(zmq.SUBSCRIBE, "".decode('ascii'))

while True:
    string = socket.recv_string()
    print(string)
