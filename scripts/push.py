#!/usr/bin/python
import zmq
import sys

if len(sys.argv) < 3:
    print("usage: <ip> <port> [<url_server>]")
    sys.exit(1)

url = "tcp://158.130.6.191:52323"
if len(sys.argv) == 4:
    url = sys.argv[3]

context = zmq.Context()
socket = context.socket(zmq.PUSH)

socket.connect(url)

socket.send_string("{} {}".format(sys.argv[1], sys.argv[2]))
