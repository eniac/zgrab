#!/usr/bin/python
import zmq
import sys
import time

if len(sys.argv) < 3:
    print("usage: <ip> <port> [<url_server>]")
    sys.exit(1)

url = "tcp://158.130.6.191:52323"
if len(sys.argv) == 4:
    url = sys.argv[3]

context = zmq.Context()
socket = context.socket(zmq.PUB)

socket.bind(url)

while True: 
    # Send port first to allow filtering
    socket.send_string("{} {}".format(sys.argv[2], sys.argv[1]))
    time.sleep(1)
