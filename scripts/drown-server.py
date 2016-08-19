#!/usr/bin/python
import shlex
import signal
import os
import sys
from subprocess import Popen, PIPE

processes = []

def cleanup(signal, frame):
    for p in processes:
        p.kill()

def run_command(cmd):
    args = shlex.split(cmd)
    return Popen(args)

if __name__ == "__main__":

    zgrab_dir = os.getcwd()

    if len(sys.argv) > 1:
        zgrab_dir = sys.argv[1]

    commands = [
        '{zgrab_dir}/scripts/request_aggregator.py --receive "tcp://*:52329" --send "ipc:///tmp/zgrab_in.ipc" --error "ipc:///tmp/zgrab_out.ipc"'.format(zgrab_dir=zgrab_dir),
        '{zgrab_dir}/scripts/result_publisher.py --receive "ipc:///tmp/zgrab_out.ipc" --send "tcp://*:52328"'.format(zgrab_dir=zgrab_dir),
        '{zgrab_dir}/zgrab --senders 1000 --log-file /dev/null --metadata-file /dev/null --input-file "zmq:ipc:///tmp/zgrab_in.ipc" --output-file "zmq:ipc:///tmp/zgrab_out.ipc" --port 25  --startsslv2 --smtp --ehlo "research-scan.cis.upenn.edu" --timeout 30'.format(zgrab_dir=zgrab_dir),
        '{zgrab_dir}/zgrab --senders 1000 --log-file /dev/null --metadata-file /dev/null --input-file "zmq:ipc:///tmp/zgrab_in.ipc" --output-file "zmq:ipc:///tmp/zgrab_out.ipc" --port 110 --startsslv2 --pop3 --timeout 30'.format(zgrab_dir=zgrab_dir),
        '{zgrab_dir}/zgrab --senders 1000 --log-file /dev/null --metadata-file /dev/null --input-file "zmq:ipc:///tmp/zgrab_in.ipc" --output-file "zmq:ipc:///tmp/zgrab_out.ipc" --port 143 --startsslv2 --imap --timeout 30'.format(zgrab_dir=zgrab_dir),
        '{zgrab_dir}/zgrab --senders 1000 --log-file /dev/null --metadata-file /dev/null --input-file "zmq:ipc:///tmp/zgrab_in.ipc" --output-file "zmq:ipc:///tmp/zgrab_out.ipc" --port 443 --sslv2 --timeout 30 '.format(zgrab_dir=zgrab_dir),
        '{zgrab_dir}/zgrab --senders 1000 --log-file /dev/null --metadata-file /dev/null --input-file "zmq:ipc:///tmp/zgrab_in.ipc" --output-file "zmq:ipc:///tmp/zgrab_out.ipc" --port 465 --sslv2 --timeout 30 '.format(zgrab_dir=zgrab_dir),
        '{zgrab_dir}/zgrab --senders 1000 --log-file /dev/null --metadata-file /dev/null --input-file "zmq:ipc:///tmp/zgrab_in.ipc" --output-file "zmq:ipc:///tmp/zgrab_out.ipc" --port 587 --startsslv2 --smtp --ehlo "research-scan.cis.upenn.edu" --timeout 30'.format(zgrab_dir=zgrab_dir),
        '{zgrab_dir}/zgrab --senders 1000 --log-file /dev/null --metadata-file /dev/null --input-file "zmq:ipc:///tmp/zgrab_in.ipc" --output-file "zmq:ipc:///tmp/zgrab_out.ipc" --port 993 --sslv2 --timeout 30'.format(zgrab_dir=zgrab_dir),
        '{zgrab_dir}/zgrab --senders 1000 --log-file /dev/null --metadata-file /dev/null --input-file "zmq:ipc:///tmp/zgrab_in.ipc" --output-file "zmq:ipc:///tmp/zgrab_out.ipc" --port 995 --sslv2 --timeout 30'.format(zgrab_dir=zgrab_dir),
    ]

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    
    for command in commands:
        processes.append(run_command(command))
    p = Popen(shlex.split('tail -f /dev/null'))
    processes.append(p)
    p.wait()
