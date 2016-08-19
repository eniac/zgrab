#!/usr/bin/python

import zmq
import argparse
import json
import traceback
import hashlib

def process_message(message):
    if len(message) < 0:
        return None

    parsed = None
    try:
        parsed = json.loads(message)
    except ValueError:
        return None

    sslv2 = False
    sslv2_export = False
    sslv2_extra_clear = False
    output = dict()
    # an empty field means inconclusive
    try:
        output['ip'] = parsed['ip']
    except KeyError:
        pass
    try:
        output['port'] = parsed['port']
    except KeyError:
        pass
    try:
        output['common_name'] = parsed['data']['sslv2']['server_hello']['certificate']['parsed']['subject']['common_name']
    except KeyError:
        pass
    try:
        output['alt_names'] = parsed['data']['sslv2']['server_hello']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names']
    except KeyError:
        pass
    try:
        m = parsed['data']['sslv2']['server_hello']['certificate']['parsed']['subject_key_info']['rsa_public_key']['modulus']
        e = parsed['data']['sslv2']['server_hello']['certificate']['parsed']['subject_key_info']['rsa_public_key']['exponent']
        pk = "%s:%s" % (m, e)
        h = hashlib.sha256()
        h.update(pk)
        output['key_sha256'] = h.hexdigest()
    except KeyError:
        pass
    try:
        output['fingerprint_sha256'] = parsed['data']['sslv2']['server_hello']['certificate']['parsed']['fingerprint_sha256']
    except KeyError:
        pass
    try:
        output['sslv2'] = parsed['data']['sslv2']['server_verify']['valid']
    except KeyError:
        pass
    try:
        output['sslv2_export'] = parsed['data']['sslv2_export']['server_verify']['valid']
    except KeyError:
        pass
    try:
        output['sslv2_extra_clear'] = parsed['data']['sslv2_extra_clear']['server_verify']['extra_clear']
    except KeyError:
        pass
    try:
        if 'timeout' in parsed['error']:
            output['error'] = True
    except KeyError:
        pass
    # Process results directly from the request aggregator
    try:
        if 'blacklisted' in parsed:
            output['error'] = True 
            output['blacklisted'] = True
    except KeyError:
        pass

    return json.dumps(output)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Aggregate results and publish to clients") 
    parser.add_argument('--receive', '-r', help="url to subscribe on")
    parser.add_argument('--send', '-s', help="url to publish to")

    args = parser.parse_args()
    
    context = zmq.Context.instance()
    
    # Receive results from zgrab workers
    receiver = context.socket(zmq.PULL)
    receiver.bind(args.receive)

    # Publish results to clients
    publisher = context.socket(zmq.PUB)
    publisher.bind(args.send)

    while True:
        try: 
            message = receiver.recv_string().strip()
            output = process_message(message)
            if output != None:
                publisher.send_string(output)
        except Exception:
            print(traceback.format_exc())
            #receiver.close()
            #publisher.close()
            #raise
