#!/usr/bin/python

# Run this from the directory that you will be scanning from

import os

scans = [
        "zgrab_invalid_curve",
        "zgrab_twist",
        "zgrab_baseline",
        ]

configs = [ 
["25",  " --curve-preferences '21' --ecdhe-ciphers --port 25  --starttls --smtp --ehlo 'research-scan.cis.upenn.edu' --timeout 30"],
["110", " --curve-preferences '21' --ecdhe-ciphers --port 110 --starttls --pop3 --timeout 30"],
["143", " --curve-preferences '21' --ecdhe-ciphers --port 143 --starttls --imap --timeout 30"],
["443", " --curve-preferences '21' --ecdhe-ciphers --port 443 --tls --timeout 10"],
["465", " --curve-preferences '21' --ecdhe-ciphers --port 465 --tls --timeout 10"], 
["563", " --curve-preferences '21' --ecdhe-ciphers --port 563 --tls --timeout 10"], 
["587", " --curve-preferences '21' --ecdhe-ciphers --port 587 --starttls --smtp --ehlo 'research-scan.cis.upenn.edu' --timeout 30"],
["636", " --curve-preferences '21' --ecdhe-ciphers --port 636 --tls --timeout 10"], 
["853", " --curve-preferences '21' --ecdhe-ciphers --port 853 --tls --timeout 10"], 
["989", " --curve-preferences '21' --ecdhe-ciphers --port 989 --tls --timeout 10"],
["990", " --curve-preferences '21' --ecdhe-ciphers --port 990 --tls --timeout 10"],
["992", " --curve-preferences '21' --ecdhe-ciphers --port 992 --tls --timeout 10"],
["993", " --curve-preferences '21' --ecdhe-ciphers --port 993 --tls --timeout 10"],
["994", " --curve-preferences '21' --ecdhe-ciphers --port 994 --tls --timeout 10"],
["995", " --curve-preferences '21' --ecdhe-ciphers --port 995 --tls --timeout 10"],
["2526", " --curve-preferences '21' --ecdhe-ciphers --port 2526 --tls --timeout 10"], 
["8443", " --curve-preferences '21' --ecdhe-ciphers --port 8443 --tls --timeout 10"],
        ]

zgrab_path = os.path.expandvars('$GOPATH') + '/src/github.com/zmap/zgrab'

count_file = open('count_all.sh', 'w')
comm_file = open('comm_all.sh', 'w')

for scan in scans:
    for config in configs:

        scanDir = os.path.join(scan, config[0])
        executable = "{scan}".format(scan=scan)
        try:
            os.makedirs(scanDir)
        except Exception:
            pass
        countScript = os.path.join(scanDir, 'count.sh')
        with open(countScript, 'w') as f:
            f.write('echo $PWD && grep "server_finished" zgrab.banners | jq ".data.tls.server_key_exchange.ecdh_params.server_public.x.value" | wc -l')
        count_file.write('pushd . > /dev/null && cd {scanDir} > /dev/null && bash count.sh && popd > /dev/null\n'.format(scanDir=scanDir))

        commScript = os.path.join(scanDir, 'comm.sh')
        with open(commScript, 'w') as f:
            f.write('echo $PWD && comm -12 <(grep "server_finished" zgrab.banners2 | jq ".data.tls.server_key_exchange.ecdh_params.server_public.x.value" | sort) <(grep "server_finished" zgrab.banners | jq ".data.tls.server_key_exchange.ecdh_params.server_public.x.value" | sort)  | wc -l')
        comm_file.write('pushd . > /dev/null && cd {scanDir} > /dev/null && bash comm.sh && popd > /dev/null\n'.format(scanDir=scanDir))

count_file.close()
comm_file.close()

