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

command_file = open('run_all.sh', 'w')
command_file.write('# run with sudo\n')

for scan in scans:
    for config in configs:

        scanDir = os.path.join(scan, config[0])
        executable = "{scan}".format(scan=scan)
        try:
            os.makedirs(scanDir)
        except Exception:
            pass
        zmapConf = os.path.join(scanDir, 'scan.conf')
        runScript = os.path.join(scanDir, 'run.sh')
        with open(zmapConf, 'w') as f:
            f.write('target-port {}\n'.format(config[0]))
            f.write('output-fields saddr,success,repeat\n')
            f.write('output-filter "success = 1 && repeat = 0"\n')
            f.write('output-module csv\n')
            f.write('bandwidth 200M\n')
            f.write('seed 2002\n')
            f.write('metadata zmap.meta.json\n')
            f.write('cooldown-time 5\n')
            f.write('max-targets 1%\n')
            f.write('interface "em1"\n')
            f.write('blacklist-file "/etc/zmap/blacklist.conf"\n')

        cmd = ('{path}/{executable}'
             ' {config}'
             ' --metadata-file zgrab.meta'
             ' --log-file zgrab.log'
             ' --output-file zgrab.banners'
             ' --tls-verbose'
             ' --gomaxprocs 24'
             ' --senders=10000'.format(
                       executable=executable,
                       path=zgrab_path,
                       config=config[1]))
        cmd2 = ('{path}/{executable}'
             ' {config}'
             ' --metadata-file zgrab.meta2'
             ' --log-file zgrab.log2'
             ' --output-file zgrab.banners2'
             ' --tls-verbose'
             ' --gomaxprocs 24'
             ' --senders=10000'.format(
                       executable=executable,
                       path=zgrab_path,
                       config=config[1]))

        with open(runScript, 'w') as f:
            f.write('# run with sudo\n')
            f.write('zmap -C scan.conf'
                    ' | ztee results.csv --success-only'
                    ' | tee >({cmd2})'
                    ' | {cmd}\n'.format(cmd=cmd,cmd2=cmd2))
        command_file.write('pushd . && cd {scanDir} && bash run.sh && popd\n'.format(scanDir=scanDir))

command_file.close()
