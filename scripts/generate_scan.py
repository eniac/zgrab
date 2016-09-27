#!/usr/bin/python

# Run this from the directory that you will be scanning from

import os

scans = [
        "zgrab",
        ]

configs = [ 
["22",  " --ssh --port 22 --timeout 10"],
        ]

zgrab_path = os.path.expandvars('$GOPATH') + '/src/github.com/zmap/zgrab'

command_file = open('run_all.sh', 'w')
command_file.write('# run with sudo\n')

for scan in scans:
    for config in configs:

        scanDir = os.path.join(scan, config[0])
        executable = "zgrab".format(scan=scan)
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
            f.write('bandwidth 50M\n')
#        f.write('seed 19105\n')
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
             ' --gomaxprocs 24'
             ' --senders=10000'.format(
                       executable=executable,
                       path=zgrab_path,
                       config=config[1]))

        with open(runScript, 'w') as f:
            f.write('# run with sudo\n')
            f.write('zmap -C scan.conf'
                    ' | ztee results.csv --success-only'
                    ' | {cmd}\n'.format(cmd=cmd))
        command_file.write('pushd . && cd {scanDir} && bash run.sh && popd\n'.format(scanDir=scanDir))

command_file.close()
