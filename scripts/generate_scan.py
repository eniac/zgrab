#!/usr/bin/python

# Run this from the directory that you will be scanning from

import os

configs = [ 
        '2048S256V1',
#        '2048S256V1_0',
        '2048S256V1_1',
        '2048S256V1_M1',
        '2048S256V1_S7',

        '2048S256V2',
#        '2048S256V2_0',
        '2048S256V2_1',
        '2048S256V2_M1',
        '2048S256V2_S7',

        '1024S160V1',
#        '1024S160V1_0',
        '1024S160V1_1',
        '1024S160V1_M1',
        '1024S160V1_S7',

        '2048S224V1',
#        '2048S224V1_0',
        '2048S224V1_1',
        '2048S224V1_M1',
        '2048S224V1_S3',

        '1024S160V2',
#        '1024S160V2_0',
        '1024S160V2_1',
        '1024S160V2_M1',
        '1024S160V2_S7',

        '2048S224V2',
#        '2048S224V2_0',
        '2048S224V2_1',
        '2048S224V2_M1',
        '2048S224V2_S3',

        'BASELINEV1',
        'BASELINEV2',
        ]

zgrab_path = os.path.expandvars('$GOPATH') + '/src/github.com/zmap/zgrab'

command_file = open('run_all.sh', 'w')
command_file.write('# run with sudo\n')

for config in configs:

    scanDir = os.path.join(config)
    try:
        os.makedirs(config)
    except Exception:
        pass
    zmapConf = os.path.join(scanDir, 'scan.conf')
    runScript = os.path.join(scanDir, 'run.sh')
    with open(zmapConf, 'w') as f:
        f.write('probe-module udp\n')
        if 'V2' in config:
            f.write('probe-args=file:' + zgrab_path + '/scripts/1024.IKEv2.pkt\n')
        else:
            f.write('probe-args=file:' + zgrab_path + '/scripts/1024.psk.pkt\n')
        f.write('target-port 500\n')
        f.write('output-fields saddr,success,repeat\n')
        f.write('output-filter "success = 1 && repeat = 0"\n')
        f.write('output-module csv\n')
        f.write('bandwidth 400M\n')
        f.write('metadata zmap.meta.json\n')
        f.write('cooldown-time 5\n')
        f.write('seed 123789\n')
        f.write('max-targets 100%\n')
        f.write('interface "em1"\n')
        f.write('blacklist-file "/etc/zmap/blacklist.conf"\n')

    ike_cmd = ('{path}/zgrab'
               ' --ike-config {config}'
               ' --port 500'
               ' --metadata-file zgrab.meta.ike.json'
               ' --log-file zgrab.ike.log'
               ' --output-file banners.ike.json'
               ' --gomaxprocs 24'
               ' --senders=10000'.format(
                   path=zgrab_path,
                   config=config))

    with open(runScript, 'w') as f:
        f.write('# run with sudo\n')
        f.write('zmap -C scan.conf'
                ' | ztee results.csv --success-only'
                ' | {ike_cmd}\n'.format(ike_cmd=ike_cmd))
    command_file.write('pushd . && cd {scanDir} && bash run.sh && popd\n'.format(scanDir=scanDir))

command_file.close()
