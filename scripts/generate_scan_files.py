#!/usr/bin/python

import os

cipherKinds = {
        'rc2': 'SSL2_RC2_EXPORT_CBC_WITH_MD5',
#        'rc4': 'SSL2_RC4_128_EXPORT40_WITH_MD5',
#        'des': 'SSL2_DES_64_CBC_WITH_MD5'
        }

ports = {
#        '25':  ('--starttls --smtp --ehlo=test','--starttls --smtp --ehlo=test'),
#        '110': ('--starttls --pop3','--starttls --pop3'),
#        '143': ('--starttls --imap','--starttls --imap'),
        '443': ('--tls-version SSLV2','--tls'),
#        '465': ('--tls-version SSLV2','--tls'),
#        '587': ('--starttls --smtp --ehlo=test','--starttls --smtp --ehlo=test'),
#        '993': ('--tls-version SSLV2','--tls'),
#        '995': ('--tls-version SSLV2','--tls'),
        }

command_file = open('run_all.sh', 'w')
command_file.write('# run with sudo\n')

for cipherKind,cipherKindString in cipherKinds.items():
    for port, portArgs in ports.items():
        scanDir = os.path.join(cipherKind, port)
        try:
            os.makedirs(scanDir)
        except Exception:
            pass
        zmapConf = os.path.join(scanDir, 'scan.conf')
        runScript = os.path.join(scanDir, 'run.sh')
        with open(zmapConf, 'w') as f:
            f.write('probe-module tcp_synscan\n')
            f.write('target-port {}\n'.format(port))
            f.write('output-fields saddr,success,repeat\n')
            f.write('output-filter "success = 1 && repeat = 0"\n')
            f.write('output-module csv\n')
            f.write('bandwidth 250M\n')
            f.write('metadata zmap.meta.json\n')
#            f.write('log-file zmap.log\n')
            f.write('cooldown-time 5\n')
            f.write('max-targets 100%\n')
            f.write('interface "p4p1"\n')
            f.write('blacklist-file "/etc/zmap/blacklist.conf"\n')

        ssl2_cmd =  (' ~/d/d --cipherKind {cipherKind} --port {port} {portArgs}'
                    ' --output-file banners.ssl2.json'
                    ' --log-file zgrab.ssl2.log'
                    ' --metadata-file zgrab.meta.ssl2.json'
                    ' --gomaxprocs 12'
                    ' --senders 5000'.format(
                            cipherKind=cipherKindString, 
                            port=port, 
                            portArgs=portArgs[0]))
        tls_cmd =   (' ~/zgrab_vanilla/zgrab --port {port} {portArgs}'
                    ' --output-file banners.tls.json'
                    ' --log-file zgrab.tls.log'
                    ' --metadata-file zgrab.meta.tls.json'
                    ' --gomaxprocs 12'
                    ' --senders 5000'.format(
                            port=port, 
                            portArgs=portArgs[1]))
        with open(runScript, 'w') as f:
            f.write('# run with sudo\n')
            f.write('zmap -C scan.conf'
                    ' | ztee results.csv --success-only'
                    ' | tee >({ssl2_cmd})'
                    ' | {tls_cmd}\n'.format(ssl2_cmd=ssl2_cmd,tls_cmd=tls_cmd))
        command_file.write('pushd . && cd {scanDir} && bash run.sh && popd\n'.format(scanDir=scanDir))

command_file.close()
