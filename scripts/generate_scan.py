#!/usr/bin/python

# Run this from the directory that you will be scanning from

import os
import argparse

# <standalone-scans-with-zmap>: [<followup zgrab scans>]
scans = {
        'V1': [
#            'BASELINEV1',
#
#            '2048S256V1',
#            '2048S256V1_0',
#            '2048S256V1_1',
#            '2048S256V1_M1',
#            '2048S256V1_S7',
#
#            '1024S160V1',
#            '1024S160V1_0',
#            '1024S160V1_1',
#            '1024S160V1_M1',
#            '1024S160V1_S7',
#
#            '2048S224V1',
#            '2048S224V1_0',
#            '2048S224V1_1',
#            '2048S224V1_M1',
#            '2048S224V1_S3',

            #'ECDH_BASELINE_V1',
            '224_ECP_V1',
            '224_ECP_TWIST_S11_V1',
            '224_ECP_INVALID_S13_V1',
            '256_BRAINPOOL_V1',
            ],
        'V2': [
#            'BASELINEV2',
#
#            '2048S256V2',
#            '2048S256V2_0',
#            '2048S256V2_1',
#            '2048S256V2_M1',
#            '2048S256V2_S7',
#
#            '1024S160V2',
#            '1024S160V2_0',
#            '1024S160V2_1',
#            '1024S160V2_M1',
#            '1024S160V2_S7',
#
#            '2048S224V2',
#            '2048S224V2_0',
#            '2048S224V2_1',
#            '2048S224V2_M1',
#            '2048S224V2_S3',

            #'ECDH_BASELINE_V2',
            '224_ECP_V2',
            '224_ECP_TWIST_S11_V2',
            '224_ECP_INVALID_S13_V2',
            '256_BRAINPOOL_V2',
            ],
}

zmap_config = {
        'probe-module': 'udp',
        'target-port': '500',
        'output-fields': 'saddr,success,repeat',
        'output-filter': '"success = 1 && repeat = 0"',
        'output-module': 'csv',
        'bandwidth': '250M',
        'cooldown-time': '5',
        #'seed': '123789',
        'interface': '"p4p1"',
        'blacklist-file': '"/etc/zmap/blacklist.conf"',
        }


def check_path(filename, args):
    if args.force or not os.path.exists(filename):
        return True
    else:
        ans = raw_input("File exists: {}. Overwrite? (y/n) ".format(filename))
        if ans.lower() == 'y' or ans.lower() == 'yes':
            print "Overwriting {}".format(filename)
            return True
        else:
            print 'Not overwriting {}'.format(filename)
            return False


def main(args):
    run_script = open('run_all.sh', 'w')
    run_script.write('# run with sudo\n')

    zgrab_path = os.path.expandvars('$GOPATH') + '/src/github.com/zmap/zgrab'
    for zmap_scan, zgrab_scans in scans.items():
        zmap_scan_dir = os.path.join(zmap_scan)
        zmap_scan_conf = os.path.join(zmap_scan_dir, 'scan.conf')
        try:
            os.makedirs(zmap_scan_dir)
        except Exception:
            pass
        if check_path(zmap_scan_conf, args):
            with open(zmap_scan_conf, 'w') as f:
                if 'V2' in zmap_scan:
                    f.write('probe-args=file:' + zgrab_path + '/scripts/1024.IKEv2.pkt\n')
                else:
                    f.write('probe-args=file:' + zgrab_path + '/scripts/1024.psk.pkt\n')
                for k,v in zmap_config.items():
                    f.write('{k} {v}\n'.format(k=k, v=v))
                f.write('metadata {m}\n'.format(m=os.path.join(zmap_scan_dir, 'zmap.meta.json')))
                f.write('max-targets {p}%\n'.format(p=args.percent))

        zmap_scan_script = os.path.join(zmap_scan_dir, 'run.sh')
        zmap_scan_results = os.path.join(zmap_scan_dir, 'results.csv')
        if check_path(zmap_scan_script, args):
            with open(zmap_scan_script, 'w') as f:
                f.write('zmap -C {c}'.format(c=zmap_scan_conf)) 
                f.write(' | ztee {r} --success-only > /dev/null\n'.format(r=zmap_scan_results))
            run_script.write('bash {s}\n'.format(s=zmap_scan_script))

        for zgrab_scan in zgrab_scans:
            zgrab_scan_dir = os.path.join(zmap_scan_dir, zgrab_scan)
            if not check_path(zgrab_scan_dir, args):
                continue
            try:
                os.makedirs(zgrab_scan_dir)
            except Exception:
                pass
            cmd = ('{e} --ike-config {c}'
                    ' --port 500'
                    ' --gomaxprocs 24'
                    ' --senders 10000'
                    ' --metadata-file {meta}'
                    ' --log-file {log}'
                    ' --output-file {out}').format(
                            e=args.executable, 
                            c=zgrab_scan,
                            meta=os.path.join(zgrab_scan_dir, 'zgrab.meta.json'),
                            log=os.path.join(zgrab_scan_dir, 'zgrab.log'),
                            out=os.path.join(zgrab_scan_dir, 'zgrab.banners'))
            cmd2 = ('{e} --ike-config {c}'
                    ' --port 500'
                    ' --gomaxprocs 24'
                    ' --senders 10000'
                    ' --metadata-file {meta}'
                    ' --log-file {log}'
                    ' --output-file {out}').format(
                            e=args.executable, 
                            c=zgrab_scan,
                            meta=os.path.join(zgrab_scan_dir, 'zgrab.meta.json2'),
                            log=os.path.join(zgrab_scan_dir, 'zgrab.log2'),
                            out=os.path.join(zgrab_scan_dir, 'zgrab.banners2'))

            zgrab_scan_cmd = ('cat {r} | ztee /dev/null --success-only | zfilter.py').format(r=zmap_scan_results)
            if args.double:
                zgrab_scan_cmd += ' | tee >({cmd2})'.format(cmd2=cmd2)
            zgrab_scan_cmd += ' | {cmd}'.format(cmd=cmd)
            run_script.write('{c}\n'.format(c=zgrab_scan_cmd))
    run_script.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate files and directories to run a scan.')
    parser.add_argument('--double', '-d', action='store_true', help='Hit each host twice in succession.')
    parser.add_argument('--executable', '-e', type=str, default=os.path.expandvars('$GOPATH') + '/src/github.com/zmap/zgrab/zgrab')
    parser.add_argument('--percent', '-p', type=float, default=0.01, help='Percentage of available hosts to scan')
    parser.add_argument('--force', '-f', action='store_true', help='Overwrite existing files without asking')
    args = parser.parse_args()
    main(args)
