#!/usr/bin/python

# Run this from the directory that you will be scanning from

import os
import argparse

zgrab_path = os.path.expandvars('$GOPATH') + '/src/github.com/zmap/zgrab'

class Config:
    def __init__(self, name, zmap_options, zgrab_common_options, zgrab_scans):
        self.name=name
        self.zmap_options=zmap_options
        self.zgrab_common_options=zgrab_common_options
        self.zgrab_scans=zgrab_scans

zmap_global_options = {
        'output-fields': 'saddr,success,repeat',
        'output-filter': '"success = 1 && repeat = 0"',
        'output-module': 'csv',
        'bandwidth': '250M',
        'cooldown-time': '5',
        #'seed': '123789',
        'interface': '"p4p1"',
        'blacklist-file': '"/etc/zmap/blacklist.conf"',
        }
zgrab_global_options = ' --gomaxprocs 24 --senders 10000'

scans = [
        Config(name='IKEV1',
            zmap_options={
                'probe-args': 'file:' + zgrab_path + '/scripts/1024.psk.pkt',
                'probe-module': 'udp',
                'target-port': '500',
                },
            zgrab_common_options=' --ike-version 1 --port 500',
            zgrab_scans=[
#                ('BASELINE', ' --ike-config BASELINE'),
#
#                ('2048S256', ' --ike-config 2048S256'),
#                ('2048S256_0', ' --ike-config 2048S256_0'),
#                ('2048S256_1', ' --ike-config 2048S256_1'),
#                ('2048S256_M1', ' --ike-config 2048S256_M1'),
#                ('2048S256_S7', ' --ike-config 2048S256_S7'),
#
#                ('1024S160', ' --ike-config 1024S160'),
#                ('1024S160_0', ' --ike-config 1024S160_0'),
#                ('1024S160_1', ' --ike-config 1024S160_1'),
#                ('1024S160_M1', ' --ike-config 1024S160_M1'),
#                ('1024S160_S7', ' --ike-config 1024S160_S7'),
#
#                ('2048S224', ' --ike-config 2048S224'),
#                ('2048S224_0', ' --ike-config 2048S224_0'),
#                ('2048S224_1', ' --ike-config 2048S224_1'),
#                ('2048S224_M1', ' --ike-config 2048S224_M1'),
#                ('2048S224_S3', ' --ike-config 2048S224_S3'),

                ('ECDH_BASELINE', ' --ike-config ECDH_BASELINE'),
                ('256_ECP_DOUBLE', ' --ike-config 256_ECP'),
                ('256_ECP_TWIST_S5', ' --ike-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --ike-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --ike-config 224_ECP'),
                ('256_BRAINPOOL', ' --ike-config 256_BRAINPOOL'),
                ('384_ECP', ' --ike-config 384_ECP'),
                ('521_ECP', ' --ike-config 521_ECP'),
#                ('CURVE25519', ' --ike-config CURVE25519'), # not yet standardized: https://tools.ietf.org/html/draft-ietf-ipsecme-safecurves-05#section-2
                ]
            ),
        Config(name='IKEV2',
            zmap_options={
                'probe-args': 'file:' + zgrab_path + '/scripts/1024.IKEv2.pkt',
                'probe-module': 'udp',
                'target-port': '500',
                },
            zgrab_common_options=' --ike-version 2 --port 500',
            zgrab_scans=[
#                ('BASELINE', ' --ike-config BASELINE'),
#
#                ('2048S256', ' --ike-config 2048S256'),
#                ('2048S256_0', ' --ike-config 2048S256_0'),
#                ('2048S256_1', ' --ike-config 2048S256_1'),
#                ('2048S256_M1', ' --ike-config 2048S256_M1'),
#                ('2048S256_S7', ' --ike-config 2048S256_S7'),
#
#                ('1024S160', ' --ike-config 1024S160'),
#                ('1024S160_0', ' --ike-config 1024S160_0'),
#                ('1024S160_1', ' --ike-config 1024S160_1'),
#                ('1024S160_M1', ' --ike-config 1024S160_M1'),
#                ('1024S160_S7', ' --ike-config 1024S160_S7'),
#
#                ('2048S224', ' --ike-config 2048S224'),
#                ('2048S224_0', ' --ike-config 2048S224_0'),
#                ('2048S224_1', ' --ike-config 2048S224_1'),
#                ('2048S224_M1', ' --ike-config 2048S224_M1'),
#                ('2048S224_S3', ' --ike-config 2048S224_S3'),

                ('ECDH_BASELINE', ' --ike-config ECDH_BASELINE'),
                ('256_ECP_DOUBLE', ' --ike-config 256_ECP'),
                ('256_ECP_TWIST_S5', ' --ike-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --ike-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --ike-config 224_ECP'),
                ('256_BRAINPOOL', ' --ike-config 256_BRAINPOOL'),
                ('384_ECP', ' --ike-config 384_ECP'),
                ('521_ECP', ' --ike-config 521_ECP'),
#                ('CURVE25519', ' --ike-config CURVE25519'), # not yet standardized: https://tools.ietf.org/html/draft-ietf-ipsecme-safecurves-05#section-2
                ]
            ),
        ]


def generate_zgrab_command(executable, scan_options, common_options, global_options, prefix):
    return ('{e}'
            ' {s}'
            ' {c}'
            ' {g}'
            ' --metadata-file {p}.meta'
            ' --log-file {p}.log'
            ' --output-file {p}.banners').format(
                    e=args.executable, 
                    s=scan_options,
                    c=common_options,
                    g=zgrab_global_options,
                    p=prefix)

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

    for scan in scans:
        zmap_scan_dir = os.path.join(scan.name)
        zmap_scan_conf = os.path.join(zmap_scan_dir, 'scan.conf')
        try:
            os.makedirs(zmap_scan_dir)
        except Exception:
            pass
        if check_path(zmap_scan_conf, args):
            with open(zmap_scan_conf, 'w') as f:
                for k,v in zmap_global_options.items():
                    f.write('{k} {v}\n'.format(k=k, v=v))
                for k,v in scan.zmap_options.items():
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

        for zgrab_scan, zgrab_options in scan.zgrab_scans:
            zgrab_scan_dir = os.path.join(zmap_scan_dir, zgrab_scan)
            if not check_path(zgrab_scan_dir, args):
                continue
            try:
                os.makedirs(zgrab_scan_dir)
            except Exception:
                pass

            zgrab_scan_cmd = ('cat {r} | ztee /dev/null --success-only | ' + zgrab_path + '/scripts/zfilter.py').format(r=zmap_scan_results)
            if 'DOUBLE' in zgrab_scan:
                zgrab_scan_cmd += ' | tee >({cmd2})'.format(cmd2=generate_zgrab_command(args.executable, zgrab_options, scan.zgrab_common_options, zgrab_global_options, os.path.join(zgrab_scan_dir, 'zgrab2')))
            zgrab_scan_cmd += ' | {cmd}'.format(cmd=generate_zgrab_command(args.executable, zgrab_options, scan.zgrab_common_options, zgrab_global_options, os.path.join(zgrab_scan_dir, 'zgrab')))
            run_script.write('echo {n} && time {c}\n'.format(n=zgrab_scan, c=zgrab_scan_cmd))
    run_script.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate files and directories to run a scan.')
    parser.add_argument('--executable', '-e', type=str, default=os.path.expandvars('$GOPATH') + '/src/github.com/zmap/zgrab/zgrab')
    parser.add_argument('--percent', '-p', type=float, default=0.01, help='Percentage of available hosts to scan')
    parser.add_argument('--force', '-f', action='store_true', help='Overwrite existing files without asking')
    args = parser.parse_args()
    main(args)
