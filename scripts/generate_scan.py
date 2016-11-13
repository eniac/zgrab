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
        Config(name='SSH', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '22',
                },
            zgrab_common_options=' --ssh --port 22',
            zgrab_scans=[
                ('OPENSSH', ' --ssh-client OpenSSH_6.6p1'),
                ('DROPBEAR', ' --ssh-client dropbear_0_46'),
                ('ECDH_BASELINE', ' --ssh-kex-algorithms curve25519-sha256@libssh.org,ecdh-sha2-1.3.132.0.33,ecdh-sha2-1.3.36.3.3.2.8.1.1.7,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521'),
                ('256_ECP_DOUBLE', ' --ssh-kex-algorithms ecdh-sha2-nistp256'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', ' --ssh-kex-algorithms ecdh-sha2-nistp256 --ssh-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --ssh-kex-algorithms ecdh-sha2-nistp256 --ssh-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --ssh-kex-algorithms ecdh-sha2-1.3.132.0.33'),
                ('256_BRAINPOOL', ' --ssh-kex-algorithms ecdh-sha2-1.3.36.3.3.2.8.1.1.7'),
                ('384_ECP', ' --ssh-kex-algorithms ecdh-sha2-nistp384'),
                ('521_ECP', ' --ssh-kex-algorithms ecdh-sha2-nistp521'),
                ('CURVE25519', ' --ssh-kex-algorithms curve25519-sha256@libssh.org'),
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

            zgrab_scan_cmd = ('cat {r} | ztee /dev/null --success-only | zfilter.py').format(r=zmap_scan_results)
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
