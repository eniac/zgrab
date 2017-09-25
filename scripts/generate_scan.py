#!/usr/bin/python

# Run this from the directory that you will be scanning from

import os
import argparse
import sys

class Config:
    def __init__(self, name, zmap_options, zgrab_common_options, zgrab_scans):
        self.name=name
        self.zmap_options=zmap_options
        self.zgrab_common_options=zgrab_common_options
        self.zgrab_scans=zgrab_scans

# NIST-P224 generator of subgroup of order 11 on twist
P224_TWIST_S11 = "{},{}".format(21219928721835262216070635629075256199931199995500865785214182108232, 
        2486431965114139990348241493232938533843075669604960787364227498903)
# NIST-P224 generator of subgroup of order 13 on curve w/ B-1
P224_INVALID_S13 = "{},{}".format(1234919426772886915432358412587735557527373236174597031415308881584, 
        218592750580712164156183367176268299828628545379017213517316023994)
# NIST-P256 generator of subgroup of order 5 on twist y^2 = x^3 +
# 64540953657701435357043644561909631465859193840763101878720769919119982834454*x
# + 21533133778103722695369883733312533132949737997864576898233410179589774724054
P256_TWIST_S5 = "{},{}".format(75610932410248387784210576211184530780201393864652054865721797292564276389325,
        30046858919395540206086570437823256496220553255320964836453418613861962163895)
# NIST-P256 generator of subgroup of order 5 on curve w/ B-1
P256_INVALID_S5 = "{},{}".format(86765160823711241075790919525606906052464424178558764461827806608937748883041,
        62096069626295534024197897036720226401219594482857127378802405572766226928611)
# Curve25519 generator of subgroup of order 2
CURVE25519_S2 = "{}".format(19298681539552699237261830834781317975544997444273427339909597334652188435537)

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

available_scans = [
        Config(name='SSH-22', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '22',
                },
            zgrab_common_options=' --xssh --port 22 --xssh-verbose',
            zgrab_scans=[
#                ('OPENSSH', ' --ssh-client OpenSSH_6.6p1'),
#                ('DROPBEAR', ' --ssh-client dropbear_0_46'),
#                ('BASELINE', ' --xssh-kex-algorithms '),
#                ('DH_BASELINE', ' --xssh-kex-algorithms '),
                ('ECDH_BASELINE', ' --xssh-kex-algorithms curve25519-sha256@libssh.org,ecdh-sha2-1.3.132.0.33,ecdh-sha2-1.3.36.3.3.2.8.1.1.7,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521'),
                ('P256_DOUBLE', ' --xssh-kex-algorithms ecdh-sha2-nistp256'), # double scan to check for repeats
                ('P256_TWIST_S5', ' --xssh-kex-algorithms ecdh-sha2-nistp256 --xssh-kex-values {}'.format(P256_TWIST_S5)),
                ('P256_INVALID_S5', ' --xssh-kex-algorithms ecdh-sha2-nistp256 --xssh-kex-values {}'.format(P256_INVALID_S5)),
                ('P224', ' --xssh-kex-algorithms ecdh-sha2-1.3.132.0.33'),
                ('BRAINPOOOL_256', ' --xssh-kex-algorithms ecdh-sha2-1.3.36.3.3.2.8.1.1.7'),
                ('P384', ' --xssh-kex-algorithms ecdh-sha2-nistp384'),
                ('P521', ' --xssh-kex-algorithms ecdh-sha2-nistp521'),
                ('CURVE25519', ' --xssh-kex-algorithms curve25519-sha256@libssh.org'),
                ]
            ),
        Config(name='IKEV1-500',
            zmap_options={
                'probe-module': 'udp',
                'target-port': '500',
                },
            zgrab_common_options=' --ike-version 1 --port 500',
            zgrab_scans=[
                ('EC2N_155', ' --ike-builtin EC2N_155'),
                ('EC2N_185', ' --ike-builtin EC2N_185'),
                ('BASELINE', ' --ike-builtin BASELINE'),

                ('2048S256', ' --ike-builtin 2048S256'),
                ('2048S256_0', ' --ike-builtin 2048S256_0'),
                ('2048S256_1', ' --ike-builtin 2048S256_1'),
                ('2048S256_M1', ' --ike-builtin 2048S256_M1'),
                ('2048S256_S7', ' --ike-builtin 2048S256_S7'),

                ('1024S160', ' --ike-builtin 1024S160'),
                ('1024S160_0', ' --ike-builtin 1024S160_0'),
                ('1024S160_1', ' --ike-builtin 1024S160_1'),
                ('1024S160_M1', ' --ike-builtin 1024S160_M1'),
                ('1024S160_S7', ' --ike-builtin 1024S160_S7'),

                ('2048S224', ' --ike-builtin 2048S224'),
                ('2048S224_0', ' --ike-builtin 2048S224_0'),
                ('2048S224_1', ' --ike-builtin 2048S224_1'),
                ('2048S224_M1', ' --ike-builtin 2048S224_M1'),
                ('2048S224_S3', ' --ike-builtin 2048S224_S3'),

                ('ECDH_BASELINE', ' --ike-builtin ECDH_BASELINE'),
                ('256_ECP_DOUBLE', ' --ike-builtin 256_ECP'),
                ('256_ECP_TWIST_S5', ' --ike-builtin 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --ike-builtin 256_ECP_INVALID_S5'),
                ('224_ECP', ' --ike-builtin 224_ECP'),
                ('256_BRAINPOOL', ' --ike-builtin 256_BRAINPOOL'),
                ('384_ECP', ' --ike-builtin 384_ECP'),
                ('521_ECP', ' --ike-builtin 521_ECP'),
                ('CURVE25519', ' --ike-builtin CURVE25519'), # not yet standardized: https://tools.ietf.org/html/draft-ietf-ipsecme-safecurves-05#section-2
                ]
            ),
        Config(name='IKEV2-500',
            zmap_options={
                'probe-module': 'udp',
                'target-port': '500',
                },
            zgrab_common_options=' --ike-version 2 --port 500',
            zgrab_scans=[
                ('EC2N_155', ' --ike-builtin EC2N_155'),
                ('EC2N_185', ' --ike-builtin EC2N_155'),
                ('BASELINE', ' --ike-builtin BASELINE'),

                ('2048S256', ' --ike-builtin 2048S256'),
                ('2048S256_0', ' --ike-builtin 2048S256_0'),
                ('2048S256_1', ' --ike-builtin 2048S256_1'),
                ('2048S256_M1', ' --ike-builtin 2048S256_M1'),
                ('2048S256_S7', ' --ike-builtin 2048S256_S7'),

                ('1024S160', ' --ike-builtin 1024S160'),
                ('1024S160_0', ' --ike-builtin 1024S160_0'),
                ('1024S160_1', ' --ike-builtin 1024S160_1'),
                ('1024S160_M1', ' --ike-builtin 1024S160_M1'),
                ('1024S160_S7', ' --ike-builtin 1024S160_S7'),

                ('2048S224', ' --ike-builtin 2048S224'),
                ('2048S224_0', ' --ike-builtin 2048S224_0'),
                ('2048S224_1', ' --ike-builtin 2048S224_1'),
                ('2048S224_M1', ' --ike-builtin 2048S224_M1'),
                ('2048S224_S3', ' --ike-builtin 2048S224_S3'),

                ('ECDH_BASELINE', ' --ike-builtin ECDH_BASELINE'),
                ('256_ECP_DOUBLE', ' --ike-builtin 256_ECP'),
                ('256_ECP_TWIST_S5', ' --ike-builtin 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --ike-builtin 256_ECP_INVALID_S5'),
                ('224_ECP', ' --ike-builtin 224_ECP'),
                ('256_BRAINPOOL', ' --ike-builtin 256_BRAINPOOL'),
                ('384_ECP', ' --ike-builtin 384_ECP'),
                ('521_ECP', ' --ike-builtin 521_ECP'),
                ('CURVE25519', ' --ike-builtin CURVE25519'), # not yet standardized: https://tools.ietf.org/html/draft-ietf-ipsecme-safecurves-05#section-2
                ]
            ),
        Config(name='STARTTLS-25', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '25',
                },
            zgrab_common_options=' --starttls --port 25 --smtp --ehlo "research-scan.cis.upenn.edu" --timeout 30 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-110', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '110',
                },
            zgrab_common_options=' --starttls --port 110 --pop3 --timeout 30 --ecdhe-ciphers --tls-verbose --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-143', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '143',
                },
            zgrab_common_options=' --starttls --port 143 --imap --timeout 30 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-443', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '443',
                },
            zgrab_common_options=' --tls --port 443 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
#                ('ECDH_BASELINE', ' --curve-preferences all'),
#                ('ECDH_ANDROID', ' --curve-preferences 14,13,25,11,12,24,9,10,22,23,8,6,7,20,21,4,5,18,19,1,2,3,15,16,17'),
#                ('160K1_ECP_DOUBLE', ' --curve-preferences 15'),
#                ('160R1_ECP_DOUBLE', ' --curve-preferences 16'),
#                ('256_ECP_INVALID_S5_DOUBLE', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
#                ('X25519_DOUBLE', ' --curve-preferences 29'),
#                ('X25519_INVALID_S8', ' --curve-preferences 29 --tls-kex-config X25519_INVALID_S8'),
#                ('X448', ' --curve-preferences 30'),
#                ('256_ECP_TWIST_S5_COMPRESS', ' --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5,COMPRESS'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
#                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
#                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
#                ('EXPLICIT_PRIME_CURVE', ' --curve-preferences 65281'),
#                ('EXPLICIT_CHAR2_CURVE', ' --curve-preferences 65282'),
                ]
            ),
        Config(name='TLS-465', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '465',
                },
            zgrab_common_options=' --tls --port 465 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-563', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '563',
                },
            zgrab_common_options=' --tls --port 563 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-587', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '587',
                },
            zgrab_common_options=' --starttls --port 587 --smtp --ehlo "research-scan.cis.upenn.edu" --timeout 30 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-636', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '636',
                },
            zgrab_common_options=' --tls --port 636 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-853', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '853',
                },
            zgrab_common_options=' --tls --port 853 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-989', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '989',
                },
            zgrab_common_options=' --tls --port 989 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-990', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '990',
                },
            zgrab_common_options=' --tls --port 990 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-992', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '992',
                },
            zgrab_common_options=' --tls --port 992 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-993', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '993',
                },
            zgrab_common_options=' --tls --port 993 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-994', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '994',
                },
            zgrab_common_options=' --tls --port 994 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-995', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '995',
                },
            zgrab_common_options=' --tls --port 995 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        Config(name='TLS-8443', 
            zmap_options={
                'probe-module': 'tcp_synscan',
                'target-port': '8443',
                },
            zgrab_common_options=' --tls --port 8443 --ecdhe-ciphers --tls-verbose',
            zgrab_scans=[
                ('ECDH_BASELINE', ' --curve-preferences all'),
                ('256_ECP_DOUBLE', ' --curve-preferences 23'), # double scan to check for repeats
                ('256_ECP_TWIST_S5', '  --curve-preferences 23 --tls-kex-config 256_ECP_TWIST_S5'),
                ('256_ECP_INVALID_S5', ' --curve-preferences 23 --tls-kex-config 256_ECP_INVALID_S5'),
                ('224_ECP', ' --curve-preferences 21'),
                ('384_ECP', ' --curve-preferences 24'),
                ('521_ECP', ' --curve-preferences 25'),
                ('256_BRAINPOOL', ' --curve-preferences 26'),
                ]
            ),
        ]


def generate_zgrab_command(executable, scan_options, common_options, global_options, prefix):
    return ('{e}'
            ' {s}'
            ' {c}'
            ' {g}'
            ' --metadata-file "{p}.meta"'
            ' --log-file "{p}.log"'
            ' --output-file "{p}.banners"').format(
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
    run_script = open(os.path.join(args.directory, 'run_all.sh'), 'w')
    run_script.write('# run with sudo\n')

    for scan in available_scans:
        if scan.name not in args.scans:
            continue
        zmap_scan_dir = os.path.join(args.directory, scan.name)
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
                f.write('metadata "{m}"\n'.format(m=os.path.join(zmap_scan_dir, 'zmap.meta.json')))
                f.write('max-targets {p}%\n'.format(p=args.percent))
                if 'IKEV1' in scan.name:
                    f.write('probe-args "file:{p}\n"'.format(p=os.path.join(zmap_scan_dir, 'IKEV1_BASELINE.pkt')))
                if 'IKEV2' in scan.name:
                    f.write('probe-args "file:{p}\n"'.format(p=os.path.join(zmap_scan_dir, 'IKEV2_BASELINE.pkt')))

        zmap_scan_script = os.path.join(zmap_scan_dir, 'run.sh')
        zmap_scan_results = os.path.join(zmap_scan_dir, 'results.csv')
        if check_path(zmap_scan_script, args):
            with open(zmap_scan_script, 'w') as f:
                if 'IKEV1' in scan.name:
                    f.write('echo 127.0.0.1 | {e} --ike --ike-version 1 --ike-probe-file {p} --ike-builtin BASELINE\n'.format(e=args.executable, p=os.path.join(zmap_scan_dir, 'IKEV1_BASELINE.pkt')))
                if 'IKEV2' in scan.name:
                    f.write('echo 127.0.0.1 | {e} --ike --ike-version 2 --ike-probe-file {p} --ike-builtin BASELINE\n'.format(e=args.executable, p=os.path.join(zmap_scan_dir, 'IKEV2_BASELINE.pkt')))
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
    parser = argparse.ArgumentParser(description="Generate files and directories to run a scan.")
    parser.add_argument("-e", "--executable", type=str, default=os.path.expandvars("$GOPATH") + "/src/github.com/zmap/zgrab/zgrab")
    parser.add_argument("-p", "--percent", type=float, default=0.01, help="Percentage of available hosts to scan")
    parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing files without asking")
    parser.add_argument("-d", "--directory", default=os.path.expandvars("$PWD"), type=str, help="Directory to write scan files (absolute or relative)")
    parser.add_argument("-s", "--scans", required=True, help="Comma-separated list of scans to enable ({})".format(",".join(scan.name for scan in available_scans)))
    args = parser.parse_args()
    args.scans = args.scans.split(",")
    if not os.path.isfile(args.executable) or not os.access(args.executable, os.X_OK):
        print("File does not exist or is not executable: {}".format(args.executable))
        sys.exit(1)
    if args.percent < 0 or args.percent > 100:
        print("Please specify a scan percentage between 0 and 100")
        sys.exit(1)
    args.directory = os.path.abspath(args.directory)
    if not os.path.exists(args.directory):
        print("Creating directory '{}'".format(args.directory))
        os.makedirs(args.directory)
    elif not os.access(args.directory, os.W_OK | os.X_OK):
        print("Please make directory '{}' both readable and writable".format(args.directory))
        sys.exit(1)
    main(args)
